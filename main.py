import rhash
import concurrent.futures
import secrets
import time

PREIMAGE_NOT_FOUND = "Pre-image not found"

def get_truncated_hash(data: bytes, n):
    hashed = rhash.hash_msg(data, rhash.HAS160)
    return hashed[-int(n / 4):]

def generate_random_hex(bits):
    return format(secrets.randbits(bits), f'0{bits // 4}x')

def combine_strings(str1, str2):
    return str2 + str1

def find_index_from_hash(current_hash, index_dict):
    if current_hash in index_dict:
        return index_dict[current_hash]
    return None

def iterate_chain(initial_value, chain_length, bit_length, target_hash, r_value):
    for _ in range(chain_length - 1):
        initial_value = get_truncated_hash(combine_strings(initial_value, generate_random_hex(128 - bit_length)).encode(), bit_length)
        if get_truncated_hash(combine_strings(initial_value, generate_random_hex(128 - bit_length)).encode(), bit_length) == target_hash:
            return combine_strings(initial_value, r_value)
    return None

def build_hash_chain_table(count, chain_length, bit_length):
    def build_chain_entry(i):
        initial_value = generate_random_hex(bit_length)
        current_value = initial_value

        for _ in range(chain_length):
            current_value = get_truncated_hash(combine_strings(current_value, generate_random_hex(128 - bit_length)).encode(), bit_length)

        return initial_value, current_value

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = list(executor.map(build_chain_entry, range(count)))

    return results

def attack_hash_chain(table, index_dict, target_hash, chain_length, bit_length, r_value):
    current_hash = target_hash
    for _ in range(chain_length):
        index = find_index_from_hash(current_hash, index_dict)

        if index is not None:
            initial_value = table[index][0]
            result = iterate_chain(initial_value, chain_length, bit_length, target_hash, r_value)
            
            if result:
                return result
            return PREIMAGE_NOT_FOUND
        current_hash = get_truncated_hash(combine_strings(current_hash, generate_random_hex(128 - bit_length)).encode(), bit_length)
    return PREIMAGE_NOT_FOUND

def run_attack(count, chain_length, bit_length, r_value):
    table = build_hash_chain_table(count, chain_length, bit_length)
    index_dict = {table[i][1]: i for i in range(count)}

    successes = 0

    for _ in range(10_100):
        random_value = generate_random_hex(256)
        random_hash = get_truncated_hash(random_value.encode(), bit_length)
        result = attack_hash_chain(table, index_dict, random_hash, chain_length, bit_length, r_value)
        
        if result != PREIMAGE_NOT_FOUND and get_truncated_hash(combine_strings(result, generate_random_hex(128 - bit_length)).encode(), bit_length) == random_hash:
            successes += 1

    success_rate = successes / 10000 if successes > 0 else 0

    print(f"Success Count: {successes}, Probability: {success_rate}")
    print(f"Failure Count: {10000 - successes}")

if __name__ == '__main__':
    chain_count = pow(2, 20)
    chain_length = pow(2, 10)
    bit_length = 32
    r_value = generate_random_hex(128 - bit_length)
    target_hash = get_truncated_hash(generate_random_hex(256).encode(), bit_length)

    start_time = time.time()
    run_attack(chain_count, chain_length, bit_length, r_value)
    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Execution time: {execution_time} seconds")
