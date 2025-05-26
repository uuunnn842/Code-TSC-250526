import hashlib
import random
import os
from ecdsa import SECP256k1, SigningKey
import time
from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs

# Define the number of test times
TEST_TIMES = 10000  # Default to test 10000 times

# SHA-1 related functions
def calculate_sha1_time(data):
    sha1 = hashlib.sha1()
    start_time = time.time()
    sha1.update(data)
    hash_value = sha1.hexdigest()
    end_time = time.time()
    return hash_value, end_time - start_time

def test_sha1():
    total_time = 0
    for _ in range(TEST_TIMES):
        _, execution_time = calculate_sha1_time(random_data)
        total_time += execution_time
    return total_time

# ECC related functions
def calculate_ecc_point_multiplication_time():
    private_key = random.randint(1, SECP256k1.order - 1)
    generator_point = SECP256k1.generator
    start_time = time.time()
    result_point = private_key * generator_point
    end_time = time.time()
    return result_point, end_time - start_time

def test_ecc():
    total_time = 0
    for _ in range(TEST_TIMES):
        _, execution_time = calculate_ecc_point_multiplication_time()
        total_time += execution_time
    return total_time

# PUF related functions
def test_puf(num_challenges, num_tests, puf_type, **kwargs):
    puf = XORArbiterPUF(n=256, k=10, seed=10)
    challenges = random_inputs(n=puf.n, N=num_challenges, seed=10)

    total_time = 0
    for _ in range(num_tests):
        start_time = time.time()
        responses = puf.eval(challenges)
        end_time = time.time()
        total_time += (end_time - start_time)

    return total_time

# Scalar multiplication related functions
def calculate_scalar_multiplication_time():
    private_key = random.randint(1, SECP256k1.order - 1)
    generator_point = SECP256k1.generator
    start_time = time.time()
    result_point = private_key * generator_point
    end_time = time.time()
    return result_point, end_time - start_time

def test_scalar_multiplication():
    total_time = 0
    for _ in range(TEST_TIMES):
        _, execution_time = calculate_scalar_multiplication_time()
        total_time += execution_time
    return total_time

# Multi-scalar multiplication related functions
def calculate_multi_scalar_multiplication_time():
    private_key1 = random.randint(1, SECP256k1.order - 1)
    private_key2 = random.randint(1, SECP256k1.order - 1)
    generator_point = SECP256k1.generator
    start_time = time.time()
    result_point = private_key1 * generator_point + private_key2 * generator_point
    end_time = time.time()
    return result_point, end_time - start_time

def test_multi_scalar_multiplication():
    total_time = 0
    for _ in range(TEST_TIMES):
        _, execution_time = calculate_multi_scalar_multiplication_time()
        total_time += execution_time
    return total_time

# Memo dictionary for caching results of T(n, x)
memo = {}

def T(n, x, mod=2 ** 128):
    # If the result for current n and x has already been calculated, return it from the cache
    if (n, x) in memo:
        return memo[(n, x)]

    # Base cases
    if n == 0:
        result = 1 % mod
    elif n == 1:
        result = x % mod
    # Recursive calculation
    elif n % 2 == 0:  # If n is even
        temp = T(n // 2, x, mod)
        result = (2 * temp * temp - 1) % mod
    else:  # If n is odd
        temp1 = T((n - 1) // 2, x, mod)
        temp2 = T((n + 1) // 2, x, mod)
        result = (2 * temp1 * temp2 - x) % mod

    # Store the result in the cache
    memo[(n, x)] = result
    return result

def test_Tn():
    total_time = 0
    bit = 160
    mod = 2 ** bit
    for _ in range(TEST_TIMES):
        memo.clear()
        n = random.getrandbits(bit)
        if n < 2 ** (bit - 1):
            n += 2 ** (bit - 1)
        x = random.getrandbits(bit)
        if x < 2 ** (bit - 1):
            x += 2 ** (bit - 1)
        start_time = time.time()
        T(n, x, mod)
        end_time = time.time()
        total_time += (end_time - start_time)
    return total_time

if __name__ == "__main__":
    # Parameter settings
    num_challenges = TEST_TIMES  # Use TEST_TIMES as num_challenges
    num_tests = 1
    puf_type = XORArbiterPUF
    puf_params = {"n": 256, "k": 10, "seed": 1}
    data_size = 128
    random_data = os.urandom(data_size)

    print(T(464897, T(5656, 9571, 2 ** 128), 2 ** 128), T(5656 * 464897, 9571, 2 ** 128))

    # Test SHA-1 for 10000 times
    total_sha1_time = test_sha1()
    print(f"SHA-1 total execution time: {total_sha1_time:.6f} seconds")

    # # Test ECC point multiplication for 10000 times
    # total_ecc_time = test_ecc()
    # print(f"ECC point multiplication total execution time: {total_ecc_time:.6f} seconds")

    # Test PUF for 10000 times
    total_puf_time = test_puf(num_challenges, num_tests, XORArbiterPUF, **puf_params)
    print(f"PUF total execution time: {total_puf_time:.6f} seconds")

    # Test scalar multiplication for 10000 times
    total_scalar_mul_time = test_scalar_multiplication()
    print(f"Scalar multiplication total execution time: {total_scalar_mul_time:.6f} seconds")

    # Test multi-scalar multiplication for 10000 times
    total_multi_scalar_mul_time = test_multi_scalar_multiplication()
    print(f"Multi-scalar multiplication total execution time: {total_multi_scalar_mul_time:.6f} seconds")

    # Test T(n, x) for 10000 times
    total_Tn_time = test_Tn()
    print(f"T(n, x) total execution time: {total_Tn_time:.6f} seconds")