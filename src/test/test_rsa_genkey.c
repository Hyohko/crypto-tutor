#include "unity.h"
#include "rsa.h" // For rsa_ctx_t, rsa_init, rsa_genkey, rsa_free, RSA_DEFAULT_PUBLIC_EXPONENT, RSA_SUCCESS, RSA_ERROR_KEY_SIZE_INVALID
#include "test_helpers.h" // For TEST_ASSERT_EQUAL_GMP_MPZ if needed, though not directly used here for mpz comparison
#include <stdio.h> // For sprintf

// Define RSA_DEFAULT_PUBLIC_EXPONENT if not in rsa.h (it should be)
#ifndef RSA_DEFAULT_PUBLIC_EXPONENT
#define RSA_DEFAULT_PUBLIC_EXPONENT "65537" // Or "10001" depending on common practice in the project
#endif

// Define min/max key bitlens if not in rsa.h (they should be for rsa_genkey to use them)
// These values are assumed based on common RSA practices and the problem description's analysis.
#ifndef RSA_MIN_KEY_BITLEN
#define RSA_MIN_KEY_BITLEN 1024
#endif
#ifndef RSA_MAX_KEY_BITLEN
#define RSA_MAX_KEY_BITLEN 32768
#endif


void setUp(void) {
    // Empty for now
}

void tearDown(void) {
    // Empty for now
}

void test_genkey_1024_multiple_times(void) {
    for (int i = 0; i < 10; ++i) {
        rsa_ctx_t newkey;
        rsa_init(&newkey);

        // Assuming RSA_DEFAULT_PUBLIC_EXPONENT is a string like "65537" and rsa_genkey handles its conversion if needed,
        // or expects it as a number if its type is different. The original rsa_genkey takes const char* for e_hex.
        rsa_error_t ret = rsa_genkey(&newkey, 1024, RSA_DEFAULT_PUBLIC_EXPONENT);

        char msg[100];
        sprintf(msg, "RSA-1024 key generation failed on iteration %d", i);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, ret, msg);

        if (ret == RSA_SUCCESS) {
            TEST_ASSERT_NOT_NULL_MESSAGE(newkey.n, "Modulus N is NULL after genkey");
            TEST_ASSERT_NOT_NULL_MESSAGE(newkey.e, "Exponent E is NULL after genkey");
            TEST_ASSERT_NOT_NULL_MESSAGE(newkey.d, "Private exponent D is NULL after genkey");
            TEST_ASSERT_NOT_NULL_MESSAGE(newkey.p, "Prime P is NULL after genkey");
            TEST_ASSERT_NOT_NULL_MESSAGE(newkey.q, "Prime Q is NULL after genkey");

            TEST_ASSERT_MESSAGE(mpz_cmp_ui(newkey.n, 0) != 0, "Modulus N is zero after genkey");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(newkey.e, 0) != 0, "Exponent E is zero after genkey");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(newkey.d, 0) != 0, "Private exponent D is zero after genkey");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(newkey.p, 0) != 0, "Prime P is zero after genkey");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(newkey.q, 0) != 0, "Prime Q is zero after genkey");
            TEST_ASSERT_MESSAGE(newkey.is_private == RSA_PRIVATE, "Key is not a private key structure");
        }
        rsa_free(&newkey);
    }
}

void test_genkey_invalid_size_too_small(void) {
    rsa_ctx_t badkey;
    rsa_init(&badkey);
    // Use a value known to be less than RSA_MIN_KEY_BITLEN (e.g., 1000 if min is 1024)
    rsa_error_t ret = rsa_genkey(&badkey, RSA_MIN_KEY_BITLEN - 24, RSA_DEFAULT_PUBLIC_EXPONENT);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(RSA_SUCCESS, ret, "Key generation with < min bits succeeded unexpectedly.");
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_ERROR_KEY_SIZE_INVALID, ret, "Incorrect error code for < min bits key size.");
    TEST_ASSERT_MESSAGE(badkey.is_private == RSA_KEY_NOT_SET, "Key should not be set");
    rsa_free(&badkey);
}

void test_genkey_invalid_size_too_large(void) {
    rsa_ctx_t badkey;
    rsa_init(&badkey);
    // Use a value known to be greater than RSA_MAX_KEY_BITLEN (e.g., 40000 if max is 32768)
    rsa_error_t ret = rsa_genkey(&badkey, RSA_MAX_KEY_BITLEN + 7232, RSA_DEFAULT_PUBLIC_EXPONENT);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(RSA_SUCCESS, ret, "Key generation with > max bits succeeded unexpectedly.");
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_ERROR_KEY_SIZE_INVALID, ret, "Incorrect error code for > max bits key size.");
    TEST_ASSERT_MESSAGE(badkey.is_private == RSA_KEY_NOT_SET, "Key should not be set");
    rsa_free(&badkey);
}

void test_genkey_valid_size_not_power_of_two(void) {
    rsa_ctx_t key;
    rsa_init(&key);

    // 5000 is within typical RSA_MIN_KEY_BITLEN (1024) and RSA_MAX_KEY_BITLEN (e.g., 16384 or 32768)
    // The rsa_genkey function in rsa.c only checks these min/max bounds, not for power-of-two. NEVERTHELESS,
    // no practical real-world-use-case of RSA ever uses non-power-of-two keysizes.
    int bitlen_to_test = 5000;

    // Check if 5000 is actually valid according to defined MIN/MAX. If not, this test itself is flawed.
    if (bitlen_to_test < RSA_MIN_KEY_BITLEN || bitlen_to_test > RSA_MAX_KEY_BITLEN) {
        // This case means 5000 is outside the valid range, so it *should* return RSA_ERROR_KEY_SIZE_INVALID
        rsa_error_t ret = rsa_genkey(&key, bitlen_to_test, RSA_DEFAULT_PUBLIC_EXPONENT);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_ERROR_KEY_SIZE_INVALID, ret, "Key generation with 5000 bits (outside defined min/max) did not return RSA_ERROR_KEY_SIZE_INVALID.");
    } else {
        // 5000 is within the valid range. But, it's not a power of two. Expect failure.
        rsa_error_t ret = rsa_genkey(&key, bitlen_to_test, RSA_DEFAULT_PUBLIC_EXPONENT);
        char msg[160];
        sprintf(msg, "Key generation with %d bits succeeded unexpectedly. rsa.c's rsa_genkey should not allow this size.", bitlen_to_test);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_ERROR_KEY_SIZE_INVALID, ret, msg);

        if (ret == RSA_ERROR_KEY_SIZE_INVALID) {
            // Initializing the key will allocate mpz structures for the elements, but
            // they will contain zero values if the key is not set
            sprintf(msg, "Modulus N is NOT NULL after genkey (%d bits)", bitlen_to_test);
            TEST_ASSERT_NOT_NULL_MESSAGE(key.n, msg);
            sprintf(msg, "Modulus N is not zero after genkey (%d bits)", bitlen_to_test);
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(key.n, 0) == 0, msg);
            // Other components can also be checked similarly
            TEST_ASSERT_NOT_NULL_MESSAGE(key.e, "Exponent E is NULL");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(key.e, 0) == 0, "Exponent E is not zero");
            TEST_ASSERT_NOT_NULL_MESSAGE(key.d, "Private exponent D is NULL");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(key.d, 0) == 0, "Private exponent D is not zero");
            TEST_ASSERT_NOT_NULL_MESSAGE(key.p, "Prime P is NULL");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(key.p, 0) == 0, "Prime P is not zero");
            TEST_ASSERT_NOT_NULL_MESSAGE(key.q, "Prime Q is NULL");
            TEST_ASSERT_MESSAGE(mpz_cmp_ui(key.q, 0) == 0, "Prime Q is not zero");
            TEST_ASSERT_MESSAGE(key.is_private == RSA_KEY_NOT_SET, "Key should not be set");
        }
    }
    rsa_free(&key);
}
