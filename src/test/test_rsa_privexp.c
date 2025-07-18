#include "rsa.h"  // Assuming rsa.h contains rsa_ctx_t, rsa_init, rsa_set_privkey, rsa_compute_private_exponent, rsa_clear, rsa_free and RSA_SUCCESS
#include "test_helpers.h"
#include "unity.h"

// From test_constants.c
extern const char *RSA_TEST_MODULI[];
extern const char *RSA_TEST_PRIMES_P[];
extern const char *RSA_TEST_PRIMES_Q[];
extern const char *RSA_TEST_EXPONENTS_D[];
extern const char *RSA_TEST_SIGNATURES[];
extern const char *RSA_TEST_MESSAGES[];
extern const unsigned int NUM_NIST_TESTS;

/*void setUp(void) {
    // Initialize any necessary global/static rsa_ctx_t or other variables for
tests.
    // For now, direct initialization in test functions is preferred for
clarity,
    // but if there's common setup, it can go here.
    // rsa_init(&test_key_privexp); // Example if a global key were used across
multiple tests in this file
}

void tearDown(void) {
    // Clean up any global/static rsa_ctx_t or other variables.
    // rsa_free(&test_key_privexp); // Example if a global key were used
}*/

void test_all_nist_private_exponent_vectors(void) {
    rsa_ctx_t private_key;
    rsa_init(&private_key);

    for (size_t i = 0; i < NUM_NIST_TESTS; ++i) {
        mpz_t expected_d;
        mpz_init(expected_d);

        mpz_set_str(expected_d, RSA_TEST_EXPONENTS_D[i], 16);

        // Note: rsa_set_privkey is expected to take hex strings for P and Q,
        // and E. Assuming E is a global hex string constant like "10001" or
        // similar. The length argument for rsa_set_privkey for E might need
        // adjustment if E is not a fixed length. For this example, assuming
        // RSA_TEST_PUBLIC_EXPONENT_E is a simple hex string like "10001" (which
        // is base 16).
        int result = rsa_set_privkey(
            &private_key, RSA_TEST_PRIMES_P[i], strlen(RSA_TEST_PRIMES_P[i]),
            RSA_TEST_PRIMES_Q[i], strlen(RSA_TEST_PRIMES_Q[i]),
            RSA_DEFAULT_PUBLIC_EXPONENT, RSA_BASE_HEX
        );

        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, result, "rsa_set_privkey failed"
        );

        if (result == RSA_SUCCESS) {
            result = rsa_compute_private_exponent(&private_key);
            TEST_ASSERT_EQUAL_INT_MESSAGE(
                RSA_SUCCESS, result, "rsa_compute_private_exponent failed"
            );

            if (result == RSA_SUCCESS) {
                TEST_ASSERT_EQUAL_GMP_MPZ(
                    expected_d, private_key.d, "Private exponent mismatch"
                );
            }
        }

        mpz_clear(expected_d);
        rsa_clear(&private_key
        );  // Clear mpz_t members within the key for the next iteration
        rsa_init(&private_key
        );  // Re-initialize for the next iteration to ensure a clean state
            // (especially if rsa_clear doesn't fully reset)
    }

    rsa_free(&private_key);  // Free the last initialized key context
}
