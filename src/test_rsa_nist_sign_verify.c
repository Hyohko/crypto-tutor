#include "unity.h"
#include "rsa.h"
#include "rsatest.h"
#include "test_helpers.h"
#include <string.h> // For strstr
#include <stdio.h>  // For sprintf

// For _countof macro, if not defined in rsatest.h
#ifndef _countof
#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

void setUp(void) {
    // Can be empty for now
}

void tearDown(void) {
    // Can be empty for now
}

void test_all_nist_sign_verify_vectors(void) {
    rsa_ctx_t public_key, private_key;
    mpz_t plaintext, signature, expected_signature, should_be_valid_modulus, output;

    rsa_init(&public_key);
    rsa_init(&private_key);
    mpz_inits(plaintext, signature, expected_signature, should_be_valid_modulus, output, NULL);

    for (size_t i = 0; i < _countof(RSA_TEST_MODULI); ++i) {
        bool expect_fail = (strstr(RSA_TEST_SIGNATURES[i], "FAIL") != NULL);
        char msg_buffer[256];
        sprintf(msg_buffer, "NIST Sign/Verify Test Vector %zu", i + 1); // Use %zu for size_t

        // Set keys
        // Assuming RSA_TEST_PUBLIC_EXPONENT_E is a hex string like "10001"
        int result_pub = rsa_set_pubkey(&public_key, RSA_TEST_MODULI[i], strlen(RSA_TEST_MODULI[i]),
                                        RSA_TEST_PUBLIC_EXPONENT_E, strlen(RSA_TEST_PUBLIC_EXPONENT_E));
        char pub_key_msg[512];
        sprintf(pub_key_msg, "%s: rsa_set_pubkey failed for N=%s, E=%s", msg_buffer, RSA_TEST_MODULI[i], RSA_TEST_PUBLIC_EXPONENT_E);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result_pub, pub_key_msg);

        int result_priv = rsa_set_privkey(&private_key, RSA_TEST_PRIMES_P[i], strlen(RSA_TEST_PRIMES_P[i]),
                                          RSA_TEST_PRIMES_Q[i], strlen(RSA_TEST_PRIMES_Q[i]),
                                          RSA_TEST_PUBLIC_EXPONENT_E, strlen(RSA_TEST_PUBLIC_EXPONENT_E));
        char priv_key_msg[512];
        sprintf(priv_key_msg, "%s: rsa_set_privkey failed for P=%s, Q=%s, E=%s", msg_buffer, RSA_TEST_PRIMES_P[i], RSA_TEST_PRIMES_Q[i], RSA_TEST_PUBLIC_EXPONENT_E);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result_priv, priv_key_msg);

        if (result_pub != RSA_SUCCESS || result_priv != RSA_SUCCESS) {
            rsa_clear(&public_key);
            rsa_clear(&private_key);
            rsa_init(&public_key);
            rsa_init(&private_key);
            UnityPrint("Skipping current iteration due to key setup failure.");
            UNITY_PRINT_EOL();
            continue;
        }

        // Check modulus consistency
        mpz_mul(should_be_valid_modulus, private_key.p, private_key.q);
        char mod_mismatch_pub_msg[256];
        sprintf(mod_mismatch_pub_msg, "%s: Public key modulus N does not match P*Q", msg_buffer);
        TEST_ASSERT_EQUAL_GMP_MPZ(should_be_valid_modulus, public_key.n, mod_mismatch_pub_msg);

        char mod_mismatch_priv_msg[256];
        sprintf(mod_mismatch_priv_msg, "%s: Private key modulus N does not match P*Q", msg_buffer);
        TEST_ASSERT_EQUAL_GMP_MPZ(should_be_valid_modulus, private_key.n, mod_mismatch_priv_msg);

        // Load plaintext and expected signature
        mpz_set_str(plaintext, RSA_TEST_MESSAGES[i], 16);
        if (!expect_fail) {
            mpz_set_str(expected_signature, RSA_TEST_SIGNATURES[i], 16);
        }

        // Sign
        rsa_error_t ret_sign = rsa_mpz_private(&private_key, signature, plaintext);

        if (expect_fail) {
            char sign_fail_msg[256];
            sprintf(sign_fail_msg, "%s: Signing was expected to fail but succeeded.", msg_buffer);
            TEST_ASSERT_NOT_EQUAL_MESSAGE(RSA_SUCCESS, ret_sign, sign_fail_msg);
            rsa_clear(&public_key);
            rsa_clear(&private_key);
            rsa_init(&public_key);
            rsa_init(&private_key);
            continue;
        } else {
            char sign_succ_msg[256];
            sprintf(sign_succ_msg, "%s: Signing failed unexpectedly.", msg_buffer);
            TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, ret_sign, sign_succ_msg);
            if (ret_sign != RSA_SUCCESS) {
                rsa_clear(&public_key);
                rsa_clear(&private_key);
                rsa_init(&public_key);
                rsa_init(&private_key);
                continue;
            }
            char sig_match_msg[256];
            sprintf(sig_match_msg, "%s: Signature does not match expected signature.", msg_buffer);
            TEST_ASSERT_EQUAL_GMP_MPZ(expected_signature, signature, sig_match_msg);
        }

        // Verify
        rsa_error_t ret_verify = rsa_mpz_public(&public_key, output, signature);
        char verify_succ_msg[256];
        sprintf(verify_succ_msg, "%s: Verification failed unexpectedly.", msg_buffer);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, ret_verify, verify_succ_msg);

        if (ret_verify != RSA_SUCCESS) {
            rsa_clear(&public_key);
            rsa_clear(&private_key);
            rsa_init(&public_key);
            rsa_init(&private_key);
            continue;
        }
        char verify_match_msg[256];
        sprintf(verify_match_msg, "%s: Verification output does not match plaintext.", msg_buffer);
        TEST_ASSERT_EQUAL_GMP_MPZ(plaintext, output, verify_match_msg);

        rsa_clear(&public_key);
        rsa_clear(&private_key);
        rsa_init(&public_key);
        rsa_init(&private_key);
    }

    mpz_clears(plaintext, signature, expected_signature, should_be_valid_modulus, output, NULL);
    rsa_free(&public_key);
    rsa_free(&private_key);
}
