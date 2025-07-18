#include <stdio.h>   // For sprintf
#include <stdlib.h>  // For rand, srand
#include <string.h>  // For strlen
#include <time.h>    // For time

#include "rsa.h"
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

// Copied from rsa.c as a temporary workaround for this subtask
// Ideally, this would be exposed via rsa.h or a shared utility header
static void local_rsa_mpz_gen_random_fast(
    mpz_t random_num, unsigned int num_bits
) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    // Seed with a combination of time and clock for better randomness in quick
    // succession
    gmp_randseed_ui(
        state, (unsigned long int)time(NULL) + (unsigned long int)clock()
    );

    mpz_urandomb(
        random_num, state, num_bits
    );  // Generate random number with specified bits

    gmp_randclear(state);
}

static void perform_random_test_logic(
    bool use_nist_keys, int bitlen, const char *test_name_prefix
) {
    mpz_t plaintext, ciphertext, signature, should_be_valid_modulus, output;
    rsa_ctx_t public_key, private_key;

    mpz_inits(
        plaintext, ciphertext, signature, should_be_valid_modulus, output, NULL
    );
    rsa_init(&public_key);
    rsa_init(&private_key);

    char msg_buffer[8192];  // Increased buffer size for more descriptive
                            // messages

    // Key Setup
    if (use_nist_keys) {
        srand(time(NULL));
        int index = rand() % NUM_NIST_TESTS;
        sprintf(
            msg_buffer, "%s (NIST Vector %d): rsa_set_pubkey failed",
            test_name_prefix, index
        );
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS,
            rsa_set_pubkey(
                &public_key, RSA_TEST_MODULI[index],
                strlen(RSA_TEST_MODULI[index]), RSA_DEFAULT_PUBLIC_EXPONENT,
                RSA_BASE_HEX
            ),
            msg_buffer
        );

        sprintf(
            msg_buffer, "%s (NIST Vector %d): rsa_set_privkey failed",
            test_name_prefix, index
        );
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS,
            rsa_set_privkey(
                &private_key, RSA_TEST_PRIMES_P[index],
                strlen(RSA_TEST_PRIMES_P[index]), RSA_TEST_PRIMES_Q[index],
                strlen(RSA_TEST_PRIMES_Q[index]), RSA_DEFAULT_PUBLIC_EXPONENT,
                RSA_BASE_HEX
            ),
            msg_buffer
        );

        mpz_mul(should_be_valid_modulus, private_key.p, private_key.q);
        sprintf(
            msg_buffer,
            "%s (NIST Vector %d): Public key modulus N does not match P*Q",
            test_name_prefix, index
        );
        TEST_ASSERT_EQUAL_GMP_MPZ(
            should_be_valid_modulus, public_key.n, msg_buffer
        );
        sprintf(
            msg_buffer,
            "%s (NIST Vector %d): Private key modulus N does not match P*Q",
            test_name_prefix, index
        );
        TEST_ASSERT_EQUAL_GMP_MPZ(
            should_be_valid_modulus, private_key.n, msg_buffer
        );

    } else {
        sprintf(
            msg_buffer, "%s (Bitlen %d): rsa_genkey failed", test_name_prefix,
            bitlen
        );
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS,
            rsa_genkey(&private_key, bitlen, RSA_DEFAULT_PUBLIC_EXPONENT),
            msg_buffer
        );

        sprintf(
            msg_buffer, "%s (Bitlen %d): rsa_pubkey_from_private failed",
            test_name_prefix, bitlen
        );
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, rsa_pubkey_from_private(&public_key, &private_key),
            msg_buffer
        );
    }

    // Sign/Verify Test
    sprintf(msg_buffer, "%s: Sign/Verify", test_name_prefix);
    unsigned int num_bits_for_plaintext =
        mpz_sizeinbase(public_key.n, 2) - 1;  // Ensure plaintext < n
    do {
        local_rsa_mpz_gen_random_fast(plaintext, num_bits_for_plaintext);
    } while (mpz_cmp(plaintext, public_key.n) >= 0
    );  // Ensure plaintext is strictly less than n

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_SUCCESS, rsa_mpz_private(&private_key, signature, plaintext),
        "Sign failed"
    );
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_SUCCESS, rsa_mpz_public(&public_key, output, signature),
        "Verify failed"
    );
    TEST_ASSERT_EQUAL_GMP_MPZ(plaintext, output, msg_buffer);

    // Encrypt/Decrypt Test
    sprintf(msg_buffer, "%s: Encrypt/Decrypt", test_name_prefix);
    do {
        local_rsa_mpz_gen_random_fast(plaintext, num_bits_for_plaintext);
    } while (mpz_cmp(plaintext, public_key.n) >= 0
    );  // Ensure plaintext is strictly less than n

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_SUCCESS, rsa_mpz_public(&public_key, ciphertext, plaintext),
        "Encrypt failed"
    );
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_SUCCESS, rsa_mpz_private(&private_key, output, ciphertext),
        "Decrypt failed"
    );
    TEST_ASSERT_EQUAL_GMP_MPZ(plaintext, output, msg_buffer);

    // Clean up
    mpz_clears(
        plaintext, ciphertext, signature, should_be_valid_modulus, output, NULL
    );
    rsa_free(&public_key);
    rsa_free(&private_key);
}

/*void setUp(void) {
    // Empty
}

void tearDown(void) {
    // Empty
}*/

void test_random_sign_verify_enc_dec_with_nist_keys(void) {
    perform_random_test_logic(
        true, 2048, "NISTKeys"
    );  // Bitlen is nominal for NIST keys
}

void test_random_sign_verify_enc_dec_with_generated_keys_2048(void) {
    perform_random_test_logic(false, 2048, "GenKey2048");
}

void test_random_sign_verify_enc_dec_with_generated_keys_4096(void) {
    perform_random_test_logic(false, 4096, "GenKey4096");
}
