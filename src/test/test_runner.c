#include "unity/unity.h"
#include "rsa.h"

// Forward declare test functions
void test_all_nist_private_exponent_vectors(void);
void test_all_nist_sign_verify_vectors(void);
void test_random_sign_verify_enc_dec_with_nist_keys(void);
void test_random_sign_verify_enc_dec_with_generated_keys_2048(void);
void test_random_sign_verify_enc_dec_with_generated_keys_4096(void);
void test_genkey_1024_multiple_times(void);
void test_genkey_invalid_size_too_small(void);
void test_genkey_invalid_size_too_large(void);
void test_genkey_valid_size_not_power_of_two(void); // Renamed from test_genkey_invalid_size_not_power_of_two based on implementation
void test_euler_totient_function_with_vectors(void);
void test_rsa_pss_sign_verify_happy_path(void);
void test_rsa_pss_sign_verify_generate_keys(void);
void test_rsa_pss_verify_modified_message(void);
void test_rsa_pss_verify_modified_signature(void);
void test_rsa_pss_zero_length_message(void);

// Test suites will be run here

int main(void) {
    rsa_set_allocators();
    UNITY_BEGIN();
    RUN_TEST(test_all_nist_private_exponent_vectors);
    RUN_TEST(test_all_nist_sign_verify_vectors);
    RUN_TEST(test_random_sign_verify_enc_dec_with_nist_keys);
    RUN_TEST(test_random_sign_verify_enc_dec_with_generated_keys_2048);
    RUN_TEST(test_random_sign_verify_enc_dec_with_generated_keys_4096);
    RUN_TEST(test_genkey_1024_multiple_times);
    RUN_TEST(test_genkey_invalid_size_too_small);
    RUN_TEST(test_genkey_invalid_size_too_large);
    RUN_TEST(test_genkey_valid_size_not_power_of_two); // Per user request
    RUN_TEST(test_euler_totient_function_with_vectors);
    RUN_TEST(test_rsa_pss_sign_verify_happy_path);
    RUN_TEST(test_rsa_pss_sign_verify_generate_keys);
    RUN_TEST(test_rsa_pss_verify_modified_message);
    RUN_TEST(test_rsa_pss_verify_modified_signature);
    RUN_TEST(test_rsa_pss_zero_length_message);
    return UNITY_END();
}
