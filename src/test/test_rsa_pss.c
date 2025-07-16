#include "unity.h"
#include "rsa.h"
#include "test_helpers.h"
#include "test_common.h"

const char RSA_PSS_PRIME_P[] = "160252590505041750332111686678129741353300256858106084829801775515002117535930688189325371055545232842086937031804048427038291113677639664691882396375891131212944491037503276449402139527354017282204389650877584480294355298355090199225341147650484913255624475779762264475799257268930381201792080170697414114227";
const char RSA_PSS_PRIME_Q[] = "153298609280541504947860111297047517158812292657931387130253675216029871216956532580340143207615212566079445236764712819466507610045505138781059971081312919275412157928873168337071366964163899827425135661619274169930999014270735377549183393527981068182721450336041277075682819539811558077762960316924456149349";
const char RSA_PSS_PUBLIC_N[] = "24566499258027010724915580093113285804870167901171529495497955443012006897789688602960926539542320001266424736537433266611935158350739712943060248534191187606558499032643177314725979156582350559411854956700785115228393724912028007916782326076026810820814200524674773082070809590300690054416379657261604181499946123168274249868597746353531807830249777047025891602901318655603301324019316395571421048695855929118257451511703070008071259002459370051631374586167637483657284690151196492323643435000112063190328943185608020125628334499731127880263791320941525907516560544403321594823922223867756847180122091601936057688223";
int RSA_PSS_PUBLIC_E = 0x10001;

void test_rsa_pss_sign_verify_happy_path(void) {
    rsa_ctx_t pubkey;
    rsa_ctx_t privkey;

    rsa_init(&pubkey);
    rsa_init(&privkey);

    rsa_set_pubkey(&pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);
    rsa_set_privkey(&privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q, strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);

    for (int i = 0; i < 10; i++) {
        // create test data
        const size_t BUFSIZE = 10000;
        unsigned char *data = rand_bytes_urandom(BUFSIZE);
        mpz_t signature;
        mpz_init(signature);

        rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed");
        result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_verify failed");
        free(data);
        mpz_clear(signature);
    }
    rsa_free(&pubkey);
    rsa_free(&privkey);
}

void test_rsa_pss_sign_verify_generate_keys(void) {
    for (int i = 0; i < 10; i++) {
        rsa_error_t result = RSA_SUCCESS;
        rsa_ctx_t pubkey;
        rsa_ctx_t privkey;

        rsa_init(&pubkey);
        rsa_init(&privkey);

        result = rsa_genkey(&privkey, 1024, 0);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_genkey failed");
        result = rsa_pubkey_from_private(&pubkey, &privkey);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pubkey_from_private failed");

        // create test data
        const size_t BUFSIZE = 10000;
        unsigned char *data = rand_bytes_urandom(BUFSIZE);
        mpz_t signature;
        mpz_init(signature);

        result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed");

        result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_verify failed");

        free(data);
        mpz_clear(signature);
        rsa_free(&pubkey);
        rsa_free(&privkey);
    }
}

void test_rsa_pss_verify_modified_message(void) {
    rsa_ctx_t pubkey;
    rsa_ctx_t privkey;

    rsa_init(&pubkey);
    rsa_init(&privkey);

    rsa_set_pubkey(&pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);
    rsa_set_privkey(&privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q, strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);

    const size_t BUFSIZE = 100;
    unsigned char *data = rand_bytes_urandom(BUFSIZE);
    mpz_t signature;
    mpz_init(signature);

    rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed");

    data[0]++; // Modify the message

    result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_ERROR_INVALID_SIGNATURE, result, "rsa_pss_verify should have failed");

    free(data);
    mpz_clear(signature);
    rsa_free(&pubkey);
    rsa_free(&privkey);
}

void test_rsa_pss_verify_modified_signature(void) {
    rsa_ctx_t pubkey;
    rsa_ctx_t privkey;

    rsa_init(&pubkey);
    rsa_init(&privkey);

    rsa_set_pubkey(&pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);
    rsa_set_privkey(&privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q, strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);

    const size_t BUFSIZE = 100;
    unsigned char *data = rand_bytes_urandom(BUFSIZE);
    mpz_t signature;
    mpz_init(signature);

    rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed");

    mpz_add_ui(signature, signature, 1); // Modify the signature

    result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_ERROR_INVALID_SIGNATURE, result, "rsa_pss_verify should have failed");

    free(data);
    mpz_clear(signature);
    rsa_free(&pubkey);
    rsa_free(&privkey);
}

void test_rsa_pss_zero_length_message(void) {
    rsa_ctx_t pubkey;
    rsa_ctx_t privkey;

    rsa_init(&pubkey);
    rsa_init(&privkey);

    rsa_set_pubkey(&pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);
    rsa_set_privkey(&privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q, strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL);

    unsigned char *data = NULL;
    const size_t BUFSIZE = 0;
    mpz_t signature;
    mpz_init(signature);

    rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed for zero length message");

    result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_verify failed for zero length message");

    mpz_clear(signature);
    rsa_free(&pubkey);
    rsa_free(&privkey);
}
