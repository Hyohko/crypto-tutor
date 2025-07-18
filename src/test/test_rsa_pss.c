#include "rsa.h"
#include "test_common.h"
#include "test_helpers.h"
#include "unity.h"

const char RSA_PSS_PRIME_P[] =
    "16025259050504175033211168667812974135330025685810608482980177551500211753"
    "59306881893253710555452328420869370318040484270382911136776396646918823963"
    "75891131212944491037503276449402139527354017282204389650877584480294355298"
    "35509019922534114765048491325562447577976226447579925726893038120179208017"
    "0697414114227";
const char RSA_PSS_PRIME_Q[] =
    "15329860928054150494786011129704751715881229265793138713025367521602987121"
    "69565325803401432076152125660794452367647128194665076100455051387810599710"
    "81312919275412157928873168337071366964163899827425135661619274169930999014"
    "27073537754918339352798106818272145033604127707568281953981155807776296031"
    "6924456149349";
const char RSA_PSS_PUBLIC_N[] =
    "24566499258027010724915580093113285804870167901171529495497955443012006897"
    "78968860296092653954232000126642473653743326661193515835073971294306024853"
    "41911876065584990326431773147259791565823505594118549567007851152283937249"
    "12028007916782326076026810820814200524674773082070809590300690054416379657"
    "26160418149994612316827424986859774635353180783024977704702589160290131865"
    "56033013240193163955714210486958559291182574515117030700080712590024593700"
    "51631374586167637483657284690151196492323643435000112063190328943185608020"
    "12562833449973112788026379132094152590751656054440332159482392222386775684"
    "7180122091601936057688223";
int RSA_PSS_PUBLIC_E = 0x10001;

void test_rsa_pss_sign_verify_happy_path(void) {
    rsa_ctx_t pubkey;
    rsa_ctx_t privkey;

    rsa_init(&pubkey);
    rsa_init(&privkey);

    rsa_set_pubkey(
        &pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E,
        RSA_BASE_DECIMAL
    );
    rsa_set_privkey(
        &privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q,
        strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL
    );

    for (int i = 0; i < 10; i++) {
        // create test data
        const size_t BUFSIZE = 10000;
        unsigned char *data = rand_bytes_urandom(BUFSIZE);
        mpz_t signature;
        mpz_init(signature);

        rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, result, "rsa_pss_sign failed"
        );
        result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, result, "rsa_pss_verify failed"
        );
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
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, result, "rsa_pubkey_from_private failed"
        );

        // create test data
        const size_t BUFSIZE = 10000;
        unsigned char *data = rand_bytes_urandom(BUFSIZE);
        mpz_t signature;
        mpz_init(signature);

        result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, result, "rsa_pss_sign failed"
        );

        result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
        TEST_ASSERT_EQUAL_INT_MESSAGE(
            RSA_SUCCESS, result, "rsa_pss_verify failed"
        );

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

    rsa_set_pubkey(
        &pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E,
        RSA_BASE_DECIMAL
    );
    rsa_set_privkey(
        &privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q,
        strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL
    );

    const size_t BUFSIZE = 100;
    unsigned char *data = rand_bytes_urandom(BUFSIZE);
    mpz_t signature;
    mpz_init(signature);

    rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed");

    data[0]++;  // Modify the message

    result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_ERROR_INVALID_SIGNATURE, result, "rsa_pss_verify should have failed"
    );

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

    rsa_set_pubkey(
        &pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E,
        RSA_BASE_DECIMAL
    );
    rsa_set_privkey(
        &privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q,
        strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL
    );

    const size_t BUFSIZE = 100;
    unsigned char *data = rand_bytes_urandom(BUFSIZE);
    mpz_t signature;
    mpz_init(signature);

    rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(RSA_SUCCESS, result, "rsa_pss_sign failed");

    mpz_add_ui(signature, signature, 1);  // Modify the signature

    result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_ERROR_INVALID_SIGNATURE, result, "rsa_pss_verify should have failed"
    );

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

    rsa_set_pubkey(
        &pubkey, RSA_PSS_PUBLIC_N, strlen(RSA_PSS_PUBLIC_N), RSA_PSS_PUBLIC_E,
        RSA_BASE_DECIMAL
    );
    rsa_set_privkey(
        &privkey, RSA_PSS_PRIME_P, strlen(RSA_PSS_PRIME_P), RSA_PSS_PRIME_Q,
        strlen(RSA_PSS_PRIME_Q), RSA_PSS_PUBLIC_E, RSA_BASE_DECIMAL
    );

    unsigned char *data = NULL;
    const size_t BUFSIZE = 0;
    mpz_t signature;
    mpz_init(signature);

    rsa_error_t result = rsa_pss_sign(&privkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_SUCCESS, result, "rsa_pss_sign failed for zero length message"
    );

    result = rsa_pss_verify(&pubkey, data, BUFSIZE, signature);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        RSA_SUCCESS, result, "rsa_pss_verify failed for zero length message"
    );

    mpz_clear(signature);
    rsa_free(&pubkey);
    rsa_free(&privkey);
}
