/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
*/
#ifndef RSA_H
#define RSA_H
#include <gmp.h>
#include <stdio.h>
//#include <limits.h>
#include <stdbool.h>

#ifndef _countof
#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#ifndef MAX
#define MAX(a, b)   ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b)   ((a) < (b) ? (a) : (b))
#endif

#define RSA_DEFAULT_PUBLIC_EXPONENT (0x10001) // 65537
#define RSA_KEYSIZE_MAX (32768)
#define RSA_KEYSIZE_MIN (1024)

// ERROR CODES
typedef enum {
    RSA_SUCCESS = 0,
    RSA_ERROR_P_NOT_PRIME = -1,
    RSA_ERROR_Q_NOT_PRIME = -2,
    RSA_ERROR_INVALID_PRIME_TOO_SMALL = -3,
    RSA_ERROR_MODINV_NOT_EXIST = -4,
    RSA_ERROR_INVALID_SIGNATURE = -5,
    RSA_ERROR_INVALID_SIGNATURE_SIZE = -6,
    RSA_ERROR_STRING_CONVERSION = -7,
    RSA_ERROR_INVALID_MODULUS = -8,
    RSA_ERROR_INVALID_MESSAGE = -9,
    RSA_ERROR_INVALID_OUTPUT_SIZE = -10,
    RSA_ERROR_INVALID_INPUT_SIZE = -11,
    RSA_ERROR_INVALID_EXPONENT = -12,
    RSA_ERROR_INVALID_BASE = -13,
    RSA_ERROR_INVALID_LENGTH = -14,
    RSA_ERROR_INVALID_ARGUMENTS = -15,
    RSA_ERROR_INVALID_CONTEXT = -16,
    RSA_ERROR_KEY_SIZE_INVALID = -17,
    RSA_ERROR_KEY_NOT_SET = -18,
    RSA_ERROR_INVALID_KEY = -19,
    RSA_ERROR_NOT_COPRIME = -20,
    RSA_ERROR_PRIMES_TOO_CLOSE = -21,
    RSA_ERROR_ALLOC_FAILED = -22,
} rsa_error_t;

typedef enum {
    RSA_KEY_NOT_SET = 0xd3adb33fL,
    RSA_PUBLIC = 0,
    RSA_PRIVATE = 1
} rsa_key_type_t;

// Available bases for conversion - as an enum
typedef enum {
    RSA_BASE_BINARYDATA = 0,
    RSA_BASE_DECIMAL = 10,
    RSA_BASE_HEX = 16,
    RSA_BASE_BASE32 = 32
} rsa_base_t;
// Base64 is not supported by the GMP library, so we will not support it here either

// Define a structure to hold the RSA key components
typedef struct {
    mpz_t p; // First prime factor of the modulus
    mpz_t q; // Second prime factor of the modulus
    mpz_t d; // Private exponent
    mpz_t n; // Modulus (n = p * q)
    mpz_t e; // Public exponent
    mp_bitcnt_t key_size; // Size of the key in bits
    rsa_key_type_t is_private; // Flag to indicate if the key is private (1) or public (0)
} rsa_ctx_t;

void rsa_set_allocators(void);
void rsa_init(rsa_ctx_t *ctx);
void rsa_clear(rsa_ctx_t *ctx);
void rsa_free(rsa_ctx_t *ctx);
rsa_error_t rsa_genkey(rsa_ctx_t *ctx, unsigned int bitlen, unsigned int exponent);
void rsa_debug(rsa_ctx_t *ctx);
const char* rsa_strerror(int err_code);

rsa_error_t rsa_set_pubkey(rsa_ctx_t *ctx, const char *modulus, size_t len_modulus, unsigned int exponent, rsa_base_t base);
rsa_error_t rsa_set_privkey(rsa_ctx_t *ctx, const char *prime_p, size_t len_p, const char *prime_q, size_t len_q, unsigned int exponent, rsa_base_t base);
rsa_error_t rsa_pubkey_from_private(rsa_ctx_t *pubkey, const rsa_ctx_t *privkey);
rsa_error_t rsa_mpz_public(rsa_ctx_t *ctx, mpz_t output, const mpz_t input);
rsa_error_t rsa_mpz_private(rsa_ctx_t *ctx, mpz_t output, const mpz_t input);
rsa_error_t rsa_mpz_sign(rsa_ctx_t *ctx, mpz_t output, const mpz_t input, const mpz_t expected_output);
rsa_error_t rsa_mpz_verify(rsa_ctx_t *ctx, const mpz_t message, const mpz_t signature);
rsa_error_t rsa_validate_key_components(rsa_ctx_t *ctx);
rsa_error_t rsa_compute_private_exponent(rsa_ctx_t *ctx);
rsa_error_t rsa_mpz_gen_random_fast(mpz_t result, mp_bitcnt_t num_bits);
rsa_error_t rsa_mpz_gen_random_secure(mpz_t result, mp_bitcnt_t num_bits);

rsa_error_t rsa_private(rsa_ctx_t *ctx, char *output, size_t olen, const char *input, size_t ilen, rsa_base_t base);
rsa_error_t rsa_public(rsa_ctx_t *ctx, char *output, size_t olen, const char *input, size_t ilen, rsa_base_t base);
#endif // RSA_H