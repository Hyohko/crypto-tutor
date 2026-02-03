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

/**
 * @file rsa.h
 * @brief Interface for RSA encryption, decryption, key generation, signing, and
 * verification.
 *
 * This library provides functions for performing RSA operations using the GMP
 * (GNU Multiple Precision Arithmetic Library). It supports key generation,
 * setting public/private keys from various formats, encryption/decryption, and
 * signing/verification.
 */

#ifndef RSA_H
#define RSA_H
#include <gmp.h>
#include <stdio.h>
// #include <limits.h>
#include <stdbool.h>

/**
 * @def _countof(arr)
 * @brief Calculates the number of elements in a statically allocated array.
 * @param arr The array.
 * @return The number of elements in arr.
 */
#ifndef _countof
#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

/**
 * @def MAX(a, b)
 * @brief Returns the maximum of two values.
 * @param a The first value.
 * @param b The second value.
 * @return The greater of a and b.
 */
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/**
 * @def MIN(a, b)
 * @brief Returns the minimum of two values.
 * @param a The first value.
 * @param b The second value.
 * @return The lesser of a and b.
 */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/** @def RSA_DEFAULT_PUBLIC_EXPONENT
 *  @brief Default public exponent (e) value (65537).
 *  A commonly used prime exponent for RSA.
 */
#define RSA_DEFAULT_PUBLIC_EXPONENT (0x10001)  // 65537

/** @def RSA_KEYSIZE_MAX
 *  @brief Maximum supported RSA key size in bits (e.g., 32768).
 */
#define RSA_KEYSIZE_MAX (32768)

/** @def RSA_KEYSIZE_MIN
 *  @brief Minimum supported RSA key size in bits (e.g., 1024).
 *  Keys smaller than this are generally considered insecure.
 */
#define RSA_KEYSIZE_MIN (1024)

/**
 * @enum rsa_error_t
 * @brief Defines error codes returned by RSA functions.
 *
 * RSA_SUCCESS (0) indicates success, while negative values indicate various
 * errors.
 */
typedef enum {
    RSA_SUCCESS = 0,            /**< Operation completed successfully. */
    RSA_ERROR_P_NOT_PRIME = -1, /**< Provided P value is not prime. */
    RSA_ERROR_Q_NOT_PRIME = -2, /**< Provided Q value is not prime. */
    RSA_ERROR_INVALID_PRIME_TOO_SMALL =
        -3, /**< A prime factor (P or Q) is too small. */
    RSA_ERROR_MODINV_NOT_EXIST =
        -4, /**< Modular inverse does not exist (e.g., for d). */
    RSA_ERROR_INVALID_SIGNATURE = -5, /**< The provided signature is invalid. */
    RSA_ERROR_INVALID_SIGNATURE_SIZE =
        -6, /**< The size of the provided signature is incorrect. */
    RSA_ERROR_STRING_CONVERSION = -7, /**< Error converting a string to/from a
                                         number (e.g., invalid hex). */
    RSA_ERROR_INVALID_MODULUS =
        -8, /**< The modulus (N) is invalid (e.g., too small, not positive). */
    RSA_ERROR_INVALID_MESSAGE =
        -9, /**< The message to be encrypted/signed is invalid. */
    RSA_ERROR_INVALID_OUTPUT_SIZE = -10, /**< The output buffer is too small or
                                            output value is too large. */
    RSA_ERROR_INVALID_INPUT_SIZE =
        -11, /**< The input data size is invalid (e.g., larger than modulus). */
    RSA_ERROR_INVALID_EXPONENT =
        -12,                      /**< The public exponent (E) is invalid. */
    RSA_ERROR_INVALID_BASE = -13, /**< Invalid base specified for number
                                     conversion (e.g., not hex, dec). */
    RSA_ERROR_INVALID_LENGTH =
        -14, /**< A provided length (e.g., for a buffer or key) is invalid. */
    RSA_ERROR_INVALID_ARGUMENTS =
        -15, /**< One or more function arguments are NULL or invalid. */
    RSA_ERROR_INVALID_CONTEXT = -16, /**< The RSA context (rsa_ctx_t) is in an
                                        invalid state for the operation. */
    RSA_ERROR_KEY_SIZE_INVALID =
        -17, /**< The specified key size is not supported (e.g., not power of 2,
                too small, too large). */
    RSA_ERROR_KEY_NOT_SET = -18, /**< The RSA key (public or private) has not
                                    been set in the context. */
    RSA_ERROR_INVALID_KEY = -19, /**< General invalid key error. */
    RSA_ERROR_NOT_COPRIME = -20, /**< Values are not coprime when they need to
                                    be (e.g., e and lambda). */
    RSA_ERROR_PRIMES_TOO_CLOSE = -21, /**< Prime factors P and Q are too close,
                                         potentially weakening the key. */
    RSA_ERROR_ALLOC_FAILED = -22,     /**< Memory allocation failed. */
} rsa_error_t;

/**
 * @enum rsa_key_type_t
 * @brief Defines the type of key held in an RSA context.
 */
typedef enum {
    RSA_KEY_NOT_SET = 0xd3adb33fL, /**< Magic number indicating the key context
                                      is uninitialized or cleared. */
    RSA_PUBLIC = 0, /**< Indicates the context holds a public key. */
    RSA_PRIVATE = 1 /**< Indicates the context holds a private key. */
} rsa_key_type_t;

/**
 * @enum rsa_base_t
 * @brief Defines numerical bases for string-to-number conversions.
 */
typedef enum {
    RSA_BASE_BINARYDATA =
        0, /**< Raw binary data. GMP mpz_import/export may treat as base 256. */
    RSA_BASE_DECIMAL = 10, /**< Decimal representation. */
    RSA_BASE_HEX = 16,     /**< Hexadecimal representation. */
    RSA_BASE_BASE32 = 32   /**< Base32 representation. */
} rsa_base_t;
// Base64 is not supported by the GMP library, so we will not support it here
// either

/**
 * @struct rsa_ctx_t
 * @brief Holds the components of an RSA key and related information.
 *
 * This structure is used to store all necessary parts of an RSA public or
 * private key, including the large integer components, key size, and key type.
 */
typedef struct {
    mpz_t p; /**< First prime factor of the modulus (used in private keys). */
    mpz_t q; /**< Second prime factor of the modulus (used in private keys). */
    mpz_t d; /**< Private exponent. */
    mpz_t n; /**< Modulus (n = p * q). */
    mpz_t e; /**< Public exponent. */
    // Chinese Remainder Theorem - Precomputed values
    mpz_t dp; /**< First half of the CRT private exponent -> d mod (p - 1). */
    mpz_t dq; /**< First half of the CRT private exponent -> d mod (q - 1). */
    mpz_t q_inv; /**< q^(-1) mod p. */
    mp_bitcnt_t key_size; /**< Size of the key (modulus n) in bits. */
    rsa_key_type_t
        is_private; /**< Flag indicating if the key is private (RSA_PRIVATE),
                       public (RSA_PUBLIC), or not set (RSA_KEY_NOT_SET). */
} rsa_ctx_t;

/**
 * @brief Sets custom memory allocation functions for GMP.
 * @note This function should ideally be called once at the beginning of the
 * program before any other RSA or GMP operations. It configures GMP to use
 *       secure_malloc, secure_realloc, and secure_free from rsa.c.
 *       The implementation in rsa.c makes this a singleton; subsequent calls do
 * nothing.
 */
void rsa_set_allocators(void);

/**
 * @brief Initializes an RSA context.
 * @param[out] ctx Pointer to the rsa_ctx_t structure to initialize.
 *                 All mpz_t members are initialized. is_private is set to
 * RSA_KEY_NOT_SET.
 */
void rsa_init(rsa_ctx_t *ctx);

/**
 * @brief Clears the RSA key components within a context but does not free the
 * mpz_t structures themselves. Sets mpz_t members to 0 and is_private to
 * RSA_KEY_NOT_SET.
 * @param[in,out] ctx Pointer to the rsa_ctx_t structure to clear.
 */
void rsa_clear(rsa_ctx_t *ctx);

/**
 * @brief Frees the mpz_t members of an RSA context and zeroes the structure.
 * @param[in,out] ctx Pointer to the rsa_ctx_t structure to free. is_private is
 * set to RSA_KEY_NOT_SET.
 */
void rsa_free(rsa_ctx_t *ctx);

/**
 * @brief Generates an RSA key pair (public and private keys).
 * @param[out] ctx Pointer to the rsa_ctx_t structure where the generated key
 * will be stored. On success, this context will contain P, Q, D, N, E,
 * key_size, and is_private will be RSA_PRIVATE.
 * @param[in] bitlen The desired key size in bits (e.g., 1024, 2048, 4096). Must
 * be a power of two and within [RSA_KEYSIZE_MIN, RSA_KEYSIZE_MAX].
 * @param[in] exponent The public exponent value (e.g., 65537). If 0,
 * RSA_DEFAULT_PUBLIC_EXPONENT is used.
 * @return RSA_SUCCESS on success, or an rsa_error_t code on failure.
 */
rsa_error_t rsa_genkey(
    rsa_ctx_t *ctx, unsigned int bitlen, unsigned int exponent
);

/**
 * @brief Prints debugging information about the RSA key context to standard
 * output. Prints P, Q, D, N, E (in hex), DP, DQ, Q_INV, key_size, and is_private.
 * @param[in] ctx Pointer to the rsa_ctx_t structure to debug.
 */
void rsa_debug(rsa_ctx_t *ctx);

/**
 * @brief Returns a human-readable string for an RSA error code.
 * @param[in] err_code The rsa_error_t error code.
 * @return A constant string describing the error. Returns "Unknown error code"
 * if the code is not recognized.
 */
const char *rsa_strerror(int err_code);

/**
 * @brief Sets a public key in the RSA context from string representations of
 * modulus and exponent.
 * @param[out] ctx Pointer to the rsa_ctx_t structure to populate.
 * @param[in] modulus The modulus (N) as a string.
 * @param[in] len_modulus Length of the modulus string (used if base is
 * RSA_BASE_BINARYDATA). Ignored for other bases.
 * @param[in] exponent The public exponent (E).
 * @param[in] base The numerical base of the modulus string (e.g., RSA_BASE_HEX,
 * RSA_BASE_DECIMAL, RSA_BASE_BINARYDATA).
 * @return RSA_SUCCESS on success, or an rsa_error_t code on failure.
 */
rsa_error_t rsa_set_pubkey(
    rsa_ctx_t *ctx, const char *modulus, size_t len_modulus,
    unsigned int exponent, rsa_base_t base
);

/**
 * @brief Sets a private key in the RSA context from string representations of
 * prime factors and exponent. Computes N and D from P, Q, and E.
 * @param[out] ctx Pointer to the rsa_ctx_t structure to populate.
 * @param[in] prime_p The first prime factor (P) as a string.
 * @param[in] len_p Length of the prime_p string (used if base is
 * RSA_BASE_BINARYDATA).
 * @param[in] prime_q The second prime factor (Q) as a string.
 * @param[in] len_q Length of the prime_q string (used if base is
 * RSA_BASE_BINARYDATA).
 * @param[in] exponent The public exponent (E).
 * @param[in] base The numerical base of the prime_p and prime_q strings.
 * @return RSA_SUCCESS on success, or an rsa_error_t code on failure.
 */
rsa_error_t rsa_set_privkey(
    rsa_ctx_t *ctx, const char *prime_p, size_t len_p, const char *prime_q,
    size_t len_q, unsigned int exponent, rsa_base_t base
);

/**
 * @brief Extracts the public key components (N, E) from a private key context.
 * @param[out] pubkey Pointer to the rsa_ctx_t structure to store the extracted
 * public key.
 * @param[in] privkey Pointer to the rsa_ctx_t structure containing the private
 * key.
 * @return RSA_SUCCESS on success, or RSA_ERROR_INVALID_ARGUMENTS /
 * RSA_ERROR_INVALID_CONTEXT on failure.
 */
rsa_error_t rsa_pubkey_from_private(
    rsa_ctx_t *pubkey, const rsa_ctx_t *privkey
);

/**
 * @brief Performs RSA public key operation (encryption or signature
 * verification) using mpz_t integers. output = input^E mod N
 * @param[in] ctx Pointer to an rsa_ctx_t structure containing a public or
 * private key (E and N must be set).
 * @param[out] output Pointer to an mpz_t to store the result.
 * @param[in] input Pointer to an mpz_t containing the data to process.
 * @return RSA_SUCCESS on success, or an rsa_error_t code on failure.
 */
rsa_error_t rsa_mpz_public(rsa_ctx_t *ctx, mpz_t output, const mpz_t input);

/**
 * @brief Performs RSA private key operation (decryption or signing) using mpz_t
 * integers. output = input^D mod N
 * @param[in] ctx Pointer to an rsa_ctx_t structure containing a private key.
 * @param[out] output Pointer to an mpz_t to store the result.
 * @param[in] input Pointer to an mpz_t containing the data to process.
 * @return RSA_SUCCESS on success, or an rsa_error_t code on failure.
 */
rsa_error_t rsa_mpz_private(rsa_ctx_t *ctx, mpz_t output, const mpz_t input);

/**
 * @brief Signs a message digest using RSA private key (mpz_t interface).
 * This function is declared but its implementation might be missing in rsa.c.
 * Typically, RSA signing is rsa_mpz_private applied to a padded hash of the
 * message. The `expected_output` parameter is unusual for a standard sign
 * operation.
 * @param[in] ctx Pointer to an rsa_ctx_t structure containing a private key.
 * @param[out] output Pointer to an mpz_t to store the signature.
 * @param[in] input Pointer to an mpz_t containing the message digest to sign.
 * @param[in] expected_output This parameter's purpose is unclear from
 * declaration alone for a standard sign.
 * @return RSA_SUCCESS on success, or an rsa_error_t code.
 */
rsa_error_t rsa_mpz_sign(
    rsa_ctx_t *ctx, mpz_t output, const mpz_t input, const mpz_t expected_output
);

/**
 * @brief Verifies an RSA signature against a message digest (mpz_t interface).
 * This function is declared but its implementation might be missing in rsa.c.
 * Typically, RSA verification involves using rsa_mpz_public on the signature
 * and comparing the result to the (padded) message digest.
 * @param[in] ctx Pointer to an rsa_ctx_t structure containing a public key.
 * @param[in] message Pointer to an mpz_t containing the message digest.
 * @param[in] signature Pointer to an mpz_t containing the signature to verify.
 * @return RSA_SUCCESS if the signature is valid, or an rsa_error_t code
 * otherwise.
 */
rsa_error_t rsa_mpz_verify(
    rsa_ctx_t *ctx, const mpz_t message, const mpz_t signature
);

/**
 * @brief Validates the components of an RSA key (P, Q, N, E, key_size).
 * Checks for primality of P and Q (if private key), validity of E, N, and
 * key_size.
 * @param[in] ctx Pointer to the rsa_ctx_t structure containing the key to
 * validate.
 * @return RSA_SUCCESS if the key components are valid, or an rsa_error_t code
 * on failure.
 */
rsa_error_t rsa_validate_key_components(rsa_ctx_t *ctx);

/**
 * @brief Computes the private exponent (D) from P, Q, and E.
 * Assumes P, Q, and E are already set and valid in the context.
 * @param[in,out] ctx Pointer to the rsa_ctx_t structure. D will be populated on
 * success.
 * @return RSA_SUCCESS on success, or an rsa_error_t code (e.g., if E is not
 * coprime to lambda(N)).
 */
rsa_error_t rsa_compute_private_exponent(rsa_ctx_t *ctx);

/**
 * @brief Generates a random mpz_t integer of a specified bit length (fast, not
 * cryptographically secure for key generation). Uses gmp_randinit_default and
 * seeds with clock_gettime.
 * @param[out] result Pointer to an mpz_t to store the generated random number.
 * @param[in] num_bits The desired number of bits for the random number.
 * @return RSA_SUCCESS on success, or an rsa_error_t code.
 */
rsa_error_t rsa_mpz_gen_random_fast(mpz_t result, mp_bitcnt_t num_bits);

/**
 * @brief Generates a cryptographically secure random mpz_t integer of a
 * specified bit length. Reads from /dev/urandom. num_bits must be a multiple
 * of 8.
 * @param[out] result Pointer to an mpz_t to store the generated random number.
 * @param[in] num_bits The desired number of bits for the random number (must be
 * multiple of 8).
 * @return RSA_SUCCESS on success, or an rsa_error_t code.
 */
rsa_error_t rsa_mpz_gen_random_secure(mpz_t result, mp_bitcnt_t num_bits);

/**
 * @brief Performs RSA private key operation (decryption or signing) with
 * string/binary data.
 * @param[in] ctx Pointer to an rsa_ctx_t structure holding a private key.
 * @param[out] output Buffer to store the result.
 * @param[in] olen Size of the output buffer. (Note: mpz_export behavior might
 * not strictly use this for sizing in all cases).
 * @param[in] input Buffer containing the input data.
 * @param[in] ilen Size of the input data.
 * @param[in] base The numerical base for input/output strings, or
 * RSA_BASE_BINARYDATA for raw bytes.
 * @return RSA_SUCCESS on success, or an rsa_error_t code.
 */
rsa_error_t rsa_private(
    rsa_ctx_t *ctx, char *output, size_t olen, const char *input, size_t ilen,
    rsa_base_t base
);

/**
 * @brief Performs RSA public key operation (encryption or signature
 * verification) with string/binary data.
 * @param[in] ctx Pointer to an rsa_ctx_t structure holding a public (or
 * private, as E and N are used) key.
 * @param[out] output Buffer to store the result.
 * @param[in] olen Size of the output buffer.
 * @param[in] input Buffer containing the input data.
 * @param[in] ilen Size of the input data.
 * @param[in] base The numerical base for input/output strings, or
 * RSA_BASE_BINARYDATA for raw bytes.
 * @return RSA_SUCCESS on success, or an rsa_error_t code.
 */
rsa_error_t rsa_public(
    rsa_ctx_t *ctx, char *output, size_t olen, const char *input, size_t ilen,
    rsa_base_t base
);

/**
 * @brief Performs RSA-PSS-SHA256 signing on arbitrary data.
 * @param[in] ctx Pointer to an rsa_ctx_t structure holding a private key.
 * @param[in] msg Data being verified, of an arbitrary length
 * @param[in] msg_len Size of the msg buffer.
 * @param[out] signature Signature in mpz_t format.
 * @return RSA_SUCCESS if signature created correctly, or an rsa_error_t code.
 */
rsa_error_t rsa_pss_sign(
    rsa_ctx_t *ctx, const unsigned char *msg, size_t msg_len, mpz_t signature
);

/**
 * @brief Performs RSA-PSS-SHA256 signature validation on arbitrary data.
 * @param[in] ctx Pointer to an rsa_ctx_t structure holding a public (or
 * private, as E and N are used) key.
 * @param[in] msg Data being verified, of an arbitrary length
 * @param[in] msg_len Size of the msg buffer.
 * @param[in] signature Signature in mpz_t format.
 * @return RSA_SUCCESS if signature is valid, or an rsa_error_t code.
 */
rsa_error_t rsa_pss_verify(
    rsa_ctx_t *ctx, const unsigned char *msg, size_t msg_len, mpz_t signature
);
#endif  // RSA_H
