#include "rsa.h"
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>

#define MILLER_RABIN_ITERATIONS 50

/****************************************************
    Static / private functions
****************************************************/

// Force writing zeroes to newly-allocated blocks of memory
static void * secure_malloc(size_t alloc_size){
    char *ret = (char*)malloc(alloc_size);
    if(NULL == ret)
        exit(1); // According to GMP specs, terminate program. GMP doesn't handle alloc errors
    // non-optimizable zero-ing out of the buffer
    explicit_bzero (ret, alloc_size);
    return (void*)ret;
}

// Force writing zeroes before deallocating memory
static void secure_free(void *ptr, size_t size)
{
    if(NULL != ptr)
    {
        // non-optimizable zero-ing out of the buffer
        explicit_bzero ((char*)ptr, size);
        free(ptr);
    }
}

static void * secure_realloc(void *ptr, size_t old_size, size_t new_size) {
    if(new_size <= old_size) {
        if(NULL != ptr && new_size != old_size){
            // erase the end of the memory block, the delta between new_size and old_size
            // don't allocate new memory.
            char *edit = (char*)ptr + new_size + 1;
            size_t to_zero = old_size - new_size - 1;
            explicit_bzero(edit, to_zero);
        } 
        return ptr;
    }
    char *temp = (char*)secure_malloc(new_size);
    if(NULL == temp)
    {
        exit(1); // According to GMP specs, terminate program. GMP doesn't handle alloc errors
        // This will likely happen anyway if secure_malloc fails, but to be on the safe side...
    }
    if (NULL != ptr)
    {
        // if we reach this point, new_size > old_size, so just memcpy with old_size
        memcpy(temp, (char*)ptr, new_size);
        secure_free(ptr, old_size);
    }
    return (void*)temp;
}

static rsa_error_t rsa_genprime(mpz_t prime, mp_bitcnt_t num_bits, bool is_secure)
{
    if (NULL == prime || num_bits < 2 || num_bits > RSA_KEYSIZE_MAX) {
        return RSA_ERROR_INVALID_ARGUMENTS;
    }
    // Generate a random prime number with the specified number of bits
    do {
        if (is_secure)
            rsa_mpz_gen_random_secure(prime, num_bits);
        else
            rsa_mpz_gen_random_fast(prime, num_bits);
    } while (mpz_probab_prime_p(prime, MILLER_RABIN_ITERATIONS) == 0);
    return RSA_SUCCESS; // Success: prime generated
}

// Check if the two primes are too close to each other - bitshift to the right leaving
// the 200 most significant bits and compare the hamming distance. less than 20 bits
// difference means the primes are too close to the square root of the modulus, making
// factoring way easier.
static rsa_error_t rsa_primes_too_close(mpz_t p, mpz_t q)
{
    if (NULL == p || NULL == q) {
        return RSA_ERROR_INVALID_ARGUMENTS;  // Treat invalid input as "too close"
    }
    mp_bitcnt_t p_size = mpz_sizeinbase(p, 2);
    mp_bitcnt_t q_size = mpz_sizeinbase(q, 2);
    if(p_size <= 200 || q_size <= 200) {
        // in practice, should never happen, but check anyway.
        return RSA_ERROR_INVALID_PRIME_TOO_SMALL;
    }

    mpz_t p_quotient, q_quotient;
    mpz_inits(p_quotient, q_quotient, NULL);
    mpz_fdiv_q_2exp(p_quotient, p, p_size - 200);
    mpz_fdiv_q_2exp(q_quotient, q, q_size - 200);
    mp_bitcnt_t hamdist = mpz_hamdist(p_quotient, q_quotient);
    mpz_clears(p_quotient, q_quotient, NULL);
    if (hamdist < 20) {
        return RSA_ERROR_PRIMES_TOO_CLOSE; // Error: P and Q are too close
    }
    return RSA_SUCCESS; // Success: P and Q are not too close
}

// effectively a singleton that can be called only once
void rsa_set_allocators(void) {
    static bool is_set = false;
    if(!is_set) {
        mp_set_memory_functions(secure_malloc, secure_realloc, secure_free);
        is_set = true;
    }
}

// RSA Context functions
void rsa_init(rsa_ctx_t *ctx) {
    rsa_set_allocators();
    if (NULL == ctx) {
        return; // Avoid SEGFAULT
    }
    explicit_bzero(ctx, sizeof(rsa_ctx_t)); // Initialize context to zero
    mpz_inits(ctx->p, ctx->q, ctx->d, ctx->n, ctx->e, NULL);
    ctx->is_private = RSA_KEY_NOT_SET; // Initialize to invalid key state
}

// Don't reallocate, just set all ints to zero
void rsa_clear(rsa_ctx_t *ctx) {
    if (NULL == ctx) {
        return; // Avoid SEGFAULT
    }
    if (RSA_PUBLIC != ctx->is_private && RSA_PRIVATE != ctx->is_private) {
        return; // Avoid clearing uninitialized context
    }
    mpz_set_ui(ctx->p, 0);
    mpz_set_ui(ctx->q, 0);
    mpz_set_ui(ctx->d, 0);
    mpz_set_ui(ctx->n, 0);
    mpz_set_ui(ctx->e, 0);
    ctx->is_private = RSA_KEY_NOT_SET; // Initialize to invalid key state
}

void rsa_free(rsa_ctx_t *ctx) {
    if (NULL == ctx) {
        return; // Avoid SEGFAULT
    }
    mpz_clears(ctx->p, ctx->q, ctx->d, ctx->n, ctx->e, NULL);
    explicit_bzero(ctx, sizeof(rsa_ctx_t)); // Initialize context to zero
    ctx->is_private = RSA_KEY_NOT_SET; // Initialize to invalid key state
}

rsa_error_t rsa_is_valid_base(rsa_base_t base) {
    switch (base) {
        case RSA_BASE_BINARYDATA:
        case RSA_BASE_DECIMAL:
        case RSA_BASE_HEX:
        case RSA_BASE_BASE32:
            return RSA_SUCCESS; // Valid base
        default:
            return RSA_ERROR_INVALID_BASE; // Invalid base
    }
}

void rsa_debug(rsa_ctx_t *ctx) {
    if (NULL == ctx) {
        return; // Avoid SEGFAULT
    }
    gmp_printf("p: %Zx\n", ctx->p);
    gmp_printf("q: %Zx\n", ctx->q);
    gmp_printf("d: %Zx\n", ctx->d);
    gmp_printf("n: %Zx\n", ctx->n);
    gmp_printf("e: %Zx\n", ctx->e);
    printf("key_size: %zu\n", ctx->key_size);
    printf("is_private: %d\n", ctx->is_private);
}   

rsa_error_t rsa_mpz_set_pubkey(rsa_ctx_t *ctx, mpz_t modulus, unsigned int exponent) {
    if (NULL == ctx || NULL == modulus) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid input
    }
    if (RSA_KEY_NOT_SET != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context not initialized before setting the key
    }

    mpz_set(ctx->n, modulus); // Copy modulus to context
    mpz_set_ui(ctx->e, exponent);
    ctx->is_private = RSA_PUBLIC;
    ctx->key_size = mpz_sizeinbase(ctx->n, 2);
    // round up key_size to the next multiple of 8
    ctx->key_size += (ctx->key_size % 8);

    rsa_error_t ret = rsa_validate_key_components(ctx);
    if (RSA_SUCCESS != ret) {
        rsa_free(ctx); // Clear context on error
    }
    return ret;
}

rsa_error_t rsa_set_pubkey(rsa_ctx_t *ctx, const char *modulus, size_t len_modulus, unsigned int exponent, rsa_base_t base) {
    rsa_error_t ret = rsa_is_valid_base(base);
    if (RSA_SUCCESS != ret) {
        return ret; // Error: Invalid base
    }

    if (NULL == ctx || NULL == modulus) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid input
    }
    if (RSA_KEY_NOT_SET != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context not initialized before setting the key
    }
    if (RSA_BASE_BINARYDATA == base) {
        // import raw bytes into ctx->n assuming a big-endian byte order
        mpz_import(ctx->n, len_modulus, 1, sizeof(char), 1, 0, modulus);
    }
    else if (mpz_set_str(ctx->n, modulus, base) != 0) {
        return RSA_ERROR_STRING_CONVERSION; // Error: Invalid modulus format
    }
    
    mpz_set_ui(ctx->e, exponent);
    ctx->is_private = RSA_PUBLIC;
    ctx->key_size = mpz_sizeinbase(ctx->n, 2);
    // round up key_size to the next multiple of 8
    ctx->key_size += (ctx->key_size % 8);

    ret = rsa_validate_key_components(ctx);
    if (RSA_SUCCESS != ret) {
        rsa_free(ctx); // Clear context on error
    }
    return ret;
}

rsa_error_t rsa_mpz_set_privkey(rsa_ctx_t *ctx, mpz_t prime_p, mpz_t prime_q, unsigned int exponent) {
    if (NULL == ctx) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid input
    }
    if (RSA_KEY_NOT_SET != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context not initialized before setting the key
    }

    mpz_set(ctx->p, prime_p);
    mpz_set(ctx->q, prime_q);
    mpz_mul(ctx->n, ctx->p, ctx->q);
    mpz_set_ui(ctx->e, exponent);

    ctx->is_private = RSA_PRIVATE;
    ctx->key_size = mpz_sizeinbase(ctx->n, 2);
    // round up key_size to the next multiple of 8
    ctx->key_size += (ctx->key_size % 8);

    rsa_error_t ret = rsa_validate_key_components(ctx);
    if (RSA_SUCCESS != ret) {
        rsa_free(ctx); // Clear context on error
        return ret;
    }
    ret = rsa_compute_private_exponent(ctx);
    if (RSA_SUCCESS != ret) {
        rsa_free(ctx); // Clear context on error
        return ret; // Error: failed to compute private exponent
    }
    return ret;
}

rsa_error_t rsa_set_privkey(rsa_ctx_t *ctx, const char *prime_p, size_t len_p, const char *prime_q, size_t len_q, unsigned int exponent, rsa_base_t base) {
    rsa_error_t ret = rsa_is_valid_base(base);
    if (RSA_SUCCESS != ret) {
        return ret; // Error: Invalid base
    }

    if (NULL == ctx || prime_p == NULL || prime_q == NULL) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid input
    }
    if (RSA_KEY_NOT_SET != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context not initialized before setting the key
    }

    if (RSA_BASE_BINARYDATA == base) {
        // import raw bytes into ctx->p and ctx->q assuming a big-endian byte order
        mpz_import(ctx->p, len_p, 1, sizeof(char), 1, 0, prime_p);
        mpz_import(ctx->q, len_q, 1, sizeof(char), 1, 0, prime_q);
    }
    else {
        if (mpz_set_str(ctx->p, prime_p, base) != 0) {
            ret = RSA_ERROR_STRING_CONVERSION; // Error: Invalid prime P format
            goto error_exit;
        }
        if (mpz_set_str(ctx->q, prime_q, base) != 0) {
            ret = RSA_ERROR_STRING_CONVERSION; // Error: Invalid prime Q format
            goto error_exit;
        }
    }

    mpz_mul(ctx->n, ctx->p, ctx->q);
    mpz_set_ui(ctx->e, exponent);

    ctx->is_private = RSA_PRIVATE;
    ctx->key_size = mpz_sizeinbase(ctx->n, 2);
    // round up key_size to the next multiple of 8
    ctx->key_size += (ctx->key_size % 8);

    ret = rsa_validate_key_components(ctx);
    if (RSA_SUCCESS != ret) {
        goto error_exit; // Error: failed to validate key components
    }
    ret = rsa_compute_private_exponent(ctx);
    if (RSA_SUCCESS != ret) {
        goto error_exit; // Error: failed to compute private exponent
    }

    return RSA_SUCCESS;
error_exit:
    rsa_free(ctx); // Clear context on error
    return ret;
}

rsa_error_t rsa_pubkey_from_private(rsa_ctx_t *pubkey, const rsa_ctx_t *privkey)
{
    if (NULL == pubkey || NULL == privkey ) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid input
    }
    if (RSA_PRIVATE != privkey->is_private || RSA_KEY_NOT_SET != pubkey->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context not initialized before setting the key
    }

    mpz_set(pubkey->n, privkey->n);
    mpz_set(pubkey->e, privkey->e);
    pubkey->is_private = RSA_PUBLIC;
    pubkey->key_size = privkey->key_size;
    return RSA_SUCCESS;
}

const char* rsa_strerror(int err_code) {
    switch (err_code) {
        // Success case
        case RSA_SUCCESS:
            return "Success";

        // Prime number related errors
        case RSA_ERROR_P_NOT_PRIME:
            return "P is not a prime number";
        case RSA_ERROR_Q_NOT_PRIME:
            return "Q is not a prime number";
        case RSA_ERROR_INVALID_PRIME_TOO_SMALL:
            return "Invalid prime number (too small)";
        case RSA_ERROR_MODINV_NOT_EXIST:
            return "Modular inverse does not exist";

        // Key related errors
        case RSA_ERROR_INVALID_KEY:
            return "Invalid key";
        case RSA_ERROR_KEY_SIZE_INVALID:
            return "Key size not valid (must be a power of 2 between 1024 and 32768 inclusive)";
        case RSA_ERROR_KEY_NOT_SET:
            return "RSA key not set";
        case RSA_ERROR_INVALID_MODULUS:
            return "Invalid modulus";
        case RSA_ERROR_INVALID_EXPONENT:
            return "Invalid exponent";

        // Message/signature related errors
        case RSA_ERROR_INVALID_MESSAGE:
            return "Invalid message";
        case RSA_ERROR_INVALID_OUTPUT_SIZE:
            return "Invalid message size";
        case RSA_ERROR_INVALID_INPUT_SIZE:
            return "Invalid input size";
        case RSA_ERROR_INVALID_SIGNATURE:
            return "Invalid signature";
        case RSA_ERROR_INVALID_SIGNATURE_SIZE:
            return "Invalid signature size";

        // Context/argument related errors
        case RSA_ERROR_INVALID_CONTEXT:
            return "Invalid RSA context";
        case RSA_ERROR_INVALID_ARGUMENTS:
            return "Invalid arguments";
        case RSA_ERROR_INVALID_LENGTH:
            return "Invalid length";
        case RSA_ERROR_INVALID_BASE:
            return "Invalid base for conversion (must be raw binary, decimal, hex, or base32)";

        // Format/conversion errors
        case RSA_ERROR_STRING_CONVERSION:
            return "String conversion error";

        // Coprimality errors
        case RSA_ERROR_NOT_COPRIME:
            return "Not coprime to public exponent";

        // Allocation errors
        case RSA_ERROR_ALLOC_FAILED:
            return "Memory allocation failed";

        default:
            return "Unknown error code";
    }
}

rsa_error_t rsa_mpz_gen_random_fast(mpz_t result, mp_bitcnt_t num_bits)
{
    if (NULL == result) {
        return RSA_ERROR_INVALID_ARGUMENTS;
    }
    if (num_bits < 2) {  // Reasonable limits
        return RSA_ERROR_INVALID_LENGTH;
    }
    gmp_randstate_t state;
    gmp_randinit_default(state);
    // Get the CPU clock time in nanoseconds for a better seed. Use the last significant byte
    // to construct the seed by calling clock_gettime four times and using the last byte of each
    long accumulator = 0;
    for(int i = 0; i < sizeof(long); i++) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        accumulator |= (now.tv_nsec & 0x000000ff) << (i * 8);
    }
    gmp_randseed_ui(state, accumulator);
    mpz_urandomb(result, state, num_bits);
    gmp_randclear(state);
    return RSA_SUCCESS;
}

// More secure by reading from /dev/urandom
rsa_error_t rsa_mpz_gen_random_secure(mpz_t result, mp_bitcnt_t num_bits)
{
    if (NULL == result) {
        return RSA_ERROR_INVALID_ARGUMENTS;
    }
    if (num_bits < 2 || (num_bits % 8) != 0) {
        return RSA_ERROR_INVALID_LENGTH;
    }
    size_t num_bytes = num_bits / 8;
    rsa_error_t ret = RSA_SUCCESS;
    // read num_bits from /dev/urandom
    FILE *fp = fopen("/dev/urandom", "rb");
    if (NULL == fp) {
        perror("Failed to open /dev/urandom");
        ret = RSA_ERROR_ALLOC_FAILED; // Error: Failed to open /dev/urandom
        goto exit;
    }
    unsigned char *buffer = (unsigned char*)malloc(num_bytes);
    if (NULL == buffer) {
        perror("Failed to alloc random buffer");
        ret = RSA_ERROR_ALLOC_FAILED; // Error: Memory allocation failed
        goto exit;
    }
    size_t bytes_read = fread(buffer, 1, num_bytes, fp);
    if (bytes_read != num_bytes) {
        printf("Failed to read enough bytes from /dev/urandom: %ld\n", num_bytes);
        ret = RSA_ERROR_ALLOC_FAILED; // Error: Failed to read enough bytes
        goto exit;
    }
    // Convert the buffer to a GMP number
    mpz_import(result, bytes_read, 1, sizeof(char), 1, 0, buffer);
exit:
    if (NULL != buffer) free(buffer);
    if (NULL != fp) fclose(fp);
    return ret;
}

rsa_error_t rsa_genkey(rsa_ctx_t *ctx, unsigned int bitlen, unsigned int pub_exponent)
{
    if (NULL == ctx) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    if (bitlen < RSA_KEYSIZE_MIN || bitlen > RSA_KEYSIZE_MAX || (bitlen & (bitlen - 1)) != 0) {
        return RSA_ERROR_KEY_SIZE_INVALID; // Too small, too big, or not a power of two
    }
    if (RSA_KEY_NOT_SET != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context not initialized before setting the key
    }
    if (0 == pub_exponent) {
        pub_exponent = RSA_DEFAULT_PUBLIC_EXPONENT; // Default to 65537
    }
    if (pub_exponent <= 1 || (pub_exponent % 2) == 0) {
        return RSA_ERROR_INVALID_EXPONENT;
    }

    mpz_set_ui(ctx->e, pub_exponent);
    
    // Generate two primes that have a bitlen of half the key size
    rsa_error_t ret = RSA_SUCCESS;
    do {
        do {
            ret = rsa_genprime(ctx->p, (bitlen / 2), true);
            if (RSA_SUCCESS != ret) {
                return ret; // Error: Failed to generate prime P
            }
            ret = rsa_genprime(ctx->q, (bitlen / 2), true);
            if (RSA_SUCCESS != ret) {
                return ret; // Error: Failed to generate prime Q
            }
            ret = rsa_primes_too_close(ctx->p, ctx->q);
            if (RSA_ERROR_INVALID_ARGUMENTS == ret) {
                return ret; // failing error
            }
        } while(RSA_ERROR_PRIMES_TOO_CLOSE == ret);
        mpz_mul(ctx->n, ctx->p, ctx->q);
        ctx->key_size = mpz_sizeinbase(ctx->n, 2);
    } while(ctx->key_size != bitlen); // Modulus N is correct size (== bitlen)

    ctx->is_private = RSA_PRIVATE;
    if (   (ret = rsa_validate_key_components(ctx))  != RSA_SUCCESS
        || (ret = rsa_compute_private_exponent(ctx)) != RSA_SUCCESS ) {
        ctx->is_private = RSA_KEY_NOT_SET;
    }
    return ret; // Success
}

/// This function computes the private exponent d for RSA given the public exponent e, and the two prime factors p and q.
/// The function uses the Carmichael Totient function, defined as *lambda(p,q) = LCM((p-1), (q-1))*, and then calculates the modular inverse of e modulo lambda.
/// If the modular inverse exists, it sets the value of d and returns RSA_SUCCESS.
/// NOTE: This function assumes that p and q are prime numbers. If they are not, the function will not generate an incorrect result. This function
/// checks that the public exponent e is coprime to lambda as part of the calculation. Call rsa_validate_key_components() to check
/// the validity of the key components before calling this function (it does the primality checks).
rsa_error_t rsa_compute_private_exponent(rsa_ctx_t *ctx) {
    rsa_error_t ret = RSA_SUCCESS;
    if (NULL == ctx) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    mpz_t p_minus_1, q_minus_1, lambda, should_be_one;
    mpz_inits(p_minus_1, q_minus_1, lambda, should_be_one, NULL);

    mpz_sub_ui(p_minus_1, ctx->p, 1);
    mpz_sub_ui(q_minus_1, ctx->q, 1);
    mpz_lcm(lambda, p_minus_1, q_minus_1);
    // Check if e is coprime to lambda. If it is, then compute modular inverse,
    // check if it exists and set as the private exponent d
    mpz_gcd(should_be_one, ctx->e, lambda);
    if (mpz_cmp_ui(should_be_one, 1) != 0) {
        ret = RSA_ERROR_NOT_COPRIME; // Error: e is not coprime to lambda
    } else if (mpz_invert(ctx->d, ctx->e, lambda) == 0) {
        ret = RSA_ERROR_MODINV_NOT_EXIST; // Error: modular inverse doesn't exist
    } 

    mpz_clears(p_minus_1, q_minus_1, lambda, should_be_one, NULL);
    return ret; // Success
}

// This function validates the key components of the RSA algorithm for length, primality, and coprimality.
// Perform basic primality tests (is zero, is one, is even, is mod 3), then the Baillie-PSW primality test
// for the first 24 reps, and then finally Miller-Rabin for the remaining reps (50 here).
// -- If the mpz_probab_prime_p function returns 0, then the number is not prime.
//    If it returns 1, then it is a strong pseudoprime and passes this test. If it is proven
//    to be prime, then the function returns 2.
rsa_error_t rsa_validate_key_components(rsa_ctx_t *ctx) {  
    if (NULL == ctx) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    if (RSA_PRIVATE != ctx->is_private && RSA_PUBLIC != ctx->is_private) {
        if (ctx->is_private == RSA_KEY_NOT_SET) {
            return RSA_ERROR_KEY_NOT_SET; // Error: Key not set
        }
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context is not initialized
    }

    // On the odd chance that the public exponent is not 0x10001 or 3 (the two most common public exponents),
    // check that it is prime
    if (mpz_cmp_ui(ctx->e, RSA_DEFAULT_PUBLIC_EXPONENT) != 0 && mpz_cmp_ui(ctx->e, 3) != 0) {
        if (mpz_cmp_ui(ctx->e, 0) <= 0) {
            return RSA_ERROR_INVALID_EXPONENT; // Error: public exponent is not positive
        }
        if (mpz_probab_prime_p(ctx->e, MILLER_RABIN_ITERATIONS) == 0) {
            return RSA_ERROR_INVALID_EXPONENT; // Error: public exponent is not prime.
        }
    }

    if (mpz_cmp_ui(ctx->n, 0) <= 0) {
        return RSA_ERROR_INVALID_MODULUS; // Error: modulus is not positive
    }
    if (ctx->key_size < RSA_KEYSIZE_MIN || ctx->key_size > RSA_KEYSIZE_MAX || (ctx->key_size & (ctx->key_size - 1)) != 0) {
        return RSA_ERROR_KEY_SIZE_INVALID; // Error: key size is too small, too big, or not a power of two
    }

    if(ctx->is_private == RSA_PRIVATE) {
#if defined(RSA_MORE_CHECKS)
        // I believe that mpz_probab_prime already performs these checks
        if (mpz_cmp_ui(ctx->p, 1) <= 0) {
            return RSA_ERROR_INVALID_PRIME_TOO_SMALL; // Error: prime P is less than or equal to 1
        }
        if (mpz_cmp_ui(ctx->q, 1) <= 0) {
            return RSA_ERROR_INVALID_PRIME_TOO_SMALL; // Error: prime Q is less than or equal to 1
        }
#endif // RSA_MORE_CHECKS
        if (mpz_probab_prime_p(ctx->p, MILLER_RABIN_ITERATIONS) == 0) {
            return RSA_ERROR_P_NOT_PRIME; // Error: prime P is not prime
        }
        if (mpz_probab_prime_p(ctx->q, MILLER_RABIN_ITERATIONS) == 0) {
            return RSA_ERROR_Q_NOT_PRIME; // Error: prime Q is not prime
        }
    }
    return RSA_SUCCESS; // Success
}

/// This function performs the private part of RSA - message signing and decryption.
rsa_error_t rsa_mpz_private(rsa_ctx_t *ctx, mpz_t output, const mpz_t input) {
    if (NULL == ctx || NULL == output || NULL == input) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    if (RSA_PRIVATE != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context is not private key
    }
    if (mpz_sizeinbase(input, 2) > ctx->key_size || mpz_cmp(input, ctx->n) >= 0) {
        return RSA_ERROR_INVALID_INPUT_SIZE; // Error: Input is greater than modulus
    }

#if defined(RSA_NO_BLINDING)
    mpz_powm_sec(output, input, ctx->d, ctx->n);            // output = (input ^ private_exp) mod n
#else
    {   // scope to clear the stack
        mpz_t r, s, blind_input, temp, should_be_one, r_inv, blind_output;
        mpz_inits(r, s, blind_input, temp, should_be_one, r_inv, blind_output, NULL);

        int mod_inv_exists = 0;
        do{
            rsa_mpz_gen_random_secure(r, ctx->key_size);    // random r less than and coprime to the modulus
            mpz_gcd(should_be_one, ctx->n, r);
            mod_inv_exists = mpz_invert(r_inv, r, ctx->n);  // r_inv = modular inverse of r mod n, save for later
        } while (mpz_cmp(r, ctx->n) > 0 ||
                mpz_cmp_ui(should_be_one, 1) != 0 ||
                mod_inv_exists == 0);

        mpz_powm_sec(s, r, ctx->e, ctx->n);                 // s = r ^ e mod n
        mpz_mul(blind_input, input, s);                     // blind_input = (s * input) mod n
        mpz_mod(temp, blind_input, ctx->n);
        mpz_powm_sec(blind_output, temp, ctx->d, ctx->n);   // blind_output = (blind_input ^ private_exp) mod n
        mpz_mul(temp, blind_output, r_inv);                 // output = (blind_output * r_inv) mod n
        mpz_mod(output, temp, ctx->n);
        mpz_clears(r, s, blind_input, blind_output, temp, should_be_one, r_inv, NULL);
    }
#endif // RSA_NO_BLINDING
    if (mpz_sizeinbase(output, 2) > ctx->key_size) {
        return RSA_ERROR_INVALID_OUTPUT_SIZE; // Error: Invalid output size - should be less than modulus
    }

    return RSA_SUCCESS;
}

rsa_error_t rsa_private(rsa_ctx_t *ctx, char *output, size_t olen, const char *input, size_t ilen, rsa_base_t base) {
    rsa_error_t ret = rsa_is_valid_base(base);
    if (RSA_SUCCESS != ret) {
        return ret; // Error: Invalid base
    }
    if (NULL == ctx || NULL == output || NULL == input) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    if (RSA_PRIVATE != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context is not public key or private key
    }

    mpz_t in, out;
    mpz_inits(in, out, NULL);
    if (RSA_BASE_BINARYDATA == base) {
        mpz_import(in, ilen, 1, sizeof(char), 1, 0, input); // Import raw bytes assuming big-endian byte order
    } else {
        if (mpz_set_str(in, input, base) != 0) {
            ret = RSA_ERROR_STRING_CONVERSION; // Error: Invalid input format
            goto exit;
        }
    }
    ret = rsa_mpz_private(ctx, out, in);
    if (RSA_SUCCESS != ret) {
        goto exit; // RSA Private key operation
    }
    if (RSA_BASE_BINARYDATA == base) {
        mpz_export(output, NULL, /*olen,*/ 1, sizeof(char), 1, 0, out); // Export raw bytes assuming big-endian byte order
    } else {
        if (mpz_get_str(output, base, out) != 0) {
            ret = RSA_ERROR_STRING_CONVERSION; // Error: Invalid input format
            goto exit;
        }
    }

exit:
    mpz_clears(in, out, NULL);
    return ret;
}

/// This function performs the public part of RSA - message encryption or signature verification.
rsa_error_t rsa_mpz_public(rsa_ctx_t *ctx, mpz_t output, const mpz_t input) {
    if (NULL == ctx || NULL == output || NULL == input) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    if (RSA_PUBLIC != ctx->is_private && RSA_PRIVATE != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context is not public key or private key
    }
    if (mpz_sizeinbase(input, 2) > ctx->key_size || mpz_cmp(input, ctx->n) >= 0) {
        return RSA_ERROR_INVALID_INPUT_SIZE; // Error: Input is greater than the modulus
    }
    mpz_powm_sec(output, input, ctx->e, ctx->n); // output = (input ^ public_exp) mod n
    if (mpz_sizeinbase(output, 2) > ctx->key_size) {
        return RSA_ERROR_INVALID_OUTPUT_SIZE; // Error: Output is larger than key - something went terribly wrong
    }
    return RSA_SUCCESS;
}

rsa_error_t rsa_public(rsa_ctx_t *ctx, char *output, size_t olen, const char *input, size_t ilen, rsa_base_t base) {
    rsa_error_t ret = rsa_is_valid_base(base);
    if (RSA_SUCCESS != ret) {
        return ret; // Error: Invalid base
    }
    if (NULL == ctx || NULL == output || NULL == input) {
        return RSA_ERROR_INVALID_ARGUMENTS; // Error: Invalid context
    }
    if (RSA_PUBLIC != ctx->is_private && RSA_PRIVATE != ctx->is_private) {
        return RSA_ERROR_INVALID_CONTEXT; // Error: Context is not public key or private key
    }

    mpz_t in, out;
    mpz_inits(in, out, NULL);
    if (RSA_BASE_BINARYDATA == base) {
        mpz_import(in, ilen, 1, sizeof(char), 1, 0, input); // Import raw bytes assuming big-endian byte order
    } else {
        if (mpz_set_str(in, input, base) != 0) {
            ret = RSA_ERROR_STRING_CONVERSION; // Error: Invalid input format
            goto exit;
        }
    }
    ret = rsa_mpz_public(ctx, out, in);
    if (RSA_SUCCESS != ret) {
        goto exit; // Error: Public key operation failed
    }
    if (RSA_BASE_BINARYDATA == base) {
        mpz_export(output, NULL, /*olen,*/ 1, sizeof(char), 1, 0, out); // Export raw bytes assuming big-endian byte order
    } else {
        if (mpz_get_str(output, base, out) != 0) {
            ret = RSA_ERROR_STRING_CONVERSION; // Error: Invalid input format
            goto exit;
        }
    }
exit:
    mpz_clears(in, out, NULL);
    return ret;
}