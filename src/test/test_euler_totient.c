#include "unity.h"
#include <gmp.h>
#include <stdio.h> // For sprintf

// Test vectors for Euler's totient function
const int euler_totient_testvec[] = {
    1,1,2,2,4,2,6,4,6,4,10,4,12,6,8,8,16,6,18,8,12,10,22,8,20,12,18,12,28,8,30,16,20,16,24,12
    // Note: The original rsatest.c has this array up to index 35 (for n=36).
    // The size of this array is 36.
};

// Copied from rsatest.c and made static as it's used only in this file.
// Computes Euler's totient function phi(n)
// result is set to phi(n)
// Assumes result and n are initialized.
static void euler_totient(mpz_t result, const mpz_t n) {
    mpz_t i, gcd_val, temp_n;
    mpz_inits(i, gcd_val, temp_n, NULL);

    mpz_set_ui(result, 0); // Initialize result count to 0

    if (mpz_cmp_ui(n, 0) <= 0) { // phi(n) is not defined for n <= 0 in this context
        mpz_clears(i, gcd_val, temp_n, NULL);
        return;
    }
    if (mpz_cmp_ui(n, 1) == 0) { // phi(1) = 1
        mpz_set_ui(result, 1);
        mpz_clears(i, gcd_val, temp_n, NULL);
        return;
    }

    // Iterate from 1 to n-1 for typical definition, or 1 to n for some interpretations.
    // The test vectors imply phi(n) for n from 1.
    // A common way to calculate is to count numbers k from 1 to n where gcd(n,k)=1.
    // Let's use 1 to n inclusive for the loop, and adjust if test vectors imply 1 to n-1.
    // The test vector for n=1 is result=1. This means gcd(1,1)=1 is counted.
    // For n=2, result=1 (only gcd(2,1)=1).
    // For n=3, result=2 (gcd(3,1)=1, gcd(3,2)=1).
    // So, the loop should go from 1 up to n.

    mpz_set(temp_n, n); // Use a copy for the loop limit if n itself is large, or simply use n.

    for (mpz_set_ui(i, 1); mpz_cmp(i, temp_n) <= 0; mpz_add_ui(i, i, 1)) {
        mpz_gcd(gcd_val, i, temp_n);
        if (mpz_cmp_ui(gcd_val, 1) == 0) {
            mpz_add_ui(result, result, 1);
        }
    }

    mpz_clears(i, gcd_val, temp_n, NULL);
}


/*void setUp(void) {
    // Empty
}

void tearDown(void) {
    // Empty
}*/

void test_euler_totient_function_with_vectors(void) {
    mpz_t result_mpz, n_mpz; // Renamed to avoid conflict with parameter n in euler_totient
    mpz_inits(result_mpz, n_mpz, NULL);

    size_t num_test_vectors = sizeof(euler_totient_testvec) / sizeof(euler_totient_testvec[0]);

    for (size_t i = 0; i < num_test_vectors; ++i) {
        mpz_set_ui(n_mpz, i + 1); // Test vectors are for n = 1, 2, 3, ...
        euler_totient(result_mpz, n_mpz); // Call the copied function

        char msg[100];
        sprintf(msg, "Euler totient test failed for n = %zu", i + 1); // Use %zu for size_t

        // mpz_get_ui returns unsigned long. Cast to unsigned int if euler_totient_testvec stores int.
        TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned int)euler_totient_testvec[i], (unsigned int)mpz_get_ui(result_mpz), msg);
    }

    mpz_clears(result_mpz, n_mpz, NULL);
}
