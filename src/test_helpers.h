#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <gmp.h>
#include "unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // For strlen and strcat

static inline void custom_assert_mpz_equal(const mpz_t expected, const mpz_t actual, const char* msg, const UNITY_LINE_TYPE lineNumber) {
    if (mpz_cmp(expected, actual) != 0) {
        char* expected_hex = mpz_get_str(NULL, 16, expected);
        char* actual_hex = mpz_get_str(NULL, 16, actual);

        // Calculate the required buffer size
        // Format: "%s\nExpected: 0x%s\nActual:   0x%s"
        // Includes null terminators, "0x" prefixes, newlines, and space for the message itself.
        size_t message_len = strlen(msg) + strlen(expected_hex) + strlen(actual_hex) + strlen("\nExpected: 0x") + strlen("\nActual:   0x") + 1;
        char* detailed_message = (char*)malloc(message_len);

        if (detailed_message == NULL) {
            // Handle allocation failure, though in a test context this is unlikely / indicates bigger problems
            UnityFail("Failed to allocate memory for failure message.", lineNumber);
            free(expected_hex);
            free(actual_hex);
            return;
        }

        sprintf(detailed_message, "%s\nExpected: 0x%s\nActual:   0x%s", msg, expected_hex, actual_hex);

        UnityFail(detailed_message, lineNumber);

        free(expected_hex);
        free(actual_hex);
        free(detailed_message);
    }
}

#define TEST_ASSERT_EQUAL_GMP_MPZ(expected, actual, msg) custom_assert_mpz_equal(expected, actual, msg, __LINE__)

#endif // TEST_HELPERS_H
