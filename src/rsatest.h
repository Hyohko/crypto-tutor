#ifndef RSA_TEST_H
#define RSA_TEST_H
#include "rsa.h"

void rsa_test_privexp_nist();
rsa_error_t rsa_test_random(bool use_nist_keys, int bitlen);
rsa_error_t rsa_test_nist();
void rsa_test_main(void);

#endif