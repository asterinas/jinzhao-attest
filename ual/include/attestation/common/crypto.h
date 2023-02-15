#ifndef UAL_INCLUDE_ATTESTATION_COMMON_CRYPTO_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_CRYPTO_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "openssl/ec.h"
#include "openssl/evp.h"

// Typedefs for memory management
// Specify type and destroy function type for unique_ptrs
typedef std::unique_ptr<BIO, void (*)(BIO*)> BIO_ptr;
typedef std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> BIGNUM_ptr;
typedef std::unique_ptr<RSA, void (*)(RSA*)> RSA_ptr;
typedef std::unique_ptr<EC_KEY, void (*)(EC_KEY*)> EC_KEY_ptr;
typedef std::unique_ptr<EC_GROUP, void (*)(EC_GROUP*)> EC_GROUP_ptr;
typedef std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> EVP_PKEY_ptr;
typedef std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> EVP_PKEY_CTX_ptr;
typedef std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)>
    EVP_CIPHER_CTX_ptr;
typedef std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> EVP_MD_CTX_ptr;

// evp success return value
const int evp_success = 1;

#ifdef SM_MODE
const bool smMode = true;
#else
const bool smMode = false;
#endif

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_CRYPTO_H_
