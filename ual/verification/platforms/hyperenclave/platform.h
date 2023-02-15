#ifndef UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_PLATFORM_H_
#define UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_PLATFORM_H_

#include <memory>
#include <string>

#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/x509v3.h"

using UniqueBnCtx = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using UniqueEvpMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using UniqueOpensslBuf = std::unique_ptr<uint8_t, decltype(&free)>;

using UniqueRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;
using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UniqueBigNum = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;

#ifdef __cplusplus
extern "C" {
#endif

#define PCR_SELECT_MAX 3
#define HASH_COUNT 5
#define SHA1_LENGTH 20
#define SHA256_LENGTH 32
#define SHA512_LENGTH 64
#define SM3_LENGTH 32
#define HASH_LENGTH SM3_LENGTH

#define TPM_ALG_SHA1 0x0004
#define TPM_ALG_SHA256 0x000B
#define TPM_ALG_SM2 0x001B
#define TPM_ALG_SM3_256 0x0012

#define TPM_ATTEST_SIZE 147
#define TPM_GENERATED_VALUE 0xff544347
#define TPM_ST_ATTEST_QUOTE (uint16_t)(0x8018)
#define MAX_PCR_NUM 24

#define DER_CERT_BUF_SIZE 2048
#define PEM_CERT_BUF_SIZE 2048

#define PCR_NUM 12

typedef struct {
  uint16_t size;
  uint8_t buffer[1];
} TPM2B;

// this data structure must be as big as 64 bytes to hold 64byte sgx_report_data
typedef union {
  uint8_t sha1[SHA1_LENGTH];
  uint8_t sm3[SM3_LENGTH];
  uint8_t sha256[SHA256_LENGTH];
  uint8_t sha512[SHA512_LENGTH];
} TPMU_HA;

typedef struct {
  uint16_t hash_alg;
  TPMU_HA digest;
} TPMT_HA;

typedef struct {
  uint64_t clock;
  uint32_t reset_count;
  uint32_t restart_count;
  uint8_t safe;
} TPMS_CLOCK_INFO;

typedef struct {
  uint16_t hash;
  uint8_t size_of_select;
  uint8_t pcr_select[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

typedef struct {
  uint32_t count;
  TPMS_PCR_SELECTION selections[HASH_COUNT];
} TPML_PCR_SELECTION;

typedef struct {
  uint16_t size;
  uint8_t buffer[sizeof(TPMU_HA)];
} DIGEST_2B;

typedef union {
  DIGEST_2B t;
  TPM2B b;
} TPM2B_DIGEST;

typedef struct {
  TPML_PCR_SELECTION pcr_select;
  TPM2B_DIGEST pcr_digest;
} TPMS_QUOTE_INFO;

typedef union {
  TPMT_HA digest;
  uint32_t handle;
} TPMU_NAME;

typedef struct {
  uint16_t size;
  uint8_t name[sizeof(TPMU_NAME)];
} NAME_2B;

typedef struct {
  uint16_t size;
  uint8_t buffer[sizeof(TPMT_HA)];
} DATA_2B;

typedef union {
  NAME_2B t;
  TPM2B b;
} TPM2B_NAME;

typedef union {
  DATA_2B t;
  TPM2B b;
} TPM2B_DATA;

typedef struct {
  uint32_t tpm_generated;
  uint16_t type;
  TPM2B_NAME signer;
  TPM2B_DATA extra_data;
  TPMS_CLOCK_INFO clock;
  uint64_t firmware_version;
  TPMS_QUOTE_INFO quote;
} TPMS_ATTEST;

extern void init_tpms_attest(TPMS_ATTEST* attest);
extern bool decode_tpm_attest_data(uint8_t* data,
                                   uint16_t size,
                                   TPMS_ATTEST* attest);
extern bool verify_pcr_digest(TPMS_ATTEST* attest,
                              uint8_t* hv_att_key_buf,
                              uint32_t buf_len,
                              uint8_t* pcr_array,
                              uint32_t array_size);

extern bool verify_peer_cert(uint8_t* der_cert_ptr, int der_cert_len);

#ifdef __cplusplus
}
#endif

#endif  // UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_PLATFORM_H_
