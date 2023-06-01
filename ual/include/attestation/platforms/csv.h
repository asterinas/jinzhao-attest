/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 * Copyright (c) 2022 Ant Group
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INCLUDE_ATTESTATION_PLATFORMS_CSV_H_
#define INCLUDE_ATTESTATION_PLATFORMS_CSV_H_

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  KEY_USAGE_TYPE_HSK = 0x13,
  KEY_USAGE_TYPE_INVALID = 0x1000,
  KEY_USAGE_TYPE_MIN = 0x1001,
  KEY_USAGE_TYPE_PEK = 0x1002,
  KEY_USAGE_TYPE_PDH = 0x1003,
  KEY_USAGE_TYPE_CEK = 0x1004,
  KEY_USAGE_TYPE_MAX = 0x1004,
} key_usage_t;

/* Hygon CSV Certificate */

#define HASH_BLOCK_SIZE 32
#define HYGON_SM2_UID_SIZE 256
#define ECC_POINT_SIZE 72

typedef struct _hash_block {
  uint8_t block[HASH_BLOCK_SIZE];
} __attribute__((packed)) hash_block_t;

typedef struct __attribute__((__packed__)) hygon_sm2_pubkey_in_cert {
  uint32_t curve_id;
  uint8_t qx[ECC_POINT_SIZE];
  uint8_t qy[ECC_POINT_SIZE];
  uint16_t userid_len;
  uint8_t userid[HYGON_SM2_UID_SIZE - sizeof(uint16_t)];
} hygon_pubkey_t;

typedef struct __attribute__((__packed__)) hygon_sm2_signature_in_cert {
  uint8_t r[ECC_POINT_SIZE];
  uint8_t s[ECC_POINT_SIZE];
} hygon_signature_t;

#define HYGON_CHIP_KEY_ID_SIZE 16
typedef struct __attribute__((__packed__)) hygon_root_cert {
  uint32_t version;
  struct {
    uint8_t id[HYGON_CHIP_KEY_ID_SIZE];
  } key_id, certifying_id;
  uint32_t key_usage;
  uint8_t reserved1[24];
  union {
    uint8_t pubkey[4 + ECC_POINT_SIZE * 2 + 256];
    hygon_pubkey_t ecc_pubkey;
  };
  uint8_t reserved2[108];
  union {
    uint8_t signature[ECC_POINT_SIZE * 2];
    hygon_signature_t ecc_sig;
  };
  uint8_t reserved3[112];
} hygon_root_cert_t;

typedef struct __attribute__((__packed__)) hygon_csv_sm2_pubkey_in_cert {
  uint32_t curve_id;
  uint8_t qx[ECC_POINT_SIZE];
  uint8_t qy[ECC_POINT_SIZE];
  uint16_t uid_len;
  uint8_t uid[HYGON_SM2_UID_SIZE - sizeof(uint16_t)];
  uint8_t reserved[624];
} hygon_csv_pubkey_t;

typedef struct __attribute__((__packed__)) hygon_csv_sm2_signature_in_cert {
  uint8_t r[ECC_POINT_SIZE];
  uint8_t s[ECC_POINT_SIZE];
  uint8_t reserved[368];
} hygon_csv_signature_t;

typedef struct __attribute__((__packed__)) csv_cert {
  uint32_t version;
  uint8_t api_major;
  uint8_t api_minor;
  uint8_t reserved1;
  uint8_t reserved2;
  uint32_t pubkey_usage;
  uint32_t pubkey_algo;
  hygon_csv_pubkey_t sm2_pubkey;
  uint32_t sig1_usage;
  uint32_t sig1_algo;
  hygon_csv_signature_t ecc_sig1;
  uint32_t sig2_usage;
  uint32_t sig2_algo;
  hygon_csv_signature_t ecc_sig2;
} csv_cert_t;

#define HYGON_CERT_SIZE 832
#define HYGON_CSV_CERT_SIZE 2084
#define HYGON_HSK_CEK_CERT_SIZE (HYGON_CERT_SIZE + HYGON_CSV_CERT_SIZE)

typedef struct __attribute__((aligned(1))) hsk_cek_t {
  hygon_root_cert_t hsk;
  csv_cert_t cek;
} csv_hsk_cek;

/* CSV attestation report */
#define CSV_VM_ID_SIZE 16
#define CSV_VM_VERSION_SIZE 16
#define CSV_ATTESTATION_USER_DATA_SIZE 64
#define CSV_ATTESTATION_MNONCE_SIZE 16
#define CSV_ATTESTATION_CHIP_SN_SIZE 64

// use user_data to save 32bytes user data and 32byte pubkey hash
#define CSV_USED_USER_DATA_SIZE 32

typedef struct __attribute__((__packed__)) csv_attestation_report_t {
  hash_block_t user_pubkey_digest;
  uint8_t vm_id[CSV_VM_ID_SIZE];
  uint8_t vm_version[CSV_VM_VERSION_SIZE];
  uint8_t user_data[CSV_ATTESTATION_USER_DATA_SIZE];
  uint8_t mnonce[CSV_ATTESTATION_MNONCE_SIZE];
  hash_block_t measure;
  uint32_t policy;
  uint32_t sig_usage;
  uint32_t sig_algo;
  uint32_t anonce;
  union {
    uint8_t sig1[72 * 2];
    struct {
      uint8_t r[72];
      uint8_t s[72];
    } ecc_sig1;
  };
  uint8_t pek_cert[HYGON_CSV_CERT_SIZE];
  uint8_t chip_id[CSV_ATTESTATION_CHIP_SN_SIZE];
  uint8_t reserved1[32];
  hash_block_t hmac;
  uint8_t reserved2[1548];  // Padding to a page size
} csv_attestation_report;

#include <stddef.h>
#define CSV_ATTESTATION_REPORT_SIGN_DATA_OFFSET \
  offsetof(csv_attestation_report, user_pubkey_digest)
#define CSV_ATTESTATION_REPORT_SIGN_DATA_SIZE    \
  (offsetof(csv_attestation_report, sig_usage) - \
   offsetof(csv_attestation_report, user_pubkey_digest))
#define CSV_ATTESTATION_REPORT_HMAC_DATA_OFFSET \
  offsetof(csv_attestation_report, pek_cert)
#define CSV_ATTESTATION_REPORT_HMAC_DATA_SIZE \
  (offsetof(csv_attestation_report, hmac) -   \
   offsetof(csv_attestation_report, pek_cert))

#ifdef __cplusplus
}
#endif

#endif  // INCLUDE_ATTESTATION_PLATFORMS_CSV_H_
