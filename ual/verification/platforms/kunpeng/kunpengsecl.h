#ifndef UAL_VERIFICATION_PLATFORMS_KUNPENG_KUNPENGSECL_H_
#define UAL_VERIFICATION_PLATFORMS_KUNPENG_KUNPENGSECL_H_

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#define NONCE_SIZE 64
#define NODE_LEN 8

#define KEY_PURPOSE_SIZE 32
#define KEY_TAG_TYPE_MOVE_BITS 28
#define RA_INTEGER (1 << KEY_TAG_TYPE_MOVE_BITS)
#define RA_BYTES (2 << KEY_TAG_TYPE_MOVE_BITS)

enum ra_tags {
  /*Integer Type*/
  RA_TAG_SIGN_TYPE = RA_INTEGER | 0,
  RA_TAG_HASH_TYPE = RA_INTEGER | 1,
  RA_TAG_CURVE_TYPE = RA_INTEGER | 2,
  /*Bytes Type*/
  RA_TAG_QTA_IMG_HASH = RA_BYTES | 0,
  RA_TAG_TA_IMG_HASH = RA_BYTES | 1,
  RA_TAG_QTA_MEM_HASH = RA_BYTES | 2,
  RA_TAG_TA_MEM_HASH = RA_BYTES | 3,
  RA_TAG_RESERVED = RA_BYTES | 4,
  RA_TAG_AK_PUB = RA_BYTES | 5,
  RA_TAG_SIGN_DRK = RA_BYTES | 6,
  RA_TAG_SIGN_AK = RA_BYTES | 7,
  RA_TAG_CERT_DRK = RA_BYTES | 8,
  RA_TAG_CERT_AK = RA_BYTES | 9,
};

struct ra_data_offset {
  uint32_t data_len;
  uint32_t data_offset;
};

struct __attribute__((__packed__)) ra_params {
  uint32_t tags;
  union {
    uint32_t integer;
    struct ra_data_offset blob;
  } data;
};

struct __attribute__((__packed__)) ak_cert {
  uint32_t version;
  uint64_t ts;
  char purpose[KEY_PURPOSE_SIZE];
  uint32_t param_count;
  struct ra_params params[0];
  /* following buffer data:
   * (1)qta_img_hash []
   * (2)qta_mem_hash []
   * (3)reserverd []
   * (4)ak_pub []
   * (5)sign_drk []
   * (6)cert_drk []
   */
};

typedef struct {
  uint32_t timeLow;
  uint16_t timeMid;
  uint16_t timeHiAndVersion;
  uint8_t clockSeqAndNode[NODE_LEN];
} TEE_UUID;

typedef struct {
  uint32_t size;
  uint8_t* buf;
} buffer_data;

// The memory layout of kunpeng report
typedef struct __attribute__((__packed__)) report_response {
  uint32_t version;
  uint64_t ts;
  uint8_t nonce[NONCE_SIZE];
  TEE_UUID uuid;
  uint32_t scenario;
  uint32_t param_count;
  struct ra_params params[0];
  /* following buffer data:
   * (1)ta_img_hash []
   * (2)ta_mem_hash []
   * (3)reserverd []
   * (4)sign_ak []
   * (5)ak_cert []
   */
} kunpeng_report;

bool kunpensecl_verify_signature(buffer_data* report);

#ifdef __cplusplus
}
#endif

#endif  // UAL_VERIFICATION_PLATFORMS_KUNPENG_KUNPENGSECL_H_
