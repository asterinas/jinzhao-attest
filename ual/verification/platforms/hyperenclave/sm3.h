#ifndef UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_SM3_H_
#define UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_SM3_H_

#include <string>

#include "attestation/common/error.h"
#include "attestation/common/type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_NULL_VALUE_INPUT 0x1000
#define CREATE_SM2_KEY_PAIR_FAIL 0x1002
#define COMPUTE_SM3_DIGEST_FAIL 0x1003
#define INVALID_INPUT_LENGTH 0x1001
#define ALLOCATION_MEMORY_FAIL 0x1004

/**************************************************
* Name: sm3_digest_z
* Function: compute digest of leading Z in SM3 preprocess
* Parameters:
    id[in]       user id
    id_len[in]   user id length, size in bytes
    pub_key[in]  SM2 public key
    digest[out]  digest value on Z
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. The user id value cannot be NULL. If the specific
   value is unknown, the default user id "1234567812345678"
   can be used.
2. "pub_key" is a octet string of 65 byte length. It
   is a concatenation of 04 || X || Y. X and Y both are
   SM2 public key coordinates of 32-byte length.
**************************************************/
int sm3_digest_z(const unsigned char* id,
                 const int id_len,
                 const unsigned char* pub_key,
                 unsigned char* z_digest);

/**************************************************
* Name: sm3_digest_with_preprocess
* Function: compute SM3 digest with preprocess
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    digest[out]      digest value of SM3 preprocess
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. The user id value cannot be NULL. If the specific
   value is unknown, the default user id "1234567812345678"
   can be used.
2. "pub_key" is a octet string of 65 byte length. It
   is a concatenation of 04 || X || Y. X and Y both are
   SM2 public key coordinates of 32-byte length.
**************************************************/
int sm3_digest_with_preprocess(const unsigned char* message,
                               const int message_len,
                               const unsigned char* id,
                               const int id_len,
                               const unsigned char* pub_key,
                               unsigned char* digest,
                               bool use_z);

bool global_sm3_init();
bool global_sm3_update(const unsigned char* data, unsigned int len);
unsigned int global_sm3_final(unsigned char* digest);
unsigned int global_sm3_hash(const unsigned char* message,
                             unsigned int message_len,
                             unsigned char* digest);

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

class Sm3Crypto {
 public:
  static TeeErrorCode Hash(const std::string& data, std::string* hash);
  static int GetHashSize();
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_SM3_H_
