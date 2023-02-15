#ifndef UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_SM2_H_
#define UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_SM2_H_

#include <memory>
#include <string>

#include "openssl/x509.h"
#include "openssl/x509v3.h"

using UniqueEcKey = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using UniqueEcGroup = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using UniqueEcPoint = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using UniqueEcdsaSig = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_NULL_VALUE_INPUT 0x1000
#define INVALID_INPUT_LENGTH 0x1001
#define ALLOCATION_MEMORY_FAIL 0x1004
#define COMPUTE_SM2_SIGNATURE_FAIL 0x1005
#define INVALID_SM2_SIGNATURE 0x1006
#define VERIFY_SM2_SIGNATURE_FAIL 0x1007

#define SM2_USERID_SIZE 14
#define SM2_SIG_SIZE 64
#define SM2_PUB_KEY_SIZE SM2_SIG_SIZE + 1  // 04|x|y
#define SM2_COOR_SIZE 32

typedef struct sm2_pub_key_s {
  unsigned char key[SM2_PUB_KEY_SIZE];
} sm2_pub_key_t;

typedef struct sm2_signature_s {
  unsigned char r_coordinate[32];
  unsigned char s_coordinate[32];
} sm2_signature_t;

/**************************************************
* Name: sm2_sign_data_test
* Function: compute SM2 signature with a fixed internal
    random number k given in GM/T 0003.5-2012
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    pri_key[in]      SM2 private key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. This function is only used for testing! When a
   signature is created by invoking this function,
   a fixed random number value k is used. The random
   number value is given in GM/T 0003.5-2012.
2. The user id value cannot be NULL. If the specific
   value is unknown, the default user id "1234567812345678"
   can be used.
3. "pub_key" is a octet string of 65 byte length. It
   is a concatenation of 04 || X || Y. X and Y both are
   SM2 public key coordinates of 32-byte length.
4. "pri_key" is a octet string of 32 byte length.
**************************************************/
int sm2_sign_data_test(const unsigned char* message,
                       const int message_len,
                       const unsigned char* id,
                       const int id_len,
                       const unsigned char* pub_key,
                       const unsigned char* pri_key,
                       sm2_signature_t* sm2_sig);

/**************************************************
* Name: sm2_sign_data
* Function: compute SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    pri_key[in]      SM2 private key
    sm2_sig[out]     SM2 signature
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
3. "pri_key" is a octet string of 32 byte length.
**************************************************/
int sm2_sign_data(const unsigned char* message,
                  const int message_len,
                  const unsigned char* id,
                  const int id_len,
                  const unsigned char* pub_key,
                  const unsigned char* pri_key,
                  sm2_signature_t* sm2_sig);

/**************************************************
* Name: sm2_verify_sig
* Function: verify SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                signature passes verification
    any other value:  an error occurs
* Notes:
1. "pub_key" is a octet string of 65 byte length. It
   is a concatenation of 04 || X || Y. X and Y both are
   SM2 public key coordinates of 32-byte length.
**************************************************/
int sm2_verify_sig(const unsigned char* message,
                   const int message_len,
                   const unsigned char* id,
                   const int id_len,
                   const unsigned char* pub_key,
                   sm2_signature_t* sm2_sig,
                   bool use_z);

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

class Sm2Crypto {
 public:
  static TeeErrorCode Sign(const std::string& data,
                           const std::string& id,
                           const std::string& public_key,
                           const std::string& private_key,
                           std::string* signature);
  static TeeErrorCode Verify(const std::string& data,
                             const std::string& id,
                             const std::string& public_key,
                             const std::string& signature);
  static TeeErrorCode VerifyUseZ(const std::string& data,
                                 const std::string& id,
                                 const std::string& public_key,
                                 const std::string& signature);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_VERIFICATION_PLATFORMS_HYPERENCLAVE_SM2_H_
