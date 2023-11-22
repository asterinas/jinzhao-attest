#ifndef UAL_INCLUDE_ATTESTATION_COMMON_ERROR_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_ERROR_H_

// clang-format off

// For Openssl error code
typedef enum {
  OPENSSL_ERROR = 0,
  OPENSSL_SUCCESS = 1,
} OpensslErrorCode;

// TeeErrorCode is to include both the error code from Intel SDK and
// self-defined error code.
typedef int TeeErrorCode;

#define TEE_MK_ERROR(x)                                (0xFFFF0000&((x) << 16))
#define SGX_MK_ERROR(x)                                        (0x00000000|(x))

// TEE_SUCCESS is 0 for both Intel SDK errorcde and self-defined error code.
#define TEE_SUCCESS                                        SGX_MK_ERROR(0x0000)

//=============================================================================
// bit 0  ~ bit 15: Intel SDK error code.
//=============================================================================
// https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_error.h
// Here, only list the error codes which are used.
#define TEE_ERROR_SGX_ERROR_BUSY                           SGX_MK_ERROR(0x400a)

//=============================================================================
// bit 16 ~ bit 31: Include the following self-defined error codes
//=============================================================================
// 0000 ~ 0FFF: Common/Utils
// 1000 ~ 1FFF: UnifiedAttestation
// 2000 ~ 7FFF: Reserved for other frameworks
// 8000 ~ FFFF: Reserved for other applications
//
// Common::Generic
#define TEE_ERROR_GENERIC                                  TEE_MK_ERROR(0x0001)
#define TEE_ERROR_PARAMETERS                               TEE_MK_ERROR(0x0002)
#define TEE_ERROR_MALLOC                                   TEE_MK_ERROR(0x0003)
#define TEE_ERROR_COMMANDLINE                              TEE_MK_ERROR(0x0004)
#define TEE_ERROR_SMALL_BUFFER                             TEE_MK_ERROR(0x0005)
#define TEE_ERROR_NOT_IMPLEMENTED                          TEE_MK_ERROR(0x0006)
#define TEE_ERROR_CATCH_EXCEPTION                          TEE_MK_ERROR(0x0007)

// Common::Enclave
#define TEE_ERROR_ENCLAVE                                  TEE_MK_ERROR(0x0E00)
#define TEE_ERROR_CREATE_ENCLAVE                           TEE_MK_ERROR(0x0E01)
#define TEE_ERROR_ENCLAVE_NOTINITIALIZED                   TEE_MK_ERROR(0x0E02)
#define TEE_ERROR_UNSUPPORTED_TEE                          TEE_MK_ERROR(0x0E03)
#define TEE_ERROR_INVALID_ECALL_BUFFER                     TEE_MK_ERROR(0x0E04)
#define TEE_ERROR_DESTROY_ENCLAVE_FAILED                   TEE_MK_ERROR(0x0E05)
#define TEE_ERROR_DESTROY_EMPTY_ENCLAVE                    TEE_MK_ERROR(0x0E06)
#define TEE_ERROR_INVALID_ENCLAVE_ID                       TEE_MK_ERROR(0x0E07)
#define TEE_ERROR_SEAL_DATA                                TEE_MK_ERROR(0x0E08)
#define TEE_ERROR_UNSEAL_DATA                              TEE_MK_ERROR(0x0E09)
#define TEE_ERROR_SEAL_DATA_BUFFER_SIZE                    TEE_MK_ERROR(0x0E0A)
#define TEE_ERROR_UNSEAL_DATA_BUFFER_SIZE                  TEE_MK_ERROR(0x0E0B)

// Common::Crypto::Base64
#define TEE_ERROR_CRYPTO_BASE64                            TEE_MK_ERROR(0x0110)
// Common::Crypto::Rand
#define TEE_ERROR_CRYPTO_RAND                              TEE_MK_ERROR(0x0120)
// Common::Crypto::SHA
#define TEE_ERROR_CRYPTO_SHA                               TEE_MK_ERROR(0x0130)
#define TEE_ERROR_CRYPTO_SHA_EVP_CTX                       TEE_MK_ERROR(0x0131)
#define TEE_ERROR_CRYPTO_SHA_INIT                          TEE_MK_ERROR(0x0132)
#define TEE_ERROR_CRYPTO_SHA_UPDATE                        TEE_MK_ERROR(0x0133)
#define TEE_ERROR_CRYPTO_SHA_FINAL                         TEE_MK_ERROR(0x0134)
#define TEE_ERROR_CRYPTO_SHA256                            TEE_MK_ERROR(0x0135)

// Common::Crypto::AES
#define TEE_ERROR_CRYPTO_AES                               TEE_MK_ERROR(0x0160)
#define TEE_ERROR_CRYPTO_AES_OUT_OF_MEMORY                 TEE_MK_ERROR(0x0161)
#define TEE_ERROR_CRYPTO_AES_KEY_INVALID                   TEE_MK_ERROR(0x0162)
#define TEE_ERROR_CRYPTO_AES_KEY_GENERATE                  TEE_MK_ERROR(0x0163)
#define TEE_ERROR_CRYPTO_AES_IV_GENERATE                   TEE_MK_ERROR(0x0164)
#define TEE_ERROR_CRYPTO_AES_ENCRYPT                       TEE_MK_ERROR(0x0165)
#define TEE_ERROR_CRYPTO_AES_DECRYPT                       TEE_MK_ERROR(0x0166)
#define TEE_ERROR_CRYPTO_AES_EMPTY_PLAIN                   TEE_MK_ERROR(0x0167)
#define TEE_ERROR_CRYPTO_AES_EMPTY_CIPHER                  TEE_MK_ERROR(0x0168)
#define TEE_ERROR_CRYPTO_AES_INVALID_IV                    TEE_MK_ERROR(0x0169)
#define TEE_ERROR_CRYPTO_AES_INVALID_MAC                   TEE_MK_ERROR(0x016A)

// Common::Crypto::RSA
#define TEE_ERROR_CRYPTO_RSA                               TEE_MK_ERROR(0x0170)
#define TEE_ERROR_CRYPTO_RSA_GET_KEY_FROM_RSA              TEE_MK_ERROR(0x0171)
#define TEE_ERROR_CRYPTO_RSA_GET_RSA_FROM_KEY              TEE_MK_ERROR(0x0172)
#define TEE_ERROR_CRYPTO_RSA_GENERATE_KEYPAIR              TEE_MK_ERROR(0x0173)
#define TEE_ERROR_CRYPTO_RSA_KEY_SIZE                      TEE_MK_ERROR(0x0174)
#define TEE_ERROR_CRYPTO_RSA_SIGN                          TEE_MK_ERROR(0x0176)
#define TEE_ERROR_CRYPTO_RSA_VERIFY                        TEE_MK_ERROR(0x0177)
#define TEE_ERROR_CRYPTO_RSA_ENCRYPT                       TEE_MK_ERROR(0x0178)
#define TEE_ERROR_CRYPTO_RSA_DECRYPT                       TEE_MK_ERROR(0x0179)
#define TEE_ERROR_CRYPTO_RSA_PARAMETER                     TEE_MK_ERROR(0x017F)

// Common::Crypto::SYMMETRIC
#define TEE_ERROR_CRYPTO_SYMMETRIC                         TEE_MK_ERROR(0x0180)
#define TEE_ERROR_CRYPTO_SYMMETRIC_MAC                     TEE_MK_ERROR(0x0181)

// Common::Crypto::SM2
#define TEE_ERROR_CRYPTO_SM2                               TEE_MK_ERROR(0x01A0)
#define TEE_ERROR_CRYPTO_SM2_ENCRYPT                       TEE_MK_ERROR(0x01A1)
#define TEE_ERROR_CRYPTO_SM2_DECRYPT                       TEE_MK_ERROR(0x01A2)
#define TEE_ERROR_CRYPTO_SM2_SIGN                          TEE_MK_ERROR(0x01A3)
#define TEE_ERROR_CRYPTO_SM2_VERIFY                        TEE_MK_ERROR(0x01A4)
#define TEE_ERROR_CRYPTO_SM2_KEY                           TEE_MK_ERROR(0x01A5)
#define TEE_ERROR_CRYPTO_SM2_PARAM_INIT                    TEE_MK_ERROR(0x01A6)

// Common::Crypto::SM3
#define TEE_ERROR_CRYPTO_SM3                               TEE_MK_ERROR(0x01B0)
#define TEE_ERROR_CRYPTO_SM3_EVP_CTX                       TEE_MK_ERROR(0x01B1)
#define TEE_ERROR_CRYPTO_SM3_INIT                          TEE_MK_ERROR(0x01B2)
#define TEE_ERROR_CRYPTO_SM3_UPDATE                        TEE_MK_ERROR(0x01B3)
#define TEE_ERROR_CRYPTO_SM3_FINAL                         TEE_MK_ERROR(0x01B4)
#define TEE_ERROR_CRYPTO_SM3_SIZE                          TEE_MK_ERROR(0x01B5)

// Common::Crypto::SM4
#define TEE_ERROR_CRYPTO_SM4                               TEE_MK_ERROR(0x01C0)
#define TEE_ERROR_CRYPTO_SM4_EVP_CIPHER                    TEE_MK_ERROR(0x01C1)
#define TEE_ERROR_CRYPTO_SM4_EVP_CIPHER_CTX                TEE_MK_ERROR(0x01C2)
#define TEE_ERROR_CRYPTO_SM4_CRYPT_INIT                    TEE_MK_ERROR(0x01C3)
#define TEE_ERROR_CRYPTO_SM4_CRYPT_UPDATE                  TEE_MK_ERROR(0x01C4)
#define TEE_ERROR_CRYPTO_SM4_CRYPT_FINAL                   TEE_MK_ERROR(0x01C5)
#define TEE_ERROR_CRYPTO_SM4_CHECK_KEY                     TEE_MK_ERROR(0x01C6)
#define TEE_ERROR_CRYPTO_SM4_CHECK_IV                      TEE_MK_ERROR(0x01C7)

// Common::Crypto::X509Certificate
#define TEE_ERROR_CRYPTO_CERT                              TEE_MK_ERROR(0x01D0)
#define TEE_ERROR_CRYPTO_CERT_CREATE                       TEE_MK_ERROR(0x01D1)
#define TEE_ERROR_CRYPTO_CERT_VERIFY                       TEE_MK_ERROR(0x01D2)
#define TEE_ERROR_CRYPTO_CERT_LOAD                         TEE_MK_ERROR(0x01D3)
#define TEE_ERROR_CRYPTO_CERT_CTX_INIT                     TEE_MK_ERROR(0x01D4)

// Common::Crypto::Envelope
#define TEE_ERROR_CRYPTO_ENVELOPE                          TEE_MK_ERROR(0x01E0)
#define TEE_ERROR_CRYPTO_ENVELOPE_ENCRYPT_PUBKEY           TEE_MK_ERROR(0x01E1)
#define TEE_ERROR_CRYPTO_ENVELOPE_ENCRYPT_PLAIN            TEE_MK_ERROR(0x01E2)
#define TEE_ERROR_CRYPTO_ENVELOPE_DECRYPT_PRIKEY           TEE_MK_ERROR(0x01E3)
#define TEE_ERROR_CRYPTO_ENVELOPE_SIGN                     TEE_MK_ERROR(0x01E4)
#define TEE_ERROR_CRYPTO_ENVELOPE_VERIFY_PARAM             TEE_MK_ERROR(0x01E5)
#define TEE_ERROR_CRYPTO_ENVELOPE_VERIFY_HASH              TEE_MK_ERROR(0x01E6)

// Common::Protobuf
#define TEE_ERROR_PROTOBUF                                 TEE_MK_ERROR(0x0200)
#define TEE_ERROR_PROTOBUF_IFSTREAM                        TEE_MK_ERROR(0x0201)
#define TEE_ERROR_PROTOBUF_OFSTREAM                        TEE_MK_ERROR(0x0202)
#define TEE_ERROR_PROTOBUF_SERIALIZE                       TEE_MK_ERROR(0x0203)
#define TEE_ERROR_PROTOBUF_PARSE                           TEE_MK_ERROR(0x0204)
#define TEE_ERROR_PROTOBUF_SERIALIZE_JSON                  TEE_MK_ERROR(0x0205)
#define TEE_ERROR_PROTOBUF_PARSE_JSON                      TEE_MK_ERROR(0x0206)

// Common::Bytes
#define TEE_ERROR_BYTES                                    TEE_MK_ERROR(0x0300)
#define TEE_ERROR_BYTES_UNEXPECTED_EMPTY                   TEE_MK_ERROR(0x0301)
#define TEE_ERROR_BYTES_BASE64_DECODE                      TEE_MK_ERROR(0x0302)
#define TEE_ERROR_BYTES_BASE64_ENCODE                      TEE_MK_ERROR(0x0303)
#define TEE_ERROR_BYTES_SHA256                             TEE_MK_ERROR(0x0304)
#define TEE_ERROR_BYTES_RAND                               TEE_MK_ERROR(0x0305)
#define TEE_ERROR_BYTES_EXPORT_SMALL_BUFFER                TEE_MK_ERROR(0x0306)

// Utils::FileSystem
#define TEE_ERROR_FILE                                     TEE_MK_ERROR(0x0600)
#define TEE_ERROR_FILE_OPEN                                TEE_MK_ERROR(0x0601)
#define TEE_ERROR_FILE_READ                                TEE_MK_ERROR(0x0602)
#define TEE_ERROR_FILE_WRITE                               TEE_MK_ERROR(0x0603)
#define TEE_ERROR_FILE_EXIST                               TEE_MK_ERROR(0x0604)

// Utils::Configuration
#define TEE_ERROR_CONF                                     TEE_MK_ERROR(0x0800)
#define TEE_ERROR_CONF_LOAD                                TEE_MK_ERROR(0x0801)
#define TEE_ERROR_CONF_NOTEXIST                            TEE_MK_ERROR(0x0802)
#define TEE_ERROR_PARSE_CONFIGURATIONS                     TEE_MK_ERROR(0x0006)

// UnifiedAttestation::Generation
#define TEE_ERROR_RA_GENERATE                              TEE_MK_ERROR(0x1000)
#define TEE_ERROR_RA_NOTINITIALIZED                        TEE_MK_ERROR(0x1001)
#define TEE_ERROR_RA_REPORT_DATA_SIZE                      TEE_MK_ERROR(0x1002)
#define TEE_ERROR_RA_TOO_MUCH_REPORT_DATA                  TEE_MK_ERROR(0x1004)
#define TEE_ERROR_RA_IDENTITY_NOTINITIALIZED               TEE_MK_ERROR(0x1005)
#define TEE_ERROR_RA_MISMATCH_TARGET_MRENCLAVE             TEE_MK_ERROR(0x1006)
#define TEE_ERROR_RA_CREATE_ENCLAVE_REPORT                 TEE_MK_ERROR(0x1007)
#define TEE_ERROR_RA_VERIFY_QUOTE_ENCLAVE                  TEE_MK_ERROR(0x1008)
#define TEE_ERROR_RA_SET_ENCLAVE_LOAD_POLICY               TEE_MK_ERROR(0x1009)
#define TEE_ERROR_RA_SET_QL_PATH                           TEE_MK_ERROR(0x100A)
#define TEE_ERROR_RA_GET_TARGET_INFO                       TEE_MK_ERROR(0x100B)
#define TEE_ERROR_RA_GET_QUOTE_SIZE                        TEE_MK_ERROR(0x100C)
#define TEE_ERROR_RA_GET_QUOTE                             TEE_MK_ERROR(0x100D)
#define TEE_ERROR_RA_MALLOC_QUOTE_BUFFER                   TEE_MK_ERROR(0x100E)
#define TEE_ERROR_RA_SMALLER_REPORT_BUFFER                 TEE_MK_ERROR(0x100F)
#define TEE_ERROR_RA_GET_PUBLIC_KEY                        TEE_MK_ERROR(0x1010)
#define TEE_ERROR_RA_REPORT_TYPE                           TEE_MK_ERROR(0x1011)
#define TEE_ERROR_RA_INVALID_SPID                          TEE_MK_ERROR(0x1012)
#define TEE_ERROR_RA_SMALLER_REPORT_DATA_BUFFER            TEE_MK_ERROR(0x1013)
#define TEE_ERROR_RA_HAVE_BOTH_NONCE_AND_USER_DATA         TEE_MK_ERROR(0x1014)
#define TEE_ERROR_RA_TOO_LONG_NONCE                        TEE_MK_ERROR(0x1015)
#define TEE_ERROR_RA_TOO_LONG_USER_DATA                    TEE_MK_ERROR(0x1016)

// UnifiedAttestation::Generation::Occlum
#define TEE_ERROR_RA_GENERATE_OCCLUM                       TEE_MK_ERROR(0x1040)
#define TEE_ERROR_RA_GENERATE_OCCLUM_FILE_OPEN             TEE_MK_ERROR(0x1041)
#define TEE_ERROR_RA_GENERATE_OCCLUM_GET_GROUP_ID          TEE_MK_ERROR(0x1042)
#define TEE_ERROR_RA_GENERATE_OCCLUM_QUOTE_ARGS            TEE_MK_ERROR(0x1043)
#define TEE_ERROR_RA_GENERATE_OCCLUM_GET_QUOTE             TEE_MK_ERROR(0x1044)
#define TEE_ERROR_RA_GENERATE_OCCLUM_QUOTE_LEN             TEE_MK_ERROR(0x1045)
#define TEE_ERROR_RA_GENERATE_OCCLUM_DEVICE_BUSY           TEE_MK_ERROR(0x1046)
#define TEE_ERROR_RA_GENERATE_OCCLUM_GET_SEAL_KEY          TEE_MK_ERROR(0x1047)

#define TEE_ERROR_RA_GENERATE_CSV                          TEE_MK_ERROR(0x1050)
#define TEE_ERROR_RA_GENERATE_CSV_REPORT_STRUCT            TEE_MK_ERROR(0x1051)
#define TEE_ERROR_RA_GENERATE_CSV_MMAP                     TEE_MK_ERROR(0x1052)
#define TEE_ERROR_RA_GENERATE_CSV_VMCALL                   TEE_MK_ERROR(0x1053)

// UnifiedAttestation::TeeInstance
#define TEE_ERROR_RA_ENCLAVE                               TEE_MK_ERROR(0x1060)
#define TEE_ERROR_RA_UAK_SET_KEYPAIR                       TEE_MK_ERROR(0x1061)
#define TEE_ERROR_RA_UAK_EMPTY                             TEE_MK_ERROR(0x1062)
#define TEE_ERROR_RA_UAK_SMALLER_BUFFER                    TEE_MK_ERROR(0x1063)
#define TEE_ERROR_RA_TRUSTED_REPORT_NOT_EXIST              TEE_MK_ERROR(0x1064)
#define TEE_ERROR_RA_DONOT_DELETE_DEFUALT_REPORT           TEE_MK_ERROR(0x1065)
#define TEE_ERROR_RA_MAX_UAREPORT_CACHE_INSTANCE           TEE_MK_ERROR(0x1066)
#define TEE_ERROR_RA_EMPTY_REPORT_IDENTITY                 TEE_MK_ERROR(0x1067)
#define TEE_ERROR_RA_UA_ENCLAVE_NOT_INITIALIZED            TEE_MK_ERROR(0x1068)

// UnifiedAttestation::Network::CURL-HTTP-CLIENT
#define TEE_ERROR_CURL                                     TEE_MK_ERROR(0x1080)
#define TEE_ERROR_CURL_NETWORK_ERROR                       TEE_MK_ERROR(0x1081)
#define TEE_ERROR_CURL_NO_CACHE_DATA                       TEE_MK_ERROR(0x1082)
#define TEE_ERROR_CURL_PLATFORM_UNKNOWN                    TEE_MK_ERROR(0x1083)
#define TEE_ERROR_CURL_CERTS_UNAVAILABLE                   TEE_MK_ERROR(0x1084)
#define TEE_ERROR_CURL_RES_HEADER_PARSE                    TEE_MK_ERROR(0x1085)
#define TEE_ERROR_CURL_RES_BODYMSG_PARSE                   TEE_MK_ERROR(0x1086)
#define TEE_ERROR_CURL_RES_UNESCAPE_EMPTY                  TEE_MK_ERROR(0x1087)
#define TEE_ERROR_CURL_RES_UNESCAPE_FAIL                   TEE_MK_ERROR(0x1088)
#define TEE_ERROR_CURL_GET_REQUEST                         TEE_MK_ERROR(0x1089)
#define TEE_ERROR_CURL_INIT                                TEE_MK_ERROR(0x108A)
#define TEE_ERROR_CURL_UNEXPECTED                          TEE_MK_ERROR(0x108F)

// UnifiedAttestation::EPID::IAS
#define TEE_ERROR_IAS                                      TEE_MK_ERROR(0x1090)
#define TEE_ERROR_IAS_CLIENT_INIT                          TEE_MK_ERROR(0x1091)
#define TEE_ERROR_IAS_CLIENT_CONNECT                       TEE_MK_ERROR(0x1092)
#define TEE_ERROR_IAS_CLIENT_GETSIGRL                      TEE_MK_ERROR(0x1093)
#define TEE_ERROR_IAS_CLIENT_GETREPORT                     TEE_MK_ERROR(0x1094)
#define TEE_ERROR_IAS_CLIENT_UNESCAPE                      TEE_MK_ERROR(0x1095)
#define TEE_ERROR_IAS_LOAD_CACHED_REPORT                   TEE_MK_ERROR(0x1096)

// UnifiedAttestation::DCAP::PCCS
#define TEE_ERROR_DCAP_PCCS                                TEE_MK_ERROR(0x10A0)
#define TEE_ERROR_DCAP_PCCS_NETWORK_ERROR                  TEE_MK_ERROR(0x10A1)
#define TEE_ERROR_DCAP_PCCS_NO_CACHE_DATA                  TEE_MK_ERROR(0x10A2)
#define TEE_ERROR_DCAP_PCCS_PLATFORM_UNKNOWN               TEE_MK_ERROR(0x10A3)
#define TEE_ERROR_DCAP_PCCS_CERTS_UNAVAILABLE              TEE_MK_ERROR(0x10A4)
#define TEE_ERROR_DCAP_PCCS_RES_HEADER_PARSE               TEE_MK_ERROR(0x10A5)
#define TEE_ERROR_DCAP_PCCS_RES_BODYMSG_PARSE              TEE_MK_ERROR(0x10A6)
#define TEE_ERROR_DCAP_PCCS_RES_UNESCAPE                   TEE_MK_ERROR(0x10A7)
#define TEE_ERROR_DCAP_PCCS_UNKNOWN_API_VERSION            TEE_MK_ERROR(0x10A8)
#define TEE_ERROR_DCAP_PCCS_GET_REQUEST                    TEE_MK_ERROR(0x10A9)
#define TEE_ERROR_DCAP_PCCS_URL                            TEE_MK_ERROR(0x10AA)
#define TEE_ERROR_DCAP_PCCS_UNEXPECTED                     TEE_MK_ERROR(0x10AF)

#define TEE_ERROR_HYGON_KDS                                TEE_MK_ERROR(0x10B0)
#define TEE_ERROR_HYGON_KDS_INVALID_CERT_SIZE              TEE_MK_ERROR(0x10B1)
#define TEE_ERROR_HYGON_KDS_INVALID_HSK_SIZE               TEE_MK_ERROR(0x10B2)
#define TEE_ERROR_HYGON_KDS_INVALID_CEK_SIZE               TEE_MK_ERROR(0x10B3)

// UnifiedAttestation::Verification
#define TEE_ERROR_RA_VERIFY                                TEE_MK_ERROR(0x1110)
#define TEE_ERROR_RA_VERIFY_INVALID_IAS_REPORT             TEE_MK_ERROR(0x1111)
#define TEE_ERROR_RA_VERIFY_LOAD_IAS_ROOT_CERT             TEE_MK_ERROR(0x1112)
#define TEE_ERROR_RA_VERIFY_GET_PUBKEY                     TEE_MK_ERROR(0x1113)
#define TEE_ERROR_RA_VERIFY_GET_RSAKEY                     TEE_MK_ERROR(0x1114)
#define TEE_ERROR_RA_VERIFY_SIGNATURE                      TEE_MK_ERROR(0x1115)
#define TEE_ERROR_RA_VERIFY_SIGNING_TYPE                   TEE_MK_ERROR(0x1117)
#define TEE_ERROR_RA_VERIFY_ATTR                           TEE_MK_ERROR(0x1118)
#define TEE_ERROR_RA_VERIFY_ATTR_PUBKEY                    TEE_MK_ERROR(0x1119)
#define TEE_ERROR_RA_VERIFY_ATTR_TA_MEASUREMENT            TEE_MK_ERROR(0x111A)
#define TEE_ERROR_RA_VERIFY_ATTR_SIGNER                    TEE_MK_ERROR(0x111B)
#define TEE_ERROR_RA_VERIFY_ATTR_USER_DATA                 TEE_MK_ERROR(0x111C)
#define TEE_ERROR_RA_VERIFY_ATTR_ISV_PORDID                TEE_MK_ERROR(0x111D)
#define TEE_ERROR_RA_VERIFY_ATTR_ISV_SVN                   TEE_MK_ERROR(0x111E)
#define TEE_ERROR_RA_VERIFY_ATTR_TEE_PLATFORM              TEE_MK_ERROR(0x111F)
#define TEE_ERROR_RA_VERIFY_ATTR_SPID_NAME                 TEE_MK_ERROR(0x1120)
#define TEE_ERROR_RA_VERIFY_ATTR_DEBUG_DISABLED            TEE_MK_ERROR(0x1121)
#define TEE_ERROR_RA_VERIFY_ATTR_PLATFORM                  TEE_MK_ERROR(0x1122)
#define TEE_ERROR_RA_VERIFY_ATTR_NONCE                     TEE_MK_ERROR(0x1123)
#define TEE_ERROR_RA_VERIFY_ATTR_PLATFORM_MEASUREMENT      TEE_MK_ERROR(0x1124)
#define TEE_ERROR_RA_VERIFY_ATTR_BOOT_MEASUREMENT          TEE_MK_ERROR(0x1125)
#define TEE_ERROR_RA_VERIFY_ATTR_DYN_TA_MEASUREMENT        TEE_MK_ERROR(0x1126)
#define TEE_ERROR_RA_VERIFY_ATTR_PLATFORM_HW_VERSION       TEE_MK_ERROR(0x1127)
#define TEE_ERROR_RA_VERIFY_ATTR_PLATFORM_SW_VERSION       TEE_MK_ERROR(0x1128)
#define TEE_ERROR_RA_VERIFY_ATTR_SECURE_FLAGS              TEE_MK_ERROR(0x1129)
#define TEE_ERROR_RA_VERIFY_ATTR_TEE_NAME                  TEE_MK_ERROR(0x112A)
#define TEE_ERROR_RA_VERIFY_ATTR_TEE_IDENTITY              TEE_MK_ERROR(0x112B)
#define TEE_ERROR_RA_VERIFY_ATTR_VERIFIED_TIME             TEE_MK_ERROR(0x112C)

#define TEE_ERROR_RA_VERIFY_USER_DATA_SIZE                 TEE_MK_ERROR(0x1141)
#define TEE_ERROR_RA_VERIFY_PUBKEY_HASH_SIZE               TEE_MK_ERROR(0x1142)
#define TEE_ERROR_RA_VERIFY_SIG_INIT                       TEE_MK_ERROR(0x1143)
#define TEE_ERROR_RA_VERIFY_EMPTY_QUOTE_STATUS             TEE_MK_ERROR(0x1144)
#define TEE_ERROR_RA_VERIFY_ERROR_QUOTE_STATUS             TEE_MK_ERROR(0x1145)
#define TEE_ERROR_RA_VERIFY_NEED_RERERENCE_DATA            TEE_MK_ERROR(0x1146)
#define TEE_ERROR_RA_VERIFY_UNSUPPORT_REPORT_TYPE          TEE_MK_ERROR(0x1147)
#define TEE_ERROR_RA_VERIFY_UAS_QUOTE_BODY_EMPTY           TEE_MK_ERROR(0x1148)
#define TEE_ERROR_RA_VERIFY_UAS_RESULT_EMPTY               TEE_MK_ERROR(0x1149)
#define TEE_ERROR_RA_VERIFY_UAS_RESULT_CODE                TEE_MK_ERROR(0x114A)
#define TEE_ERROR_RA_VERIFY_UNEXPECTED_DEBUG_MODE          TEE_MK_ERROR(0x114B)
#define TEE_ERROR_RA_VERIFY_RULE_ENTRY_EMPTY               TEE_MK_ERROR(0x114C)
#define TEE_ERROR_RA_VERIFY_SMALLER_INFO_BUFFER            TEE_MK_ERROR(0x114D)
#define TEE_ERROR_RA_VERIFY_NOT_INITIALIZED                TEE_MK_ERROR(0x114E)
#define TEE_ERROR_RA_VERIFY_POLICY_MAIN_ATTR_SIZE          TEE_MK_ERROR(0x114F)
#define TEE_ERROR_RA_VERIFY_POLICY_SUB_SIZE                TEE_MK_ERROR(0x1150)
#define TEE_ERROR_RA_VERIFY_POLICY_SUB_ATTR_SIZE           TEE_MK_ERROR(0x1151)

#define TEE_ERROR_RA_VERIFY_NESTED                         TEE_MK_ERROR(0x1160)
#define TEE_ERROR_RA_VERIFY_NESTED_GENERIC                 TEE_MK_ERROR(0x1161)
#define TEE_ERROR_RA_VERIFY_NESTED_ATTESTERS_SIZE          TEE_MK_ERROR(0x1162)
#define TEE_ERROR_RA_VERIFY_NESTED_POLICIES_SIZE           TEE_MK_ERROR(0x1163)
#define TEE_ERROR_RA_VERIFY_NESTED_ATTRIBUTES_SIZE         TEE_MK_ERROR(0x1164)
#define TEE_ERROR_RA_VERIFY_NESTED_REPORTS                 TEE_MK_ERROR(0x1166)
#define TEE_ERROR_RA_VERIFY_NESTED_REPORTS_SIGNATURE       TEE_MK_ERROR(0x1167)
#define TEE_ERROR_RA_VERIFY_NESTED_REPORTS_SMALLER_BUFFER  TEE_MK_ERROR(0x1168)
#define TEE_ERROR_RA_VERIFY_NESTED_REPORTS_SMALLER_BUFFER1 TEE_MK_ERROR(0x1169)
#define TEE_ERROR_RA_VERIFY_NESTED_GROUP_NAME              TEE_MK_ERROR(0x116A)
#define TEE_ERROR_RA_VERIFY_NESTED_GROUP_ID                TEE_MK_ERROR(0x116B)

// UnifiedAttestation::Verification::HyperEnclave
#define TEE_ERROR_RA_VERIFY_HYPERENCLAVE                   TEE_MK_ERROR(0x1180)
#define TEE_ERROR_RA_VERIFY_PLATFORM_CERT_LEN              TEE_MK_ERROR(0x1181)
#define TEE_ERROR_RA_VERIFY_PCR_DIGEST                     TEE_MK_ERROR(0x1182)

// UnifiedAttestation::Verification::Sgx1EPID
#define TEE_ERROR_RA_VERIFY_SGX1_EPID                      TEE_MK_ERROR(0x1190)
#define TEE_ERROR_RA_VERIFY_SGX1_PARSE_STATUS              TEE_MK_ERROR(0x1191)
#define TEE_ERROR_RA_VERIFY_SGX1_PARSE_BODY                TEE_MK_ERROR(0x1192)

// UnifiedAttestation::Verification::Sgx2DCAP
#define TEE_ERROR_RA_VERIFY_SGX2_DCAP                      TEE_MK_ERROR(0x11A0)
#define TEE_ERROR_RA_VERIFY_SGX2_DCAP_INVLID_PCK_CHAIN     TEE_MK_ERROR(0x11A1)
#define TEE_ERROR_RA_VERIFY_QUOTE_GET_FMSPC_CA             TEE_MK_ERROR(0x11A2)
#define TEE_ERROR_RA_VERIFY_GET_SUPPLEMENTAL_SIZE          TEE_MK_ERROR(0x11A3)
#define TEE_ERROR_RA_VERIFY_INVALID_SUPPLEMENTAL_SIZE      TEE_MK_ERROR(0x11A4)
#define TEE_ERROR_RA_VERIFY_DCAP_QUOTE                     TEE_MK_ERROR(0x11A5)
#define TEE_ERROR_RA_VERIFY_DCAP_QUOTE_RESULT              TEE_MK_ERROR(0x11A6)
#define TEE_ERROR_RA_VERIFY_INVALID_COLLATERAL_DATA        TEE_MK_ERROR(0x11A7)

// UnifiedAttestation::Verification::CSV
#define TEE_ERROR_RA_VERIFY_HYGON_CSV                      TEE_MK_ERROR(0x11B0)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_SIZEOF_CHECK         TEE_MK_ERROR(0x11B1)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_COLLATERAL_EMPTY     TEE_MK_ERROR(0x11B2)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_HSK_CERT             TEE_MK_ERROR(0x11B3)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_CEK_CERT             TEE_MK_ERROR(0x11B4)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_PEK_CERT             TEE_MK_ERROR(0x11B5)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_REPORT_SIGNATURE     TEE_MK_ERROR(0x11B6)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_HMAC                 TEE_MK_ERROR(0x11B7)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_HMAC_PEK_CHIPID      TEE_MK_ERROR(0x11B8)
#define TEE_ERROR_RA_VERIFY_HYGON_CSV_DATA_SIZE            TEE_MK_ERROR(0x11B9)

// UnifiedAttestation::Verification::Kunpeng
#define TEE_ERROR_RA_VERIFY_KUNPENG                        TEE_MK_ERROR(0x11C0)
#define TEE_ERROR_RA_VERIFY_KUNPENG_REPORT_SIGNATURE       TEE_MK_ERROR(0x11C1)

// UnifiedAttestation::Verification::Kunpeng
#define TEE_ERROR_RA_VERIFY_INTEL_TDX                      TEE_MK_ERROR(0x11D0)
#define TEE_ERROR_RA_VERIFY_INTEL_TDX_TEE_TYPE             TEE_MK_ERROR(0x11D1)
#define TEE_ERROR_RA_VERIFY_INTEL_TDX_QUOTE_VERSION        TEE_MK_ERROR(0x11D2)

// UnifiedAttestation::Uas::Service
#define TEE_ERROR_UAS_SERVER                               TEE_MK_ERROR(0x1800)
#define TEE_ERROR_UAS_VERIFIER_INVALID_AUTH_REPORT         TEE_MK_ERROR(0x1801)
#define TEE_ERROR_UAS_VERIFIER_CREATE_ENCLAVE              TEE_MK_ERROR(0x1802)
#define TEE_ERROR_UAS_VERIFIER_INFO_BUF_NOT_ENOUGH         TEE_MK_ERROR(0x1803)
#define TEE_ERROR_UAS_GENERATE_KEYPAIR                     TEE_MK_ERROR(0x1804)
#define TEE_ERROR_UAS_CHECK_OUTPUT_LEN                     TEE_MK_ERROR(0x1805)
#define TEE_ERROR_UAS_LEAK_SIGN_KEY                        TEE_MK_ERROR(0x1806)
#define TEE_ERROR_UAS_PLATFORM_UNSUPPORT                   TEE_MK_ERROR(0x1807)
#define TEE_ERROR_UAS_VERIFIER_GET_QUOTE                   TEE_MK_ERROR(0x1808)
#define TEE_ERROR_UAS_LEAK_ENCLAVE_KEY                     TEE_MK_ERROR(0x1809)
#define TEE_ERROR_UAS_REPORT_TYPE_UNSUPPORT                TEE_MK_ERROR(0x180A)
#define TEE_ERROR_UAS_CHECK_B64_QUOTE                      TEE_MK_ERROR(0x180B)
#define TEE_ERROR_UAS_SEM_INIT                             TEE_MK_ERROR(0x180C)
#define TEE_ERROR_UAS_REPORT_LENGTH                        TEE_MK_ERROR(0x180D)
#define TEE_ERROR_UAS_REPORT_CONVERTED_LENGTH              TEE_MK_ERROR(0x180E)


// UnifiedAttestation::Network::UasClient
#define TEE_ERROR_UAS_CLIENT                               TEE_MK_ERROR(0x1900)
#define TEE_ERROR_UAS_CONNECT_ERROR                        TEE_MK_ERROR(0x1901)
#define TEE_ERROR_UAS_JAVA_ERROR                           TEE_MK_ERROR(0x1902)
#define TEE_ERROR_UAS_GET_APP_KEY                          TEE_MK_ERROR(0x1903)
#define TEE_ERROR_UAS_GET_APP_SECRET                       TEE_MK_ERROR(0x1904)

// UnifiedAttestation::Network::ReportConvert
#define TEE_ERROR_CONVERT                                  TEE_MK_ERROR(0x1A00)
#define TEE_ERROR_CONVERT_REPORT_TYPE_UNSUPPORT            TEE_MK_ERROR(0x1A01)
#define TEE_ERROR_CONVERT_REPORT_PLATFORM_UNSUPPORT        TEE_MK_ERROR(0x1A02)
#define TEE_ERROR_CONVERT_INFO_EMPTY                       TEE_MK_ERROR(0x1A03)


// UnifiedAttestation::Istance::Generic
#define TEE_ERROR_INSTANCE_GENERIC                         TEE_MK_ERROR(0x1B00)
#define TEE_ERROR_INVALID_TEE_IDENTITY                     TEE_MK_ERROR(0x1B01)

// UnifiedAttestation::UnifiedFunction
#define TEE_ERROR_UNIFIED_FUNCTION                         TEE_MK_ERROR(0x1BE0)
#define TEE_ERROR_UNIFIED_FUNCTION_NOT_FOUND               TEE_MK_ERROR(0x1BE1)
#define TEE_ERROR_UNIFIED_FUNCTION_TEE_IDENTITY            TEE_MK_ERROR(0x1BE2)

// UnifiedAttestation::GRPC
#define TEE_ERROR_GRPC                                     TEE_MK_ERROR(0x1C00)
#define TEE_ERROR_GRPC_CLIENT                              TEE_MK_ERROR(0x1C01)
#define TEE_ERROR_GRPC_CLIENT_STATUS_ERROR                 TEE_MK_ERROR(0x1C02)
#define TEE_ERROR_GRPC_SERVER                              TEE_MK_ERROR(0x1C10)


#define TEE_ERROR_CODE(rc) (rc)
#define TEE_ERROR_MERGE(ecallcode, retcode) ((ecallcode) | (retcode))

// clang-format on

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_ERROR_H_
