#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_TEE_INSTANCE_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_TEE_INSTANCE_H_

#include <map>
#include <string>

#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/pthread.h"
#include "attestation/common/table.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"

#include "attestation/generation/core/generator_interface.h"
#include "attestation/instance/trusted_tee_instance_interface.h"

using kubetee::attestation::UaReportGenerationParameters;

using kubetee::UnifiedAttestationAttributes;

namespace kubetee {
namespace attestation {

typedef struct {
  // For set report data in tee side
  // User always use the hex string type
  // But it will be decoded firstly before be saved into report
  std::string hex_report_data;
  // Save the enclave after generation report
  kubetee::UnifiedAttestationAttributes attester_attr;
} UaReport;

class TeeInstance {
 public:
  static TeeInstance& GetInstance() {
    static TeeInstance instance_;

    UA_MUTEX_LOCK(&enclave_lock_);
    instance_.Initialize();
    UA_MUTEX_UNLOCK(&enclave_lock_);

    return instance_;
  }

  TeeErrorCode IsInitialized();

  TeeErrorCode UpdateReportData(const std::string& hex_report_data,
                                const std::string& report_identity = "");
  const std::string& ReportData(const std::string& report_identity = "");

  TeeErrorCode SaveEnclaveInfo(
      const UnifiedAttestationAttributes& attester_attr,
      const std::string& report_identity = "");
  const UnifiedAttestationAttributes& AttesterAttr(
      const std::string& report_identity = "");
  const kubetee::UnifiedAttestationAttributes& GetEnclaveInfo() {
    return AttesterAttr();
  }

  // Initialize/Replace all the UaReport field in one time
  TeeErrorCode UpdateReportCache(const UaReport& ua_report,
                                 const std::string& report_identity = "");
  // Delete the whole report cache instance which must eixsts
  TeeErrorCode DeleteReportCache(const std::string& report_identity = "");
  // Get the current number of report cache instances
  int ReportCacheSize();

  // Generate the UnifiedAttestationAuthReport report by ocall
  TeeErrorCode GenerateAuthReport(UaReportGenerationParameters* param,
                                  kubetee::UnifiedAttestationAuthReport* auth);

  TeeErrorCode ReeRun(const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);

  // Identity keypair
  TeeErrorCode CreateIdentity();
  TeeErrorCode ImportIdentity(const kubetee::AsymmetricKeyPair& identity);
  const kubetee::AsymmetricKeyPair& GetIdentity() {
    return Uak();
  }

  // TEE identity string
  TeeErrorCode SetTeeIdentity(const std::string& tee_identity) {
    if (tee_identity_.empty()) {
      tee_identity_.assign(tee_identity);
    } else if (tee_identity_ != tee_identity) {
      ELOG_ERROR("Mismatched tee idenitty: %s/%s", tee_identity_.c_str(),
                 tee_identity.c_str());
      return TEE_ERROR_UNIFIED_FUNCTION_TEE_IDENTITY;
    }
    return TEE_SUCCESS;
  }
  const std::string& GetTeeIdentity() {
    return tee_identity_;
  }

  TeeErrorCode SealData(const std::string& plain_str,
                        std::string* sealed_str,
                        bool tee_bound = true);

  TeeErrorCode UnsealData(const std::string& sealed_str,
                          std::string* plain_str);

  static std::shared_ptr<TeeInstanceInterface> Inner();

  // Default shared report cache instance
  static const char kDefaultReportCache[];

 private:
  // Hide construction functions
  TeeInstance() {}
  TeeInstance(const TeeInstance&);
  void operator=(TeeInstance const&);

  void Initialize();
  bool HasReportCache(const std::string& report_identity);
  TeeErrorCode InitializeReportCache(const std::string& report_identity);
  UaReport* FindReportByIdOrDefault(const std::string& report_identity);

  bool is_initialized = false;

  // Used for TeeRun check and ReeRun parameter
  std::string tee_identity_;

  // Save the special data checked for each report instance
  std::map<std::string, UaReport> reports_;

  // mutex for multi-thread protection
  static UA_MUTEX_T enclave_lock_;
};

class TeeInstanceUnknown : public TeeInstanceInterface {
 public:
  TeeErrorCode GenerateAuthReport(
      UaReportGenerationParameters* param,
      kubetee::UnifiedAttestationAuthReport* auth) override {
    TEE_UNREFERENCED_PARAMETER(param);
    TEE_UNREFERENCED_PARAMETER(auth);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }
  TeeErrorCode ReeRun(const kubetee::UnifiedFunctionParams& params,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response) override {
    TEE_UNREFERENCED_PARAMETER(params);
    TEE_UNREFERENCED_PARAMETER(request);
    TEE_UNREFERENCED_PARAMETER(response);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }
  TeeErrorCode SealData(const std::string& plain_str,
                        std::string* sealed_str,
                        bool tee_bound) override {
    TEE_UNREFERENCED_PARAMETER(plain_str);
    TEE_UNREFERENCED_PARAMETER(sealed_str);
    TEE_UNREFERENCED_PARAMETER(tee_bound);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }
  TeeErrorCode UnsealData(const std::string& sealed_str,
                          std::string* plain_str) override {
    TEE_UNREFERENCED_PARAMETER(sealed_str);
    TEE_UNREFERENCED_PARAMETER(plain_str);
    TEE_LOG_ERROR("Unknow TEE platform");
    return TEE_ERROR_NOT_IMPLEMENTED;
  }
};

}  // namespace attestation
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif

/// When create differen report cache instance by report_identity
/// Limit the max number of instances. This dont' include the 'default' one.
constexpr int kMaxReportIdentityNum = 64;

/// @brief Check whether the UA enclave is initialized
///
extern TeeErrorCode TeeInstanceIsInitialized();

/// @brief Initialize report data to be filled into report data
///
/// NOTE: This function need to be called in user enclave code !!!
/// NOTE: If the report data is not enough to 64 bytes, the left
///       bytes of report data will be filled by zero.
/// NOTE: User can call both UakInitialize() and this function.
///       If so, the UAK public key hash will replace the higher
///       32 bytes of the final 64 bytes report data.
///
extern TeeErrorCode TeeInstanceUpdateReportData(
    const std::string& report_data, const std::string& report_identity = "");

/// @brief Get report data which is set in enclave side
///
/// NOTE: This enclave side report data has higher priority what from the
///       untrusted code.
///
extern const std::string& TeeInstanceReportData(
    const std::string& report_identity = "");

/// @brief Save the last time attester attributes in attestation report
///
extern TeeErrorCode TeeInstanceSaveEnclaveInfo(
    const kubetee::UnifiedAttestationAttributes& attester_attr,
    const std::string& report_identity = "");

/// @brief Get the attester attributes updated when create attestation report
///
extern const kubetee::UnifiedAttestationAttributes& TeeInstanceGetEnclaveInfo(
    const std::string& report_identity = "");

/// @brief Initialize/Replace all the UaReport field in one time
///
extern TeeErrorCode TeeInstanceUpdateReportCache(
    const kubetee::attestation::UaReport& ua_report,
    const std::string& report_identity = "");

/// @brief Delete the whole report cache instance which must eixsts
///
extern TeeErrorCode TeeInstanceDeleteReportCache(
    const std::string& report_identity = "");

/// @brief Get the current number of report cache instances
///
extern TeeErrorCode TeeInstanceReportCacheSize();

#ifdef UA_ENV_TYPE_SGXSDK
/// @brief C++ API for generating authentication report by ocall
extern TeeErrorCode UaGenerateAuthReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationAuthReport* auth);
#endif

/// @brief C API for setting the report data in enclave side
/// @param report_identity: set the report data to which report instance
/// @param report_data_buf: the binary user data buffer for report data
/// @param report_data_len: the data length of report data
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationUpdateReportData(const char* report_identity,
                                              const char* report_data_buf,
                                              const int report_data_len);

/// @brief C API for getting the report data in enclave side
/// @param report_identity: get the report data from which report instance
/// @param report_data_buf: the binary user data buffer to get report data
/// @param report_data_len: Input as max buf len, and output as real len
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationReportData(const char* report_identity,
                                        char* report_data_buf,
                                        int* report_data_len);

/// @brief Delete the whole report cache instance which must eixsts
/// @param report_identity: get the report data from which report instance
///
/// @return 0 means success or other error code
///
extern int UnifiedAttestationDeleteReportCache(const char* report_identity);

/// @brief Get the current number of report cache instances
///
extern int UnifiedAttestationReportCacheSize();

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_TEE_INSTANCE_H_
