#include <string>

#include "./pthread.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/instance/trusted_tee_instance.h"

#ifdef UA_ENV_TYPE_SGXSDK
#include "instance/platforms/sgx/trusted/trusted_tee_sgx.h"
#endif

namespace kubetee {
namespace attestation {

// The shared Report cache for all, if the report identity is not set.
const char TeeInstance::kDefaultReportCache[] = "default";

// Used in GetInstance and all pubcli methods.
UA_MUTEX_T TeeInstance::enclave_lock_ = UA_MUTEX_INITIALIZER;

std::shared_ptr<TeeInstanceInterface> TeeInstance::Inner() {
#ifdef UA_ENV_TYPE_SGXSDK
  return std::make_shared<TeeInstanceSgx>();
#else
  return std::make_shared<TeeInstanceUnknown>();
#endif
}

void TeeInstance::Initialize() {
  if (!is_initialized) {
    ELOG_INFO("Initialize TeeInstance default report instance ...");
    if (TEE_SUCCESS != InitializeReportCache(kDefaultReportCache)) {
      ELOG_ERROR("Fail to initialize default UAReport!");
    }
    is_initialized = true;
  }
}

bool TeeInstance::HasReportCache(const std::string& report_identity) {
  return reports_.find(report_identity) != reports_.end();
}

TeeErrorCode TeeInstance::InitializeReportCache(
    const std::string& report_identity) {
  // Empty identity is the same behavior which use default instance
  std::string identity(report_identity);
  if (identity.empty()) {
    identity = kDefaultReportCache;
  }
  // If there already is the cache instance, nothing to do
  if (HasReportCache(identity)) {
    return TEE_SUCCESS;
  }

  // If the identity is kDefaultReportCache,  always create it.
  // For other identity name, should check the max number firstly
  if (identity != kDefaultReportCache) {
    const size_t has_default = HasReportCache(kDefaultReportCache) ? 1 : 0;
    const size_t others_size = reports_.size() - has_default;
    ELOG_DEBUG("UaReport size (without default): %ld", others_size);
    if (others_size >= kMaxReportIdentityNum) {
      ELOG_ERROR("Max report number when create: %s", identity.c_str());
      return TEE_ERROR_RA_MAX_UAREPORT_CACHE_INSTANCE;
    }
  }

  UaReport ua_report;
  ELOG_DEBUG("InitUaReport[%d]:%s", reports_.size(), identity.c_str());
  reports_.emplace(identity, ua_report);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::IsInitialized() {
  if (!is_initialized) {
    ELOG_DEBUG("UA enclave is not initialized");
    return TEE_ERROR_RA_UA_ENCLAVE_NOT_INITIALIZED;
  }
  return TEE_SUCCESS;
}

UaReport* TeeInstance::FindReportByIdOrDefault(
    const std::string& report_identity) {
  // empty or other not existed report_itenity will all use default
  auto iter = reports_.find(report_identity);
  if (iter != reports_.end()) {
    return &reports_[report_identity];
  } else {
    return &reports_["default"];
  }
}

TeeErrorCode TeeInstance::UpdateReportData(const std::string& hex_report_data,
                                           const std::string& report_identity) {
  if (hex_report_data.size() > (2 * kSha256Size)) {
    TEE_LOG_ERROR("Too much report data");
    return TEE_ERROR_RA_TOO_MUCH_REPORT_DATA;
  }

  // Update the report_data field
  UA_MUTEX_LOCK(&enclave_lock_);

  // This function will create new UaReport instance, so check current number
  TeeErrorCode ret = InitializeReportCache(report_identity);
  if (ret != TEE_SUCCESS) {
    UA_MUTEX_UNLOCK(&enclave_lock_);
    ELOG_ERROR_TRACE();
    return ret;
  }

  // Always update the trusted report data even it's empty
  ELOG_DEBUG("Update report data: %s", report_identity.c_str());
  UaReport* uareport = FindReportByIdOrDefault(report_identity);
  uareport->hex_report_data.assign(hex_report_data);

  UA_MUTEX_UNLOCK(&enclave_lock_);

  return TEE_SUCCESS;
}

const std::string& TeeInstance::ReportData(const std::string& report_identity) {
  // If there is no report_identity instance
  // return hex_report_data in default instance
  return FindReportByIdOrDefault(report_identity)->hex_report_data;
}

TeeErrorCode TeeInstance::SaveEnclaveInfo(
    const kubetee::UnifiedAttestationAttributes& attester_attr,
    const std::string& report_identity) {
  UA_MUTEX_LOCK(&enclave_lock_);

  // This function will create new UaReport instance, so check current number
  TeeErrorCode ret = InitializeReportCache(report_identity);
  if (ret != TEE_SUCCESS) {
    UA_MUTEX_UNLOCK(&enclave_lock_);
    ELOG_ERROR_TRACE();
    return ret;
  }

  // Always update the attester attributes even it's empty
  ELOG_DEBUG("Save enclave info, identity: %s", report_identity.c_str());
  UaReport* uareport = FindReportByIdOrDefault(report_identity);
  uareport->attester_attr.CopyFrom(attester_attr);

  UA_MUTEX_UNLOCK(&enclave_lock_);

  return TEE_SUCCESS;
}

const kubetee::UnifiedAttestationAttributes& TeeInstance::AttesterAttr(
    const std::string& report_identity) {
  return FindReportByIdOrDefault(report_identity)->attester_attr;
}

TeeErrorCode TeeInstance::UpdateReportCache(
    const UaReport& ua_report, const std::string& report_identity) {
  // Always delete the existed instance to avoid update field one by one
  UA_MUTEX_LOCK(&enclave_lock_);

  // This function will create new UaReport instance, so check current number
  TeeErrorCode ret = InitializeReportCache(report_identity);
  if (ret != TEE_SUCCESS) {
    UA_MUTEX_UNLOCK(&enclave_lock_);
    ELOG_ERROR_TRACE();
    return ret;
  }

  ELOG_DEBUG("UpdateUaReport: %s", report_identity.c_str());
  UaReport* uareport = FindReportByIdOrDefault(report_identity);
  uareport->hex_report_data = ua_report.hex_report_data;
  uareport->attester_attr.CopyFrom(ua_report.attester_attr);

  UA_MUTEX_UNLOCK(&enclave_lock_);
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::DeleteReportCache(
    const std::string& report_identity) {
  if (report_identity.empty()) {
    ELOG_ERROR("Empty indentity when delete report cache");
    return TEE_ERROR_RA_EMPTY_REPORT_IDENTITY;
  }
  if (report_identity == kDefaultReportCache) {
    ELOG_ERROR("Don't allow to delete deault report cache instance");
    return TEE_ERROR_RA_DONOT_DELETE_DEFUALT_REPORT;
  }
  if (!HasReportCache(report_identity)) {
    ELOG_ERROR("Delete report data, not existed: %s", report_identity.c_str());
    return TEE_ERROR_RA_TRUSTED_REPORT_NOT_EXIST;
  }

  UA_MUTEX_LOCK(&enclave_lock_);
  reports_.erase(report_identity);
  UA_MUTEX_UNLOCK(&enclave_lock_);

  return TEE_SUCCESS;
}

int TeeInstance::ReportCacheSize() {
  const int has_default = HasReportCache(kDefaultReportCache) ? 1 : 0;
  const int others_size = reports_.size() - has_default;
  // Still make sure others_size will larger than 0, even this should to be
  // Because reports_.size() should more than 1 if has default instance.
  return (others_size >= 0) ? others_size : 0;
}

TeeErrorCode TeeInstance::GenerateAuthReport(
    UaReportGenerationParameters* param,
    kubetee::UnifiedAttestationAuthReport* auth) {
  TEE_CHECK_RETURN(Inner()->GenerateAuthReport(param, auth));
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::ReeRun(const std::string& function_name,
                                 const google::protobuf::Message& request,
                                 google::protobuf::Message* response) {
  kubetee::UnifiedFunctionParams params;
  params.set_tee_identity(tee_identity_);
  params.set_function_name(function_name);

  // Call the ReeRun in special Platform
  TEE_CHECK_RETURN(Inner()->ReeRun(params, request, response));
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::SealData(const std::string& plain_str,
                                   std::string* sealed_str,
                                   bool tee_bound) {
  TEE_CHECK_RETURN(Inner()->SealData(plain_str, sealed_str, tee_bound));
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::UnsealData(const std::string& sealed_str,
                                     std::string* plain_str) {
  TEE_CHECK_RETURN(Inner()->UnsealData(sealed_str, plain_str));
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::CreateIdentity() {
  TEE_CHECK_RETURN(TeeInstanceIsInitialized());
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::ImportIdentity(
    const kubetee::AsymmetricKeyPair& identity) {
  const std::string& private_key = identity.private_key();
  const std::string& public_key = identity.public_key();
  TEE_CHECK_RETURN(UakUpdate(private_key, public_key));
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif

using kubetee::attestation::TeeInstance;

/// APIs for C++ code
TeeErrorCode TeeInstanceIsInitialized() {
  return TeeInstance::GetInstance().IsInitialized();
}

TeeErrorCode TeeInstanceUpdateReportData(const std::string& hex_report_data,
                                         const std::string& report_identity) {
  return TeeInstance::GetInstance().UpdateReportData(hex_report_data,
                                                     report_identity);
}

const std::string& TeeInstanceReportData(const std::string& report_identity) {
  return TeeInstance::GetInstance().ReportData(report_identity);
}

TeeErrorCode TeeInstanceSaveEnclaveInfo(
    const UnifiedAttestationAttributes& attester_attr,
    const std::string& report_identity) {
  return TeeInstance::GetInstance().SaveEnclaveInfo(attester_attr,
                                                    report_identity);
}

const UnifiedAttestationAttributes& TeeInstanceGetEnclaveInfo(
    const std::string& report_identity) {
  return TeeInstance::GetInstance().AttesterAttr(report_identity);
}

TeeErrorCode TeeInstanceUpdateReportCache(
    const kubetee::attestation::UaReport& ua_report,
    const std::string& report_identity) {
  return TeeInstance::GetInstance().UpdateReportCache(ua_report,
                                                      report_identity);
}

TeeErrorCode TeeInstanceDeleteReportCache(const std::string& report_identity) {
  return TeeInstance::GetInstance().DeleteReportCache(report_identity);
}

TeeErrorCode TeeInstanceReportCacheSize() {
  return TeeInstance::GetInstance().ReportCacheSize();
}

#ifdef UA_ENV_TYPE_SGXSDK
// Only use the untrusted version of this function in occlum
TeeErrorCode UaGenerateAuthReport(const UaReportGenerationParameters& param,
                                  kubetee::UnifiedAttestationAuthReport* auth) {
  UaReportGenerationParameters* pparam =
      &CCAST(UaReportGenerationParameters&, param);
  return TeeInstance::GetInstance().GenerateAuthReport(pparam, auth);
}
#endif

/// APIs for C code
int UnifiedAttestationUpdateReportData(const char* report_identity,
                                       const char* hex_report_data_buf,
                                       const int hex_report_data_len) {
  TEE_CHECK_VALIDBUF(hex_report_data_buf, hex_report_data_len);
  std::string identity = SAFESTR(report_identity);
  std::string hex_report_data(hex_report_data_buf, hex_report_data_len);
  return TeeInstanceUpdateReportData(hex_report_data, identity);
}

int UnifiedAttestationReportData(const char* report_identity,
                                 char* hex_report_data_buf,
                                 int* hex_report_data_len) {
  TEE_CHECK_VALIDBUF(hex_report_data_buf, hex_report_data_len);
  std::string identity = SAFESTR(report_identity);
  const std::string& hex_report_data = TeeInstanceReportData(identity);
  if (hex_report_data.size() >= SCAST(size_t, *hex_report_data_len)) {
    return TEE_ERROR_RA_SMALLER_REPORT_DATA_BUFFER;
  }
  memcpy(hex_report_data_buf, hex_report_data.data(), hex_report_data.size());
  *hex_report_data_len = SCAST(size_t, hex_report_data.size());
  return TEE_SUCCESS;
}

int UnifiedAttestationDeleteReportCache(const char* report_identity) {
  std::string identity = SAFESTR(report_identity);
  return TeeInstanceDeleteReportCache(identity);
}

int UnifiedAttestationReportCacheSize() {
  return TeeInstanceReportCacheSize();
}

#ifdef __cplusplus
}
#endif
