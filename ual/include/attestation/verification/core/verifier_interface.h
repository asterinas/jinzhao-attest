#ifndef UAL_INCLUDE_ATTESTATION_VERIFICATION_CORE_VERIFIER_INTERFACE_H_
#define UAL_INCLUDE_ATTESTATION_VERIFICATION_CORE_VERIFIER_INTERFACE_H_

#include <string>

#include "attestation/common/error.h"
#include "attestation/common/type.h"

#include "attestation/verification/ua_verification.h"

constexpr bool kRequired = true;
constexpr bool kOptional = false;

namespace kubetee {
namespace attestation {

class AttestationVerifierInterface {
 public:
  // Parse the attester attributes from the report body
  virtual TeeErrorCode Initialize(
      const kubetee::UnifiedAttestationReport& report) = 0;

  // verify platform information in the report
  virtual TeeErrorCode VerifyPlatform(
      const kubetee::UnifiedAttestationAttributes& attr) = 0;

  // Get quote info
  virtual TeeErrorCode GetReportQuote(std::string* quote) = 0;

  // Verify report
  TeeErrorCode Verify(const kubetee::UnifiedAttestationPolicy& policy);

  // Verify policy
  // This happens when policy comes from unstusted administrator or conf file
  static TeeErrorCode VerifyPolicy(
      const kubetee::UnifiedAttestationPolicy& actual_policy,
      const kubetee::UnifiedAttestationPolicy& expected_policy);

  // Get the attester attributes in this attestation report
  TeeErrorCode GetAttesterAttr(kubetee::UnifiedAttestationAttributes* attr) {
    *attr = attributes_;
    return TEE_SUCCESS;
  }

  // Show all the attester attributes items
  TeeErrorCode ShowAttesterAttributes();

  std::string report_type_;
  kubetee::UnifiedAttestationAttributes attributes_;
  kubetee::UnifiedAttestationNestedReports nested_reports_;

 private:
  TeeErrorCode VerifyMainAttester(
      const kubetee::UnifiedAttestationPolicy& policy);
  TeeErrorCode VerifyNestedReports(
      const kubetee::UnifiedAttestationPolicy& policy);

  // The common methods to compare EnclveInformation
  static TeeErrorCode VerifyAttributes(
      const kubetee::UnifiedAttestationAttributes& actual,
      const kubetee::UnifiedAttestationAttributes& expected);

  // Show the attributes item
  void ShowAttr(const char* name, const std::string& value) {
#ifdef DEBUGLOG
    ELOG_DEBUG("%s:%s", name, value.c_str());
#else
    TEE_UNREFERENCED_PARAMETER(name);
    TEE_UNREFERENCED_PARAMETER(value);
#endif
  }

  // Compare the attributes item
  static bool IsRequired(const char* name, const bool required);
  static bool IsStrEqual(const std::string& item_name,
                         const std::string& expected_value,
                         const std::string& actual_value,
                         const bool required = false);
  static bool IsStrMatch(const std::string& item_name,
                         const std::string& expected_value,
                         const std::string& actual_value,
                         const bool required = false);
  static bool IsHashEqual(const std::string& item_name,
                          const std::string& plain_value,
                          const std::string& hash_value,
                          const bool required = false);
  static bool IsBoolEqual(const std::string& item_name,
                          const std::string& expected_value,
                          const std::string& actual_value,
                          const bool required = false);
  static bool IsHexIntEqual(const std::string& item_name,
                            const std::string& expected_value,
                            const std::string& actual_value,
                            const bool required = false);
  static bool IsIntNotLess(const std::string& item_name,
                           const std::string& expected_value,
                           const std::string& actual_value,
                           const bool required = false);
  static bool StrToBool(const std::string& bool_str);
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_ATTESTATION_VERIFICATION_CORE_VERIFIER_INTERFACE_H_
