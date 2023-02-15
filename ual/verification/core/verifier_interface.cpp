#include <cstring>
#include <string>
#include <vector>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/scope.h"
#include "attestation/common/type.h"

#include "attestation/verification/core/verifier_interface.h"

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationVerifierInterface::Verify(
    const kubetee::UnifiedAttestationPolicy& policy) {
  // Verify the public key hash in report if specified public key
  // Public key hash will also be verified by each policy
  if (!IsHashEqual(kUaAttrPublickey, policy.pem_public_key(),
                   attributes_.hex_hash_or_pem_pubkey())) {
    return TEE_ERROR_RA_VERIFY_ATTR_PUBKEY;
  }

  // Verify the main attester attributes
  // Because compare attributes is more easy, so do it firstly.
  TEE_CHECK_RETURN(VerifyMainAttester(policy));

  // Veify the submodule enclaves information
  TEE_CHECK_RETURN(VerifyNestedReports(policy));

  // Verify the platform once
  // HyperEnclave need different user_data in policy to verify platform
  // But we ignore this which means we ignore TPM quote nonce
  // Otherwise, we need do it in the main enclave report loop
  const kubetee::UnifiedAttestationAttributes not_used_policy_attr;
  TEE_CHECK_RETURN(VerifyPlatform(not_used_policy_attr));

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierInterface::VerifyMainAttester(
    const kubetee::UnifiedAttestationPolicy& policy) {
  TeeErrorCode ret = TEE_ERROR_RA_VERIFY_RULE_ENTRY_EMPTY;

  for (int i = 0; i < policy.main_attributes_size(); i++) {
    ELOG_DEBUG("Verify main attester by attributes entry [%d]", i);
    const kubetee::UnifiedAttestationAttributes& policy_attr =
        policy.main_attributes()[i];
    ret = VerifyAttributes(attributes_, policy_attr);
    if (ret == TEE_SUCCESS) {
      return TEE_SUCCESS;
    }
  }

  // The ret value will only save the last one if all failure,
  // which is exactly expected if there is only one attributes entry.
  return ret;
}

TeeErrorCode AttestationVerifierInterface::VerifyNestedReports(
    const kubetee::UnifiedAttestationPolicy& policy) {
  // If there is no submodules, and don't expect submodule enclaves
  if (nested_reports_.json_nested_results().empty() &&
      (policy.nested_policies_size() == 0)) {
    ELOG_DEBUG("Do not need to verify submodule attesters");
    return TEE_SUCCESS;
  }

  // Check the expect submodule attesters size and the nested policy size
  kubetee::UnifiedAttestationNestedResults nested_results;
  JSON2PB(nested_reports_.json_nested_results(), &nested_results);
  if (nested_results.results_size() != policy.nested_policies_size()) {
    ELOG_ERROR("Has %d submodule attesters but expect %d",
               nested_results.results_size(), policy.nested_policies_size());
    return TEE_ERROR_RA_VERIFY_NESTED_ATTESTERS_SIZE;
  }
  ELOG_DEBUG("There are %d submodule attester", nested_results.results_size());

  // Verify the submodules report signature
  // by public key in UnifiedAttestationPolicy
  kubetee::common::DataBytes signature(nested_reports_.b64_nested_signature());
  if (kubetee::common::RsaCrypto::Verify(
          policy.pem_public_key(), nested_reports_.json_nested_results(),
          signature.FromBase64().GetStr()) != TEE_SUCCESS) {
    return TEE_ERROR_RA_VERIFY_NESTED_REPORTS_SIGNATURE;
  }

  // Verify nested attester one by one, assume the order must be the same
  for (int i = 0; i < policy.nested_policies_size(); i++) {
    ELOG_DEBUG("Verify submodule enclave [%d]", i);
    const kubetee::UnifiedAttestationAttributes& attester_attrs =
        nested_results.results()[i];
    const kubetee::UnifiedAttestationNestedPolicy& nested_policy =
        policy.nested_policies()[i];
    // Each nested attester has a list of attribtes set
    TeeErrorCode ret = TEE_ERROR_RA_VERIFY_NESTED_GENERIC;
    for (int j = 0; j < nested_policy.sub_attributes_size(); j++) {
      ELOG_DEBUG("Verify sub attributes entry [%d]", j);
      const kubetee::UnifiedAttestationAttributes& policy_attrs =
          nested_policy.sub_attributes()[j];
      if ((ret = VerifyAttributes(attester_attrs, policy_attrs)) ==
          TEE_SUCCESS) {
        break;
      }
    }
    if (ret != TEE_SUCCESS) {
      // The ret value will only save the last one if all failure,
      // which is exactly expected if there is only one sub_attributes entry.
      return ret;
    }
  }

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierInterface::VerifyAttributes(
    const kubetee::UnifiedAttestationAttributes& actual,
    const kubetee::UnifiedAttestationAttributes& expected) {
  if (!IsStrEqual(kUaAttrPlatform, expected.str_tee_platform(),
                  actual.str_tee_platform())) {
    return TEE_ERROR_RA_VERIFY_ATTR_PLATFORM;
  }
  if (!IsStrEqual(kUaAttrPlatformHwVer, expected.hex_platform_hw_version(),
                  actual.hex_platform_hw_version())) {
    return TEE_ERROR_RA_VERIFY_ATTR_PLATFORM_HW_VERSION;
  }
  if (!IsStrEqual(kUaAttrPlatformSwVer, expected.hex_platform_sw_version(),
                  actual.hex_platform_sw_version())) {
    return TEE_ERROR_RA_VERIFY_ATTR_PLATFORM_SW_VERSION;
  }
  if (!IsStrEqual(kUaAttrSecureFlags, expected.hex_secure_flags(),
                  actual.hex_secure_flags())) {
    return TEE_ERROR_RA_VERIFY_ATTR_SECURE_FLAGS;
  }
  if (!IsStrEqual(kUaAttrMrplatform, expected.hex_platform_measurement(),
                  actual.hex_platform_measurement())) {
    return TEE_ERROR_RA_VERIFY_ATTR_PLATFORM_MEASUREMENT;
  }
  if (!IsStrEqual(kUaAttrMrboot, expected.hex_boot_measurement(),
                  actual.hex_boot_measurement())) {
    return TEE_ERROR_RA_VERIFY_ATTR_BOOT_MEASUREMENT;
  }
  if (!IsStrEqual(kUaAttrMrTa, expected.hex_ta_measurement(),
                  actual.hex_ta_measurement())) {
    return TEE_ERROR_RA_VERIFY_ATTR_TA_MEASUREMENT;
  }
  if (!IsStrEqual(kUaAttrMrTaDyn, expected.hex_ta_dyn_measurement(),
                  actual.hex_ta_dyn_measurement())) {
    return TEE_ERROR_RA_VERIFY_ATTR_TA_MEASUREMENT;
  }
  if (!IsStrEqual(kUaAttrSigner, expected.hex_signer(), actual.hex_signer())) {
    return TEE_ERROR_RA_VERIFY_ATTR_SIGNER;
  }
  if (!IsStrEqual(kUaAttrProdID, expected.hex_prod_id(),
                  actual.hex_prod_id())) {
    return TEE_ERROR_RA_VERIFY_ATTR_ISV_PORDID;
  }
  if (!IsIntNotLess(kUaAttrIsvSvn, expected.str_min_isvsvn(),
                    actual.str_min_isvsvn())) {
    return TEE_ERROR_RA_VERIFY_ATTR_ISV_SVN;
  }
  if (!IsBoolEqual(kUaAttrDebugDisabled, expected.bool_debug_disabled(),
                   actual.bool_debug_disabled())) {
    return TEE_ERROR_RA_VERIFY_ATTR_DEBUG_DISABLED;
  }
  if (!IsStrMatch(kUaAttrUserData, expected.hex_user_data(),
                  actual.hex_user_data())) {
    return TEE_ERROR_RA_VERIFY_ATTR_USER_DATA;
  }
  if (!IsHashEqual(kUaAttrPublickey, expected.hex_hash_or_pem_pubkey(),
                   actual.hex_hash_or_pem_pubkey())) {
    return TEE_ERROR_RA_VERIFY_ATTR_PUBKEY;
  }
  if (!IsStrMatch(kUaAttrNonce, expected.hex_nonce(), actual.hex_nonce())) {
    return TEE_ERROR_RA_VERIFY_ATTR_NONCE;
  }
  if (verify_spid_) {
    if (!IsStrEqual(kUaAttrSpid, expected.hex_spid(), actual.hex_spid())) {
      return TEE_ERROR_RA_VERIFY_ATTR_SPID_NAME;
    }
  }

  return TEE_SUCCESS;
}

TeeErrorCode AttestationVerifierInterface::ShowAttesterAttributes() {
  ShowAttr(kUaAttrPlatform, attributes_.str_tee_platform());
  ShowAttr(kUaAttrPlatformHwVer, attributes_.hex_platform_hw_version());
  ShowAttr(kUaAttrPlatformSwVer, attributes_.hex_platform_sw_version());
  ShowAttr(kUaAttrSecureFlags, attributes_.hex_secure_flags());
  ShowAttr(kUaAttrMrplatform, attributes_.hex_platform_measurement());
  ShowAttr(kUaAttrMrboot, attributes_.hex_boot_measurement());
  ShowAttr(kUaAttrMrTa, attributes_.hex_ta_measurement());
  ShowAttr(kUaAttrMrTaDyn, attributes_.hex_ta_dyn_measurement());
  ShowAttr(kUaAttrSigner, attributes_.hex_signer());
  ShowAttr(kUaAttrProdID, attributes_.hex_prod_id());
  ShowAttr(kUaAttrIsvSvn, attributes_.str_min_isvsvn());
  ShowAttr(kUaAttrDebugDisabled, attributes_.bool_debug_disabled());
  ShowAttr(kUaAttrUserData, attributes_.hex_user_data());
  ShowAttr(kUaAttrPublickey, attributes_.hex_hash_or_pem_pubkey());
  ShowAttr(kUaAttrNonce, attributes_.hex_nonce());
  ShowAttr(kUaAttrSpid, attributes_.hex_spid());
  return TEE_SUCCESS;
}

bool AttestationVerifierInterface::IsStrEqual(const std::string& item_name,
                                              const std::string& expected_value,
                                              const std::string& actual_value,
                                              const bool required) {
  if (expected_value.empty()) {
    if (required) {
      ELOG_ERROR("[VERIFY] %s: empty, but required!", item_name.c_str());
      return false;
    } else {
      // If it is not must required, and valued expected is empty, ignore it
      ELOG_DEBUG("[VERIFY] %s: empty, be careful!", item_name.c_str());
      return true;
    }
  } else if (expected_value != actual_value) {
    // If it's not empty but mismatch
    ELOG_ERROR("[VERIFY] %s: String not equal", item_name.c_str());
    ELOG_DEBUG("    Actual  : %s", actual_value.c_str());
    ELOG_DEBUG("    Expected: %s", expected_value.c_str());
    return false;
  }
  ELOG_DEBUG("[VERIFY] %s: Success", item_name.c_str());
  return true;
}

bool AttestationVerifierInterface::IsStrMatch(const std::string& item_name,
                                              const std::string& expected_value,
                                              const std::string& actual_value,
                                              const bool required) {
  if (expected_value.empty()) {
    if (required) {
      ELOG_ERROR("[VERIFY] %s: empty, but required!", item_name.c_str());
      return false;
    } else {
      // If it is not must required, and valued expected is empty, ignore it
      ELOG_DEBUG("[VERIFY] %s: empty, be careful!", item_name.c_str());
      return true;
    }
  } else if (actual_value.find(expected_value) != 0) {
    // If it's not empty but mismatch
    ELOG_ERROR("[VERIFY] %s: String not match", item_name.c_str());
    ELOG_DEBUG("    Actual total: %s", actual_value.c_str());
    ELOG_DEBUG("    Expected sub: %s", expected_value.c_str());
    return false;
  }

  ELOG_DEBUG("[VERIFY] %s: Success", item_name.c_str());
  return true;
}

bool AttestationVerifierInterface::IsHashEqual(const std::string& item_name,
                                               const std::string& plain_value,
                                               const std::string& hash_value,
                                               const bool required) {
  if (plain_value.empty()) {
    if (required) {
      ELOG_ERROR("[VERIFY] %s: empty, but required!", item_name.c_str());
      return false;
    } else {
      // If it is not must required, and valued expected is empty, ignore it
      ELOG_DEBUG("[VERIFY] %s: empty, be careful!", item_name.c_str());
      return true;
    }
  } else if (plain_value != hash_value) {
    // Calculate the HASH value and compare to expeced value
    std::string hash_cal =
        kubetee::common::DataBytes::SHA256HexStr(plain_value);
    if (hash_cal != hash_value) {
      ELOG_ERROR("[VERIFY] %s: Hash mismatch", item_name.c_str());
      ELOG_DEBUG("    Plain        : %s", plain_value.c_str());
      ELOG_DEBUG("    Actual Hash  : %s", hash_cal.c_str());
      ELOG_DEBUG("    Expected hash: %s", hash_value.c_str());
      return false;
    }
  }

  // If hash match or the plain value itself is exactly the hash value
  ELOG_DEBUG("[VERIFY] %s: Success", item_name.c_str());
  return true;
}

bool AttestationVerifierInterface::IsBoolEqual(
    const std::string& item_name,
    const std::string& expected_value,
    const std::string& actual_value,
    const bool required) {
  if (expected_value.empty()) {
    if (required) {
      ELOG_ERROR("[VERIFY] %s: empty, but required!", item_name.c_str());
      return false;
    } else {
      // If it's must required, and empty exepected, means don't care it
      ELOG_DEBUG("[VERIFY] %s: empty, be careful!", item_name.c_str());
      return true;
    }
  }

  // Check actual_value and expected_value are the same bool value
  bool actual_bool = StrToBool(actual_value);
  bool expected_bool = StrToBool(expected_value);
  if (actual_bool != expected_bool) {
    ELOG_ERROR("[VERIFY] %s: Bool not equal", item_name.c_str());
    ELOG_DEBUG("    Actual  : %s", actual_value.c_str());
    ELOG_DEBUG("    Expected: %s", expected_value.c_str());
    return false;
  }

  ELOG_DEBUG("[VERIFY] %s: Success", item_name.c_str());
  return true;
}

bool AttestationVerifierInterface::IsHexIntEqual(
    const std::string& item_name,
    const std::string& expected_value,
    const std::string& actual_value,
    const bool required) {
  if (expected_value.empty()) {
    if (required) {
      ELOG_ERROR("[VERIFY] %s: empty, but required!", item_name.c_str());
      return false;
    } else {
      // If it's must required, and empty exepected, means don't care it
      ELOG_DEBUG("[VERIFY] %s: empty, be careful!", item_name.c_str());
      return true;
    }
  }

  // If it's not empty, check actual_value == expected_value
  int64_t actual_int = std::stoi(actual_value);
  int64_t expected_int = std::stoi(expected_value);
  if (actual_int != expected_int) {
    ELOG_ERROR("[VERIFY] %s: Value not equal", item_name.c_str());
    ELOG_DEBUG("    Actual  : %s", actual_value.c_str());
    ELOG_DEBUG("    Expected: %s", expected_value.c_str());
    return false;
  }

  ELOG_DEBUG("[VERIFY] %s: Success", item_name.c_str());
  return true;
}

bool AttestationVerifierInterface::IsIntNotLess(
    const std::string& item_name,
    const std::string& expected_value,
    const std::string& actual_value,
    const bool required) {
  if (expected_value.empty()) {
    if (required) {
      ELOG_ERROR("[VERIFY] %s: empty, but required!", item_name.c_str());
      return false;
    } else {
      // If it's must required, and empty exepected, means don't care it
      ELOG_DEBUG("[VERIFY] %s: empty, be careful!", item_name.c_str());
      return true;
    }
  }

  // If it's not empty, check actual_value >= expected_value
  int64_t actual_int = std::stoi(actual_value);
  int64_t expected_int = std::stoi(expected_value);
  if (actual_int < expected_int) {
    ELOG_ERROR("[VERIFY] %s: Less value", item_name.c_str());
    ELOG_DEBUG("    Actual  : %s", actual_value.c_str());
    ELOG_DEBUG("    Expected: %s", expected_value.c_str());
    return false;
  }

  ELOG_DEBUG("[VERIFY] %s: Success", item_name.c_str());
  return true;
}

bool AttestationVerifierInterface::StrToBool(const std::string& bool_str) {
  return ((bool_str == "true") || (bool_str == "1")) ? true : false;
}

}  // namespace attestation
}  // namespace kubetee
