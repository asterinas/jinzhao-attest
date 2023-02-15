#ifndef UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_UA_CONFIG_H_
#define UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_UA_CONFIG_H_

#include <string>

#include "utils/untrusted/untrusted_json.h"

constexpr char kUaConfFile[] = "unified_attestation.json";

constexpr char kUaConfIasUrl[] = "ua_ias_url";
constexpr char kUaConfIasSpid[] = "ua_ias_spid";
constexpr char kUaConfIasApiKey[] = "ua_ias_api_key";

constexpr char kUaConfDcapLibPath[] = "ua_dcap_lib_path";
constexpr char kUaConfDcapPccsUrl[] = "ua_dcap_pccs_url";

constexpr char kUaConfUasUrl[] = "ua_uas_url";
constexpr char kUaConfUasAppKey[] = "ua_uas_app_key";
constexpr char kUaConfUasAppSecret[] = "ua_uas_app_secret";

constexpr char kUaConfUapPlatform[] = "ua_policy_str_tee_platform";
constexpr char kUaConfUapPlatformHwVer[] = "ua_policy_hex_platform_hw_version";
constexpr char kUaConfUapPlatformSwVer[] = "ua_policy_hex_platform_sw_version";
constexpr char kUaConfUapSecureFlags[] = "ua_policy_hex_secure_flags";
constexpr char kUaConfUapMrPlatform[] = "ua_policy_hex_platform_measurement";
constexpr char kUaConfUapMrBoot[] = "ua_policy_hex_boot_measurement";
constexpr char kUaConfUapTeeID[] = "ua_policy_str_tee_identity";
constexpr char kUaConfUapMrTa[] = "ua_policy_hex_ta_measurement";
constexpr char kUaConfUapMrTaDyn[] = "ua_policy_hex_ta_dyn_measurement";
constexpr char kUaConfUapSigner[] = "ua_policy_hex_signer";
constexpr char kUaConfUapProdId[] = "ua_policy_hex_prod_id";
constexpr char kUaConfUapMinIsvSvn[] = "ua_policy_str_min_isvsvn";
constexpr char kUaConfUapUserData[] = "ua_policy_hex_user_data";
constexpr char kUaConfUapDebugDisabled[] = "ua_policy_bool_debug_disabled";
constexpr char kUaConfUapPubkeyOrHash[] = "ua_policy_hex_hash_or_pem_pubkey";
constexpr char kUaConfUapNonce[] = "ua_policy_hex_nonce";
constexpr char kUaConfUapSpid[] = "ua_policy_hex_spid";

#define UA_CONF_STR(cn) GetConfStr(kUaConfFile, cn)
#define UA_CONF_FILE_STR(cn) GetConfFileStr(kUaConfFile, cn)

#define UA_ENV_CONF_STR(en, cn, d) GetEnvConfStr(kUaConfFile, (en), (cn), (d))
#define UA_ENV_CONF_FILE_STR(en, cn, d) \
  GetEnvConfFileStr(kUaConfFile, (en), (cn), (d))

#endif  // UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_UA_CONFIG_H_
