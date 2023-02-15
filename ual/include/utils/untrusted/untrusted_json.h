#ifndef UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_JSON_H_
#define UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_JSON_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rapidjson/document.h"

#include "attestation/common/error.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace utils {

constexpr char kConfSignedCheck[] = "configurations_is_signed";
constexpr char kConfSignedConf[] = "configurations";
constexpr char kConfSignedHash[] = "hash";
constexpr char kConfSignedSig[] = "signature";

typedef std::shared_ptr<rapidjson::Document> JsonDocumentPtr;
typedef std::map<std::string, JsonDocumentPtr> JsonConfigurationsMap;

class JsonConfig {
 public:
  // Gets the singleton UnitTest object.
  static JsonConfig* GetInstance();

  // This is only required if signed configuration is used
  TeeErrorCode SetSigningPubkey(const std::string& public_key);

  // Clear the loaded configuration file from the map
  // It will be reload again when access it next time
  TeeErrorCode ClearConfigCache(const std::string& conf_file);

  // To support both rapidjson::Document and rapidjson::Value
  static bool CheckString(const rapidjson::Document& conf, const char* name);
  static bool CheckString(const rapidjson::Value& conf, const char* name);
  static bool CheckArray(const rapidjson::Document& conf, const char* name);
  static bool CheckArray(const rapidjson::Value& conf, const char* name);
  static bool CheckInt(const rapidjson::Document& conf, const char* name);
  static bool CheckInt(const rapidjson::Value& conf, const char* name);
  static bool CheckObj(const rapidjson::Document& conf, const char* name);
  static bool CheckObj(const rapidjson::Value& conf, const char* name);
  static std::string GetStr(const rapidjson::Document& conf,
                            const char* name,
                            const std::string& default_val = "");
  static std::string GetStr(const rapidjson::Value& conf,
                            const char* name,
                            const std::string& default_val = "");
  static TeeErrorCode GetStrArray(const rapidjson::Document& conf,
                                  const char* name,
                                  std::vector<std::string>* values);
  static TeeErrorCode GetStrArray(const rapidjson::Value& conf,
                                  const char* name,
                                  std::vector<std::string>* values);
  static TeeErrorCode GetInt(const rapidjson::Document& conf,
                             const char* name,
                             int* value);
  static TeeErrorCode GetInt(const rapidjson::Value& conf,
                             const char* name,
                             int* value);

  // Load configuration files and then parse and get value(s)
  std::string ConfGetStr(const std::string& conf_file,
                         const char* name,
                         const std::string& default_val = "");
  TeeErrorCode ConfGetStrArray(const std::string& conf_file,
                               const char* name,
                               std::vector<std::string>* values);
  TeeErrorCode ConfGetInt(const std::string& conf_file,
                          const char* name,
                          int* value);
  rapidjson::Document* GetJsonConf(const std::string& conf_file);

 private:
  // Hide construction functions
  JsonConfig() {}
  JsonConfig(const JsonConfig&);
  void operator=(JsonConfig const&);

  std::string GetConfigFilename(const std::string& filename);
  TeeErrorCode LoadConfiguration(const std::string& filename);
  std::string ParseSignedConfiguration(const JsonDocumentPtr& doc);

  JsonConfigurationsMap cfgs_;
  std::string signing_pubkey_;
};

}  // namespace utils
}  // namespace kubetee

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_CONF_STR(filename, name) GetConfStr((filename), (name))
#define JSON_CONF_ARRAY(filename, name, value) \
  GetConfStrArray((filename), (name), (value))
#define JSON_CONF_INT(filename, name, value) \
  GetConfInt((filename), (name), (value))

constexpr char kConfValueEnable[] = "enable";
constexpr char kConfValueDisable[] = "disable";
constexpr char kConfValueTrue[] = "true";
constexpr char kConfValueFalse[] = "false";

TeeErrorCode JsonConfigSetSigningPubKey(const std::string& public_key);
TeeErrorCode JsonConfigClearConfigCache(const std::string& conf_file);

std::string GetConfStr(const std::string& conf_file,
                       const char* name,
                       const std::string& default_value = "");
std::string GetConfFileStr(const std::string& conf_file,
                           const char* name,
                           const std::string& default_value = "");
TeeErrorCode GetConfStrArray(const std::string& conf_file,
                             const char* name,
                             std::vector<std::string>* values);
TeeErrorCode GetConfInt(const std::string& conf_file,
                        const char* name,
                        int* value);

std::string GetEnvConfStr(const char* conf_file,
                          const char* env_name,
                          const char* conf_name,
                          const std::string& default_value = "");
std::string GetEnvConfFileStr(const char* conf_file,
                              const char* env_name,
                              const char* conf_name,
                              const std::string& default_value = "");

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_JSON_H_
