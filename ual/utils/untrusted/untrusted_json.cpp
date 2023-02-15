#include <string>
#include <vector>

#include "attestation/common/asymmetric_crypto.h"
#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "utils/untrusted/untrusted_fs.h"
#include "utils/untrusted/untrusted_json.h"

namespace kubetee {
namespace utils {

JsonConfig* JsonConfig::GetInstance() {
  static JsonConfig instance;
  return &instance;
}
TeeErrorCode JsonConfig::SetSigningPubkey(const std::string& public_key) {
  signing_pubkey_ = public_key;
  return TEE_SUCCESS;
}

bool JsonConfig::CheckString(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsString()) {
    TEE_LOG_INFO("%s is missed or not string in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckString(const rapidjson::Document& conf,
                             const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsString()) {
    TEE_LOG_INFO("%s is missed or not string in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckArray(const rapidjson::Document& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsArray()) {
    TEE_LOG_INFO("%s is missed or not array in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckArray(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsArray()) {
    TEE_LOG_INFO("%s is missed or not array in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckInt(const rapidjson::Document& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsInt()) {
    TEE_LOG_INFO("%s is missed or not integer in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckInt(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsInt()) {
    TEE_LOG_INFO("%s is missed or not integer in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckObj(const rapidjson::Document& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsObject()) {
    TEE_LOG_ERROR("%s is missed or not object in config file", name);
    return false;
  }
  return true;
}

bool JsonConfig::CheckObj(const rapidjson::Value& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsObject()) {
    TEE_LOG_ERROR("%s is missed or not object in config file", name);
    return false;
  }
  return true;
}

std::string JsonConfig::GetStr(const rapidjson::Document& conf,
                               const char* name,
                               const std::string& default_val) {
  if (CheckString(conf, name)) {
    std::string value = conf[name].GetString();
    TEE_LOG_DEBUG("%s=%s", name, value.c_str());
    return value;
  } else {
    TEE_LOG_DEBUG("%s is not string type", name);
    return default_val;
  }
}

std::string JsonConfig::GetStr(const rapidjson::Value& conf,
                               const char* name,
                               const std::string& default_val) {
  if (CheckString(conf, name)) {
    std::string value = conf[name].GetString();
    TEE_LOG_DEBUG("%s=%s", name, value.c_str());
    return value;
  } else {
    TEE_LOG_DEBUG("%s is not string type", name);
    return default_val;
  }
}

TeeErrorCode JsonConfig::GetStrArray(const rapidjson::Document& conf,
                                     const char* name,
                                     std::vector<std::string>* values) {
  if (CheckArray(conf, name)) {
    const rapidjson::Value& val_array = conf[name];
    size_t count = val_array.Size();
    for (size_t i = 0; i < count; i++) {
      if (val_array[i].IsString()) {
        std::string val_str = val_array[i].GetString();
        TEE_LOG_DEBUG("%s[%ld]=%s", name, i, val_str.c_str());
        values->push_back(val_str);
      } else {
        TEE_LOG_ERROR("Invalid string type in Array");
        return TEE_ERROR_PARSE_CONFIGURATIONS;
      }
    }
  } else {
    TEE_LOG_DEBUG("Invalid Array type");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::GetStrArray(const rapidjson::Value& conf,
                                     const char* name,
                                     std::vector<std::string>* values) {
  if (CheckArray(conf, name)) {
    const rapidjson::Value& val_array = conf[name];
    size_t count = val_array.Size();
    for (size_t i = 0; i < count; i++) {
      if (val_array[i].IsString()) {
        std::string val_str = val_array[i].GetString();
        TEE_LOG_DEBUG("%s[%ld]=%s", name, i, val_str.c_str());
        values->push_back(val_str);
      } else {
        TEE_LOG_ERROR("Invalid string type in Array");
        return TEE_ERROR_PARSE_CONFIGURATIONS;
      }
    }
  } else {
    TEE_LOG_DEBUG("Invalid Array type");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::GetInt(const rapidjson::Document& conf,
                                const char* name,
                                int* value) {
  if (!CheckInt(conf, name)) {
    TEE_LOG_ERROR("Not integer type: %s", name);
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  *value = conf[name].GetInt();
  TEE_LOG_DEBUG("%s=%d", name, *value);
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::GetInt(const rapidjson::Value& conf,
                                const char* name,
                                int* value) {
  if (!CheckInt(conf, name)) {
    TEE_LOG_ERROR("Not integer type: %s", name);
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  *value = conf[name].GetInt();
  TEE_LOG_DEBUG("%s=%d", name, *value);
  return TEE_SUCCESS;
}

std::string JsonConfig::GetConfigFilename(const std::string& filename) {
  // First priority, the absolute path filename or file in current directory
  if (FsFileExists(filename)) {
    TEE_LOG_DEBUG("Configuration file: %s", filename.c_str());
    return filename;
  }

  // Then find configuration file in HOME directory
  // NOTE: In some LibOS environment, there is no HOME.
  const char* env_home = getenv("HOME");
  if (env_home) {
    std::string homepath = env_home;
    homepath = homepath + "/" + filename;
    if (FsFileExists(homepath)) {
      TEE_LOG_DEBUG("Configuration file: %s", homepath.c_str());
      return homepath;
    }
  }

  // Finally, try to find configuration file in /etc directory
  std::string etcpath = "/etc/kubetee/";
  etcpath += filename;
  if (FsFileExists(etcpath)) {
    TEE_LOG_DEBUG("Configuration file: %s", etcpath.c_str());
    return etcpath;
  }

  // If cannot find configuration file, return empty string
  TEE_LOG_ERROR("Cannot find configuration file: %s", filename.c_str());
  return "";
}

std::string JsonConfig::ParseSignedConfiguration(const JsonDocumentPtr& doc) {
  rapidjson::Document* conf = doc.get();
  const std::string config_empty = "";

  // Firstly, try to get each section
  std::string config_b64 = GetStr(*conf, kConfSignedConf);
  if (config_b64.empty()) {
    TEE_LOG_ERROR("Fail to read configuration section");
    return config_empty;
  }
  std::string hash_hex = GetStr(*conf, kConfSignedHash);
  if (hash_hex.empty()) {
    TEE_LOG_ERROR("Fail to read hash section");
    return config_empty;
  }
  std::string sig_b64 = GetStr(*conf, kConfSignedSig);
  if (sig_b64.empty()) {
    TEE_LOG_ERROR("Fail to read signature section");
    return config_empty;
  }

  // parse the configuration section
  kubetee::common::DataBytes config(config_b64);
  std::string config_str = config.FromBase64().GetStr();
  TEE_LOG_DEBUG("configurations: %s", config_str.c_str());

  // Generate the hash and check the signature and value
  if (!config.ToSHA256().ToHexStr().Compare(hash_hex)) {
    TEE_LOG_DEBUG("Calculated Hash value: %s", config.GetStr().c_str());
    TEE_LOG_ERROR("Mismatch between calculated hash value and given one");
    return config_empty;
  }

  kubetee::common::DataBytes sig_vec(sig_b64);
  std::string sig = sig_vec.FromBase64().GetStr();
  if (signing_pubkey_.empty()) {
    TEE_LOG_ERROR("Signing public key is empty");
    return config_empty;
  }
  TeeErrorCode ret =
      kubetee::common::AsymmetricCrypto::Verify(signing_pubkey_, hash_hex, sig);
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to verify hash value signature");
    return config_empty;
  }

  return config_str;
}

TeeErrorCode JsonConfig::LoadConfiguration(const std::string& filename) {
  if (filename.empty()) {
    TEE_LOG_ERROR("Empty configuration file name");
    return TEE_ERROR_CONF_NOTEXIST;
  }

  std::string config_file = GetConfigFilename(filename);
  if (config_file.empty()) {
    TEE_LOG_ERROR("Fail to find configuration file");
    return TEE_ERROR_CONF_NOTEXIST;
  }

  std::string config_str;
  if (FsReadString(config_file, &config_str) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to read configuration file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  JsonDocumentPtr doc(new rapidjson::Document);
  if (doc.get()->Parse(config_str.data()).HasParseError()) {
    TEE_LOG_ERROR("Fail to parse json configration file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  std::string is_signed = GetStr(*doc.get(), kConfSignedCheck, "false");
  if (is_signed == "true") {
    TEE_LOG_INFO("Parsing the signed configurations file ...");
    std::string config_str_signed = ParseSignedConfiguration(doc);
    JsonDocumentPtr doc_signed(new rapidjson::Document);
    if (doc_signed.get()->Parse(config_str_signed.data()).HasParseError()) {
      TEE_LOG_ERROR("Fail to parse signed configration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
    cfgs_.emplace(filename, doc_signed);
  } else {
    // Support both signed and unsigned configurations, but only signed
    // configurations in release mode.
#if defined(DEBUG) || defined(EDEBUG)
    cfgs_.emplace(filename, doc);
#else
    TEE_LOG_WARN("Please use signed configuration file in release mode");
    cfgs_.emplace(filename, doc);
    // return TEE_ERROR_PARSE_CONFIGURATIONS;
    // TEE_LOG_ERROR("Please use signed configuration file in release mode");
    // return TEE_ERROR_PARSE_CONFIGURATIONS;
#endif
  }

  TEE_LOG_INFO("Load configuration file %s successfully", filename.c_str());
  return TEE_SUCCESS;
}

TeeErrorCode JsonConfig::ClearConfigCache(const std::string& conf_file) {
  TEE_LOG_DEBUG("Clear config file caches:  %s", conf_file.c_str());
  if (cfgs_.find(conf_file) == cfgs_.end()) {
    TEE_LOG_ERROR("Clear conf file cache: %s, failed", conf_file.c_str());
    return TEE_ERROR_CONF_NOTEXIST;
  }
  cfgs_.erase(conf_file);
  return TEE_SUCCESS;
}

std::string JsonConfig::ConfGetStr(const std::string& conf_file,
                                   const char* name,
                                   const std::string& default_val) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_DEBUG("Load config failed, set %s to default value", name);
      return default_val;
    }
  }

  return GetStr(*cfgs_[conf_file].get(), name, default_val);
}

TeeErrorCode JsonConfig::ConfGetStrArray(const std::string& conf_file,
                                         const char* name,
                                         std::vector<std::string>* values) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_DEBUG("Fail to load configuration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
  }

  return GetStrArray(*cfgs_[conf_file].get(), name, values);
}

TeeErrorCode JsonConfig::ConfGetInt(const std::string& conf_file,
                                    const char* name,
                                    int* value) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_ERROR("Fail to load configuration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
  }

  return GetInt(*cfgs_[conf_file].get(), name, value);
}

rapidjson::Document* JsonConfig::GetJsonConf(const std::string& conf_file) {
  TEE_LOG_DEBUG("Get json configuration %s", conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_ERROR("Fail to load configuration file");
      return nullptr;
    }
  }

  return cfgs_[conf_file].get();
}

}  // namespace utils
}  // namespace kubetee

using kubetee::utils::JsonConfig;

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode JsonConfigSetSigningPubKey(const std::string& public_key) {
  return JsonConfig::GetInstance()->SetSigningPubkey(public_key);
}

TeeErrorCode JsonConfigClearConfigCache(const std::string& conf_file) {
  return JsonConfig::GetInstance()->ClearConfigCache(conf_file);
}

std::string GetConfStr(const std::string& conf_file,
                       const char* name,
                       const std::string& default_value) {
  return JsonConfig::GetInstance()->ConfGetStr(conf_file, name, default_value);
}

std::string GetConfFileStr(const std::string& conf_file,
                           const char* name,
                           const std::string& default_value) {
  std::string conf_value;
  std::string path = JsonConfig::GetInstance()->ConfGetStr(conf_file, name, "");
  if (TEE_SUCCESS != kubetee::utils::FsReadString(path, &conf_value)) {
    TEE_LOG_WARN("Fail to load %s from file %s", name, path.c_str());
    conf_value.assign(default_value);
  }
  return conf_value;
}

TeeErrorCode GetConfStrArray(const std::string& conf_file,
                             const char* name,
                             std::vector<std::string>* values) {
  return JsonConfig::GetInstance()->ConfGetStrArray(conf_file, name, values);
}

TeeErrorCode GetConfInt(const std::string& conf_file,
                        const char* name,
                        int* value) {
  return JsonConfig::GetInstance()->ConfGetInt(conf_file, name, value);
}

/// Get the configuration from environment variable or configuration file
std::string GetEnvConfStr(const char* conf_file,
                          const char* env_name,
                          const char* conf_name,
                          const std::string& default_value) {
  std::string conf_value;
  // The environment variable has higer priority than configuraiton file
  const char* env_value = getenv(env_name);
  if (env_value) {
    TEE_LOG_DEBUG("Get environment variable: %s=%s", env_name, env_value);
    conf_value.assign(env_value);
  } else {
    conf_value.assign(GetConfStr(conf_file, conf_name));
    TEE_LOG_DEBUG("Get configuration: %s=%s", conf_name, conf_value.c_str());
  }
  if (conf_value.empty()) {
    conf_value.assign(default_value);
    TEE_LOG_DEBUG("Default configuration: %s=%s", conf_name,
                  conf_value.c_str());
  }

  return conf_value;
}

std::string GetEnvConfFileStr(const char* conf_file,
                              const char* env_name,
                              const char* conf_name,
                              const std::string& default_value) {
  std::string conf_value;
  std::string path;
  // The environment variable has higer priority than configuraiton file
  const char* env_path = getenv(env_name);
  if (env_path) {
    TEE_LOG_DEBUG("Get environment variable: %s=%s", env_name, env_path);
    path.assign(env_path);
  } else {
    path.assign(GetConfStr(conf_file, conf_name));
    TEE_LOG_DEBUG("Get configuration path: %s=%s", conf_name, path.c_str());
  }
  if (TEE_SUCCESS != kubetee::utils::FsReadString(path, &conf_value)) {
    TEE_LOG_WARN("Fail to load %s from file %s", conf_name, path.c_str());
    conf_value.assign(default_value);
  }

  return conf_value;
}

#ifdef __cplusplus
}
#endif
