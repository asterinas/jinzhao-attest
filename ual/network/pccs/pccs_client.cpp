#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <utility>

#include "network/curl_http_client.h"
#include "network/pccs_client.h"
#include "utils/untrusted/untrusted_ua_config.h"

#include "./sgx_dcap_qv_internal.h"

namespace kubetee {
namespace attestation {

// Define the static members
char PccsClient::kCrlCATypePlatform[] = "platform";
char PccsClient::kCrlCATypeProcessor[] = "processor";

PccsClient::PccsClient() {
  pccs_server_url_ = GetPccsUrl();
}

std::string PccsClient::GetPccsUrl(uint16_t tee_type) {
  std::string url = "https://localhost:8081/sgx/certification/v3/";
  std::string base_url =
      UA_ENV_CONF_STR("UA_ENV_PCCS_URL", kUaConfDcapPccsUrl, url);
  if (tee_type == PCCS_TEE_TYPE_TDX) {
    auto found = base_url.find("/sgx/");
    if (found != std::string::npos) {
      base_url = base_url.replace(found, 5, "/tdx/");
    }
  }
  return base_url;
}

// gets the API version of the configured URL.
TeeErrorCode PccsClient::GetApiVersion(int64_t* version) {
  std::smatch result;
  std::regex pattern("/v([1-9][0-9]*)/");
  int64_t api_version = 0;

  try {
    std::string::const_iterator iterStart = pccs_server_url_.begin();
    std::string::const_iterator iterEnd = pccs_server_url_.end();
    if (regex_search(iterStart, iterEnd, result, pattern)) {
      std::string strver = result[0];
      strver = strver.substr(2);
      strver.pop_back();
      std::string::size_type sz;
      api_version = std::stoi(strver, &sz);
    }
  } catch (...) {
    api_version = 0;
  }

  if (api_version == 0) {
    return TEE_ERROR_DCAP_PCCS_UNKNOWN_API_VERSION;
  } else if (api_version == 2) {
    // Keep it consistent with old releases
    *version = 1;
  } else {
    *version = api_version;
  }
  TEE_LOG_DEBUG("API version: %ld", *version);
  return TEE_SUCCESS;
}

TeeErrorCode PccsClient::GetPccsElement(const std::string& url,
                                        const std::string& name,
                                        std::string* element,
                                        std::string* element_issuer_chain) {
  // Send get request to PCCS
  std::string res_body;
  std::string res_header;
  kubetee::attestation::CurlHttpClient curl_http_client;
  TEE_CHECK_RETURN(
      curl_http_client.HttpGet(url, nullptr, &res_body, &res_header));

  // Parse the response header and body
  HttpHeaderMap header_map;
  TEE_CHECK_RETURN(curl_http_client.HttpHeader2Map(res_header, &header_map));
  element->assign(res_body);

  if (!name.empty()) {
    // Get xxxxxx-issuer-chain from HTTP response header
    auto it = header_map.find(name + "-issuer-chain");
    if (it == header_map.end()) {
      TEE_LOG_ERROR("Canot find %s in pccs response header", name.c_str());
      return TEE_ERROR_DCAP_PCCS_RES_HEADER_PARSE;
    }

    TEE_CHECK_RETURN(
        curl_http_client.Unescape(it->second, element_issuer_chain));
    TEE_LOG_TRACE("%s:\n%s", name.c_str(), element->c_str());
    TEE_LOG_TRACE("%s-issuer-chain:\n%s", name.c_str(),
                  element_issuer_chain->c_str());
  }

  return TEE_SUCCESS;
}

TeeErrorCode PccsClient::GetPckCrlChain(const std::string& ca,
                                        std::string* pck_crl,
                                        std::string* pck_crl_issuer_chain) {
  // Check input parameters
  if ((ca != kCrlCATypePlatform) && (ca != kCrlCATypeProcessor)) {
    TEE_LOG_ERROR("Invalid PCK CRL ca value: %s", ca.c_str());
    return TEE_ERROR_PARAMETERS;
  }

  // Initialize https request url
  std::string api = "pckcrl?ca=";
  api.append(ca);

  return GetPccsElement(pccs_server_url_ + api, "sgx-pck-crl", pck_crl,
                        pck_crl_issuer_chain);
}

TeeErrorCode PccsClient::GetTcbInfo(uint16_t tee_type,
                                    const std::string& hex_fmspc,
                                    std::string* tcb_info,
                                    std::string* tcb_info_issuer_chain) {
  // Check input parameters
  // fmspc is always 6 bytes
  if (hex_fmspc.size() != (FMSPC_SIZE * 2)) {
    return TEE_ERROR_PARAMETERS;
  }

  // Initialize https request url
  std::string url = GetPccsUrl(tee_type);
  std::string api = "tcb?fmspc=";
  api.append(hex_fmspc);
  int64_t api_version;
  TEE_CHECK_RETURN(GetApiVersion(&api_version));
  if (api_version == 3) {
    return GetPccsElement(url + api, "sgx-tcb-info", tcb_info,
                          tcb_info_issuer_chain);
  } else {
    return GetPccsElement(url + api, "tcb-info", tcb_info,
                          tcb_info_issuer_chain);
  }
}

TeeErrorCode PccsClient::GetQeIdentity(uint16_t tee_type,
                                       std::string* qe_identity,
                                       std::string* qe_identity_issuer_chain) {
  // Initialize https request url
  std::string url = GetPccsUrl(tee_type);
  std::string api = "qe/identity";
  return GetPccsElement(url + api, "sgx-enclave-identity", qe_identity,
                        qe_identity_issuer_chain);
}

TeeErrorCode PccsClient::GetRootCaCrl(std::string* root_ca_crl) {
  // initialize https request url
  std::string api = "rootcacrl";
  std::string empty_str;
  return GetPccsElement(pccs_server_url_ + api, empty_str, root_ca_crl,
                        &empty_str);
}

TeeErrorCode PccsClient::GetFmspcCaFromQuote(const std::string& quote,
                                             std::string* fmspc_from_quote,
                                             std::string* ca_from_quote) {
  unsigned char fmspc_buf[FMSPC_SIZE] = {'\0'};
  unsigned char ca_buf[CA_SIZE] = {'\0'};
  quote3_error_t qvl_ret =
      qvl_get_fmspc_ca_from_quote(RCCAST(uint8_t*, quote.data()), quote.size(),
                                  fmspc_buf, FMSPC_SIZE, ca_buf, CA_SIZE);
  if (qvl_ret != SGX_QL_SUCCESS) {
    TEE_LOG_ERROR("Fail to get fmspc and ca from quote: %x", qvl_ret);
    return TEE_ERROR_RA_VERIFY_QUOTE_GET_FMSPC_CA;
  }
  kubetee::common::DataBytes fmspc_buf_hex(fmspc_buf, FMSPC_SIZE);
  fmspc_from_quote->assign(fmspc_buf_hex.ToHexStr().GetStr());
  ca_from_quote->assign(RCAST(char*, ca_buf));
  TEE_LOG_DEBUG("CA from quote: %s", ca_from_quote->c_str());
  TEE_LOG_DEBUG("FMSPC from quote: %s", fmspc_from_quote->c_str());
  return TEE_SUCCESS;
}

TeeErrorCode PccsClient::GetCollateral(
    uint16_t tee_type,
    const std::string& quote,
    kubetee::SgxQlQveCollateral* quote_collateral) {
  // get pck_ca hex_fmpsc
  std::string pck_ca;
  std::string hex_fmspc;
  TEE_CHECK_RETURN(GetFmspcCaFromQuote(quote, &hex_fmspc, &pck_ca));
  // Set version
  int64_t api_version;
  TEE_CHECK_RETURN(GetApiVersion(&api_version));
  quote_collateral->set_version(api_version);
  // Set PCK CRL and certchain
  TEE_CHECK_RETURN(
      GetPckCrlChain(pck_ca, quote_collateral->mutable_pck_crl(),
                     quote_collateral->mutable_pck_crl_issuer_chain()));
  // Set TCBInfo and certchain
  TEE_CHECK_RETURN(
      GetTcbInfo(tee_type, hex_fmspc, quote_collateral->mutable_tcb_info(),
                 quote_collateral->mutable_tcb_info_issuer_chain()));
  // Set QEIdentity and certchain
  TEE_CHECK_RETURN(
      GetQeIdentity(tee_type, quote_collateral->mutable_qe_identity(),
                    quote_collateral->mutable_qe_identity_issuer_chain()));
  // Set Root CA CRL
  TEE_CHECK_RETURN(GetRootCaCrl(quote_collateral->mutable_root_ca_crl()));

  return TEE_SUCCESS;
}

TeeErrorCode PccsClient::GetSgxCollateral(
    const std::string& quote, kubetee::SgxQlQveCollateral* quote_collateral) {
  TEE_CHECK_RETURN(GetCollateral(PCCS_TEE_TYPE_SGX, quote, quote_collateral));
  quote_collateral->set_tee_type(PCCS_TEE_TYPE_SGX);
  return TEE_SUCCESS;
}

TeeErrorCode PccsClient::GetTdxCollateral(
    const std::string& quote, kubetee::SgxQlQveCollateral* quote_collateral) {
  TEE_CHECK_RETURN(GetCollateral(PCCS_TEE_TYPE_TDX, quote, quote_collateral));
  quote_collateral->set_tee_type(PCCS_TEE_TYPE_TDX);
  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
