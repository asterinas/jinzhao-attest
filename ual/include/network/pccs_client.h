#ifndef UAL_INCLUDE_NETWORK_PCCS_CLIENT_H_
#define UAL_INCLUDE_NETWORK_PCCS_CLIENT_H_

#include <map>
#include <memory>
#include <string>

#include "curl/curl.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/type.h"

#include "./pccs.pb.h"

#define QE3_ID_SIZE 16
#define ENC_PPID_SIZE 384
#define CPUSVN_SIZE 16
#define PCESVN_SIZE 2
#define PCEID_SIZE 2
#define FMSPC_SIZE 6
#define PLATFORM_MANIFEST_SIZE 53000

namespace kubetee {
namespace attestation {

// PCCS client for SGX DCAP remote attestation mode
class PccsClient {
 public:
  PccsClient();

  static char kCrlCATypePlatform[];
  static char kCrlCATypeProcessor[];

  /// Get PCK CRL chain from PCCS server
  TeeErrorCode GetPckCrlChain(const std::string& ca,
                              std::string* pck_crl,
                              std::string* pck_crl_issuer_chain);
  /// Get TCB information from PCCS server
  TeeErrorCode GetTcbInfo(const std::string& hex_fmspc,
                          std::string* tcb_info,
                          std::string* tcb_info_issuer_chain);
  /// Get QE identity from PCCS server
  /// Currently only 0 (ECDSA QE) is supported
  TeeErrorCode GetQeIdentity(std::string* qe_identity,
                             std::string* qe_identity_issuer_chain);
  /// Get CA CRL from PCCS server
  /// Currently only 0 (ECDSA QE) is supported
  TeeErrorCode GetRootCaCrl(std::string* root_ca_crl);

  /// Get quote verification collateral (all aboves together)
  TeeErrorCode GetCollateral(const std::string& quote,
                             kubetee::SgxQlQveCollateral* quote_collateral);

 private:
  std::string GetPccsUrl();
  TeeErrorCode GetApiVersion(int64_t* version);
  TeeErrorCode GetFmspcCaFromQuote(const std::string& quote,
                                   std::string* fmspc_from_quote,
                                   std::string* ca_from_quote);
  TeeErrorCode GetPccsElement(const std::string& url,
                              const std::string& name,
                              std::string* element,
                              std::string* element_issuer_chain);
  std::string pccs_server_url_;
};

}  // namespace attestation
}  // namespace kubetee

#endif  // UAL_INCLUDE_NETWORK_PCCS_CLIENT_H_
