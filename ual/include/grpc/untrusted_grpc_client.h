#ifndef UAL_INCLUDE_GRPC_UNTRUSTED_GRPC_CLIENT_H_
#define UAL_INCLUDE_GRPC_UNTRUSTED_GRPC_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "utils/untrusted/untrusted_json.h"

#define CHECK_STATUS(s) CheckStatusCode((s), __FUNCTION__)

namespace kubetee {
namespace untrusted {

class TeeGrpcClient {
 public:
  std::shared_ptr<grpc::Channel> CreateChannel(const std::string& endpoint,
                                               const std::string& ssl_secure,
                                               const std::string& ssl_ca,
                                               const std::string& ssl_key,
                                               const std::string& ssl_cert);
  std::shared_ptr<grpc::Channel> CreateInsecureChannel(
      const std::string& endpoint);
  std::shared_ptr<grpc::Channel> CreateSecureChannel(
      const std::string& endpoint,
      const std::string& ssl_ca,
      const std::string& ssl_key,
      const std::string& ssl_cert);

  TeeErrorCode CheckStatusCode(const grpc::Status& status);
  TeeErrorCode CheckStatusCode(const grpc::Status& status, const char* func);

  bool IsSecureChannel(const std::string& ssl_secure) {
    return (ssl_secure == kConfValueEnable);
  }

 private:
  bool WaitChannelReady(std::shared_ptr<grpc::Channel> channel);
};

}  // namespace untrusted
}  // namespace kubetee

#endif  // UAL_INCLUDE_GRPC_UNTRUSTED_GRPC_CLIENT_H_
