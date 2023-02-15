#ifndef UAL_INCLUDE_GRPC_UNTRUSTED_GRPC_SERVER_H_
#define UAL_INCLUDE_GRPC_UNTRUSTED_GRPC_SERVER_H_

#include <grpcpp/grpcpp.h>

#include <memory>
#include <string>

#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "utils/untrusted/untrusted_json.h"

#define RETURN_ERROR_STATUS(err, msg)                                       \
  if ((err) != TEE_SUCCESS) {                                               \
    constexpr size_t kMaxMsgBufSize = 4096;                                 \
    char buf[kMaxMsgBufSize] = {'\0'};                                      \
    snprintf(buf, kMaxMsgBufSize, "%s | Error code: 0x%08X", (msg), (err)); \
    TEE_LOG_ERROR("%s", buf);                                               \
    return Status(grpc::StatusCode::INTERNAL, buf);                         \
  }

#define GRPC_INTERFACE_ENTER_DEBUG() \
  TEE_LOG_DEBUG("GRPC SERVER INTERFACE ENTER:%s", __FUNCTION__)
#define GRPC_INTERFACE_EXIT_DEBUG() \
  TEE_LOG_DEBUG("GRPC SERVER INTERFACE EXIT:%s", __FUNCTION__)

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCredentials;
using grpc::SslServerCredentials;
using grpc::SslServerCredentialsOptions;
using grpc::Status;

namespace kubetee {
namespace untrusted {

class TeeGrpcServer {
 public:
  std::shared_ptr<grpc::ServerBuilder> CreateBuilder(
      const std::string& server_addr,
      const std::string& ssl_secure,
      const std::string& ssl_ca,
      const std::string& ssl_key,
      const std::string& ssl_cert);
  std::shared_ptr<grpc::ServerBuilder> CreateInsecureBuilder(
      const std::string& server_addr);
  std::shared_ptr<grpc::ServerBuilder> CreateSecureBuilder(
      const std::string& server_addr,
      const std::string& ssl_ca,
      const std::string& ssl_key,
      const std::string& ssl_cert);

  bool IsSecureChannel(const std::string& ssl_secure) {
    return (ssl_secure == kConfValueEnable);
  }
};

}  // namespace untrusted
}  // namespace kubetee

#endif  // UAL_INCLUDE_GRPC_UNTRUSTED_GRPC_SERVER_H_
