#include <memory>
#include <string>

// Header files in unified attestation
#include "utils/untrusted/untrusted_fs.h"

#include "grpc/untrusted_grpc_server.h"

constexpr int kTimeoutMs = 10000;

namespace kubetee {
namespace untrusted {

std::shared_ptr<grpc::ServerBuilder> TeeGrpcServer::CreateBuilder(
    const std::string& server_addr,
    const std::string& ssl_secure,
    const std::string& ssl_ca,
    const std::string& ssl_key,
    const std::string& ssl_cert) {
  if (IsSecureChannel(ssl_secure)) {
    return CreateSecureBuilder(server_addr, ssl_ca, ssl_key, ssl_cert);
  } else {
    return CreateInsecureBuilder(server_addr);
  }
}

std::shared_ptr<grpc::ServerBuilder> TeeGrpcServer::CreateInsecureBuilder(
    const std::string& server_addr) {
  // Listen on the given address without authentication mechanism.
  auto builder = std::shared_ptr<grpc::ServerBuilder>(new grpc::ServerBuilder);
  builder->AddListeningPort(server_addr, grpc::InsecureServerCredentials());
  return builder;
}

std::shared_ptr<grpc::ServerBuilder> TeeGrpcServer::CreateSecureBuilder(
    const std::string& server_addr,
    const std::string& ssl_ca,
    const std::string& ssl_key,
    const std::string& ssl_cert) {
  // Listen on the given address with authentication mechanism.
  auto builder = std::shared_ptr<grpc::ServerBuilder>(new grpc::ServerBuilder);
  SslServerCredentialsOptions::PemKeyCertPair keycert{ssl_key, ssl_cert};
  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = ssl_ca;
  ssl_opts.pem_key_cert_pairs.push_back(keycert);
  ssl_opts.client_certificate_request =
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
  builder->AddListeningPort(server_addr, grpc::SslServerCredentials(ssl_opts));
  return builder;
}

}  // namespace untrusted
}  // namespace kubetee
