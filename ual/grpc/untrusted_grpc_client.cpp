#include <memory>
#include <string>

// Header files in unified attestation
#include "utils/untrusted/untrusted_fs.h"

#include "grpc/untrusted_grpc_client.h"

namespace kubetee {
namespace untrusted {

std::shared_ptr<grpc::Channel> TeeGrpcClient::CreateChannel(
    const std::string& endpoint,
    const std::string& ssl_secure,
    const std::string& ssl_ca,
    const std::string& ssl_key,
    const std::string& ssl_cert) {
  if (IsSecureChannel(ssl_secure)) {
    return CreateSecureChannel(endpoint, ssl_ca, ssl_key, ssl_cert);
  } else {
    return CreateInsecureChannel(endpoint);
  }
}

std::shared_ptr<grpc::Channel> TeeGrpcClient::CreateInsecureChannel(
    const std::string& endpoint) {
  std::shared_ptr<grpc::Channel> channel;
  auto insecure_creds = grpc::InsecureChannelCredentials();
  channel = grpc::CreateChannel(endpoint, insecure_creds);
  TEE_LOG_INFO("Create insecure channel to %s", endpoint.c_str());

  if (!WaitChannelReady(channel)) {
    // throw std::runtime_error("GRPC channel is not ready.");
    TEE_LOG_ERROR("Invalid server settings or GRPC channel is not ready.");
  }
  return channel;
}

std::shared_ptr<grpc::Channel> TeeGrpcClient::CreateSecureChannel(
    const std::string& endpoint,
    const std::string& ssl_ca,
    const std::string& ssl_key,
    const std::string& ssl_cert) {
  std::shared_ptr<grpc::Channel> channel;
  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = ssl_ca;
  ssl_opts.pem_private_key = ssl_key;
  ssl_opts.pem_cert_chain = ssl_cert;
  auto creds = grpc::SslCredentials(ssl_opts);

  // For our generated certificates CN.
  auto channel_args = grpc::ChannelArguments();
  constexpr char kSelfSignedCN[] = "enclave-service";
  channel_args.SetSslTargetNameOverride(kSelfSignedCN);

  channel = grpc::CreateCustomChannel(endpoint, creds, channel_args);
  TEE_LOG_INFO("Create secure channel to %s", endpoint.c_str());

  if (!WaitChannelReady(channel)) {
    // throw std::runtime_error("GRPC channel is not ready.");
    TEE_LOG_ERROR("Invalid server settings or GRPC channel is not ready.");
  }
  return channel;
}

bool TeeGrpcClient::WaitChannelReady(std::shared_ptr<grpc::Channel> channel) {
  using std::chrono::system_clock;
  grpc_connectivity_state state;
  constexpr int kTimeoutMs = 1000;
  while ((state = channel->GetState(true)) != GRPC_CHANNEL_READY) {
    system_clock::time_point now = system_clock::now();
    system_clock::time_point end = now + std::chrono::milliseconds(kTimeoutMs);
    if (!channel->WaitForStateChange(state, end)) {
      return false;
    }
  }
  return true;
}

TeeErrorCode TeeGrpcClient::CheckStatusCode(const grpc::Status& status) {
  if (!status.ok()) {
    TEE_LOG_ERROR("Status Code: %d", status.error_code());
    TEE_LOG_ERROR("Error Message: %s", status.error_message().c_str());
    return TEE_ERROR_GRPC_CLIENT_STATUS_ERROR;
  }
  return TEE_SUCCESS;
}

TeeErrorCode TeeGrpcClient::CheckStatusCode(const grpc::Status& status,
                                            const char* func) {
  if (!status.ok()) {
    TEE_LOG_ERROR("[%s] Status Code: %d", func, status.error_code());
    TEE_LOG_ERROR("Error Message: %s", status.error_message().c_str());
    return TEE_ERROR_GRPC_CLIENT_STATUS_ERROR;
  }
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace kubetee
