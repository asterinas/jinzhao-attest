#ifndef UAL_INCLUDE_ATTESTATION_COMMON_BYTES_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_BYTES_H_

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "attestation/common/error.h"
#include "attestation/common/type.h"

constexpr size_t kSha256Size = 32;

namespace kubetee {
namespace common {

class DataBytes : public std::vector<uint8_t> {
 public:
  // Constructor without any initialization
  DataBytes() {}

  // Constructor based on another vector
  explicit DataBytes(const std::vector<uint8_t>& value) {
    std::vector<uint8_t>::assign(value.begin(), value.end());
  }

  // Constructor based on a normal string
  explicit DataBytes(const std::string& value) {
    std::vector<uint8_t>::assign(value.begin(), value.end());
  }

  // Constructor based on buffer end with '\'
  explicit DataBytes(const char* buf) {
    std::string temp(buf);
    std::vector<uint8_t>::assign(temp.begin(), temp.end());
  }

  // Constructor based on buffer and length
  DataBytes(const uint8_t* buf, size_t len) {
    std::string temp(RCAST(const char*, buf), len);
    std::vector<uint8_t>::assign(temp.begin(), temp.end());
  }

  // Constructor based on size of specified character
  DataBytes(const size_t size, uint8_t ch) {
    std::vector<uint8_t>::assign(size, ch);
  }

  // Constructor based on zero initialized size
  explicit DataBytes(const size_t size) {
    std::vector<uint8_t>::assign(size, 0);
  }

  // Update value from C string
  void SetValue(const char* value) {
    std::string temp = value;
    assign(temp.begin(), temp.end());
  }

  // Update value from buffer and length
  void SetValue(const uint8_t* buf, const size_t len) {
    std::string temp(RCAST(const char*, buf), len);
    assign(temp.begin(), temp.end());
  }

  // Update value from C++ string
  void SetValue(const std::string& value) {
    assign(value.begin(), value.end());
  }

  // Update value from vector<uint8_t>
  void SetValue(const std::vector<uint8_t>& value) {
    assign(value.begin(), value.end());
  }

  // From hex string to bytes
  DataBytes& FromHexStr();

  // From bytes to hex string
  DataBytes& ToHexStr(bool inverted = false);

  // From base64 string to bytes
  DataBytes& FromBase64();

  // From bytes to base64 string
  DataBytes& ToBase64();

  // From bytes to SHA256
  DataBytes& ToSHA256();

  // Fill with random data
  DataBytes& Randomize(const size_t len);

  // Export bytes data to buffer
  DataBytes& Export(uint8_t* buf, const size_t max_buf_len);

  // Return the string format
  std::string GetStr();

  // Return the C format string, from begin to '\0'
  std::string GetCharStr();

  // Get Hexstring SHA256 value of data
  static std::string SHA256HexStr(const unsigned char* data, const size_t size);
  static std::string SHA256HexStr(const std::string& plain) {
    return SHA256HexStr(RCCAST(const unsigned char*, plain.data()),
                        plain.size());
  }

  // Get Hexstring SHA256 value of data
  std::string GetSHA256HexStr();

  // Compare to other memeory instances
  bool Compare(const uint8_t* buf, size_t len);
  bool Compare(const std::string& str);
  bool Compare(const std::vector<uint8_t>& vec);

  // For no return value statements;
  void Void() {}

  // Secure clear the content
  void SecureClear() {
    memset(data(), 0, size());
    clear();
  }

  // Return the final error code
  TeeErrorCode GetError() {
    if (error_code_ != TEE_SUCCESS) {
      return error_code_;
    } else if (empty()) {
      return TEE_ERROR_BYTES_UNEXPECTED_EMPTY;
    } else {
      return TEE_SUCCESS;
    }
  }

 private:
  // internal methods for hex string
  static uint8_t Hex2Dec(const uint8_t hex);
  static uint8_t Dec2Hex(const uint8_t dec);

  // Set internal error code and clear all data by default.
  void inline SetErrorAndClear(TeeErrorCode error) {
    error_code_ = error;
    SecureClear();
  }

  TeeErrorCode error_code_ = TEE_SUCCESS;
};

}  // namespace common
}  // namespace kubetee

using DataBytes = kubetee::common::DataBytes;

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_BYTES_H_
