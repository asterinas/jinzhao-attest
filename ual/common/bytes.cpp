#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "cppcodec/base64_rfc4648.hpp"

#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include "attestation/common/bytes.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace common {

using base64 = cppcodec::base64_rfc4648;

uint8_t DataBytes::Hex2Dec(const uint8_t hex) {
  if (('0' <= hex) && (hex <= '9')) {
    return hex - '0';
  } else if (('a' <= hex) && (hex <= 'f')) {
    return hex - 'a' + 10;
  } else if (('A' <= hex) && (hex <= 'F')) {
    return hex - 'A' + 10;
  } else {
    // Otherwise return zero for none HEX character
    return 0;
  }
}

uint8_t DataBytes::Dec2Hex(const uint8_t dec) {
  static const char* hex_digits = "0123456789ABCDEF";
  return hex_digits[dec & 0x0F];
}

// Decode from hex string to bytes
DataBytes& DataBytes::FromHexStr() {
  const size_t len = size() / 2;
  const uint8_t* pbuf = data();
  std::vector<uint8_t> dst(len);
  for (size_t i = 0; i < len; i++) {
    dst[i] = (Hex2Dec(pbuf[i * 2]) << 4) + (Hex2Dec(pbuf[i * 2 + 1]));
  }
  assign(dst.begin(), dst.end());
  return *this;
}

// Encode from data bytes to hex string
DataBytes& DataBytes::ToHexStr(bool inverted) {
  const size_t len = size();
  const uint8_t* buf = data();
  std::string dst(len * 2, '\0');
  for (size_t i = 0; i < len; i++) {
    int j = inverted ? (len - 1 - i) : i;
    dst[i * 2] = Dec2Hex(buf[j] >> 4);
    dst[i * 2 + 1] = Dec2Hex(buf[j]);
  }
  assign(dst.begin(), dst.end());
  return *this;
}

// Decode from base64 string to bytes
DataBytes& DataBytes::FromBase64() {
  try {
    std::string b64_str(RCAST(const char*, data()), size());
    std::vector<uint8_t> b64_decoded = base64::decode(b64_str);
    assign(b64_decoded.begin(), b64_decoded.end());
  } catch (std::exception& e) {
    TEE_LOG_ERROR("Fail to decode base64 string: %s", e.what());
    SetErrorAndClear(TEE_ERROR_BYTES_BASE64_DECODE);
  }
  return *this;
}

// Encode from bytes to base64 string
DataBytes& DataBytes::ToBase64() {
  std::string b64_str = base64::encode(data(), size());
  if (b64_str.empty()) {
    SetErrorAndClear(TEE_ERROR_BYTES_BASE64_ENCODE);
  } else {
    assign(b64_str.begin(), b64_str.end());
  }
  return *this;
}

// From bytes to it's hash
DataBytes& DataBytes::ToSHA256() {
  do {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
      ELOG_ERROR("Fail to do SHA256_Init");
      SetErrorAndClear(TEE_ERROR_BYTES_SHA256);
      break;
    }
    if (!SHA256_Update(&sha256, data(), size())) {
      ELOG_ERROR("Fail to do SHA256_Update");
      SetErrorAndClear(TEE_ERROR_BYTES_SHA256);
      break;
    }
    if (!SHA256_Final(hash.data(), &sha256)) {
      ELOG_ERROR("Fail to do SHA256_Final");
      SetErrorAndClear(TEE_ERROR_BYTES_SHA256);
      break;
    }
    assign(hash.begin(), hash.end());
  } while (0);

  return *this;
}

// Fill with random data of specified length
DataBytes& DataBytes::Randomize(const size_t len) {
  resize(len);
  if (RAND_bytes(data(), size()) != OPENSSL_SUCCESS) {
    ELOG_ERROR("Fail to create random data bytes");
    SetErrorAndClear(TEE_ERROR_BYTES_RAND);
  }
  return *this;
}

// Export bytes data to buffer
DataBytes& DataBytes::Export(uint8_t* buf, size_t max_buf_len) {
  if (max_buf_len < size()) {
    // don't clear data if the output buffer is too small
    error_code_ = TEE_ERROR_BYTES_EXPORT_SMALL_BUFFER;
  } else {
    std::copy(begin(), end(), buf);
  }
  return *this;
}

// Return the string format
std::string DataBytes::GetStr() {
  return std::string(RCAST(const char*, data()), size());
}

// Return the C string, from begin to first '\0'(maybe in middle of data)
std::string DataBytes::GetCharStr() {
  if (size()) {     // it's not empty and should have tail '\0'
    *rbegin() = 0;  // In case that the string have no tail '\0'
  }
  return std::string(RCAST(const char*, data()));
}

// Return the Hex string of the SHA256 value of the data
std::string DataBytes::SHA256HexStr(const unsigned char* data,
                                    const size_t size) {
  std::string hex_sha256;
  do {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
      ELOG_ERROR("Fail to do SHA256_Init");
      break;
    }
    if (!SHA256_Update(&sha256, data, size)) {
      ELOG_ERROR("Fail to do SHA256_Update");
      break;
    }
    if (!SHA256_Final(hash.data(), &sha256)) {
      ELOG_ERROR("Fail to do SHA256_Final");
      break;
    }
    const size_t len = hash.size();
    const uint8_t* buf = hash.data();
    std::string dst(len * 2, '\0');
    for (size_t i = 0; i < len; i++) {
      dst[i * 2] = Dec2Hex(buf[i] >> 4);
      dst[i * 2 + 1] = Dec2Hex(buf[i]);
    }
    hex_sha256.assign(dst);
  } while (0);

  return hex_sha256;
}

// Return the Hex string of the SHA256 value of the data
std::string DataBytes::GetSHA256HexStr() {
  return SHA256HexStr(data(), size());
}

// Compare to the memory buffer, return true when they are equal.
bool DataBytes::Compare(const uint8_t* buf, size_t len) {
  if (len > size()) {
    ELOG_DEBUG("The buffer to be compared is longer");
    return false;
  }
  return (memcmp(buf, data(), len) == 0) ? true : false;
}

// Compare to a string
bool DataBytes::Compare(const std::string& str) {
  return Compare(RCAST(const uint8_t*, str.data()), str.length());
}

// Compare to a vector
bool DataBytes::Compare(const std::vector<uint8_t>& vec) {
  return Compare(vec.data(), vec.size());
}

}  // namespace common
}  // namespace kubetee
