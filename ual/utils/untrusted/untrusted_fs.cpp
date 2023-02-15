#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "attestation/common/error.h"
#include "attestation/common/log.h"

#include "utils/untrusted/untrusted_fs.h"

namespace kubetee {
namespace utils {

TeeErrorCode FsWriteString(const std::string& filename,
                           const std::string& str) {
  std::ofstream ofs(filename,
                    std::ios::binary | std::ios::out | std::ios::trunc);
  if (!ofs) {
    TEE_LOG_ERROR("Fail to open file \"%s\"", filename.c_str());
    return TEE_ERROR_FILE_OPEN;
  }

  ofs.write(str.c_str(), str.length());
  if (ofs.fail()) {
    TEE_LOG_ERROR("Fail to write file \"%s\"", filename.c_str());
    return TEE_ERROR_FILE_WRITE;
  }

  return TEE_SUCCESS;
}

TeeErrorCode FsReadString(const std::string& filename, std::string* str) {
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs) {
    // TEE_LOG_ERROR("Fail to open file \"%s\"\n", filename.c_str());
    return TEE_ERROR_FILE_OPEN;
  }

  ifs.seekg(0, std::ios::end);
  int length = ifs.tellg();
  ifs.seekg(0, std::ios::beg);

  std::vector<char> buf(length);
  ifs.read(buf.data(), length);
  if (ifs.fail()) {
    TEE_LOG_ERROR("Fail to read file \"%s\"", filename.c_str());
    return TEE_ERROR_FILE_READ;
  }

  str->assign(buf.data(), length);
  return TEE_SUCCESS;
}

TeeErrorCode FsGetFileSize(const std::string& filename, size_t* size) {
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs.good()) {
    TEE_LOG_ERROR("Fail to open file \"%s\"", filename.c_str());
    return TEE_ERROR_FILE_OPEN;
  }

  ifs.seekg(0, std::ios::end);
  *size = ifs.tellg();
  ifs.close();
  return TEE_SUCCESS;
}

bool FsFileExists(const std::string& filename) {
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  return ifs.good();
}

std::string GetFsString(const std::string& filename) {
  std::string str;
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs) {
    TEE_LOG_DEBUG("Fail to open file \"%s\"", filename.c_str());
    return str;
  }

  ifs.seekg(0, std::ios::end);
  int length = ifs.tellg();
  ifs.seekg(0, std::ios::beg);

  std::vector<char> buf(length);
  ifs.read(buf.data(), length);
  if (ifs.fail()) {
    TEE_LOG_DEBUG("Fail to read file \"%s\"", filename.c_str());
    return str;
  }

  str.assign(buf.data(), length);
  return str;
}

}  // namespace utils
}  // namespace kubetee
