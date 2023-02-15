#ifndef UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_FS_H_
#define UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_FS_H_

#include <fstream>
#include <iostream>
#include <string>

#include "attestation/common/error.h"

namespace kubetee {
namespace utils {

TeeErrorCode FsWriteString(const std::string& filename, const std::string& str);
TeeErrorCode FsReadString(const std::string& filename, std::string* str);
TeeErrorCode FsGetFileSize(const std::string& filename, size_t* size);
bool FsFileExists(const std::string& filename);
std::string GetFsString(const std::string& filename);

}  // namespace utils
}  // namespace kubetee

#endif  // UAL_INCLUDE_UTILS_UNTRUSTED_UNTRUSTED_FS_H_
