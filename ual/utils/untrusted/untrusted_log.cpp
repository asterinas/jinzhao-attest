#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

#include "attestation/common/log.h"

#ifdef __cplusplus
extern "C" {
#endif

int tee_printf(const char* fmt, ...) {
  constexpr size_t kMaxLogBufSzie = 40960;
  char buf[kMaxLogBufSzie] = {'\0'};
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, kMaxLogBufSzie, fmt, ap);
  va_end(ap);

  // Add the special suffix to notify the limitation of buffer length
  if (strlen(buf) >= (kMaxLogBufSzie - 5)) {
    buf[kMaxLogBufSzie - 5] = '.';
    buf[kMaxLogBufSzie - 4] = '.';
    buf[kMaxLogBufSzie - 3] = '.';
    buf[kMaxLogBufSzie - 2] = '\n';
    buf[kMaxLogBufSzie - 1] = 0;
  }

  int ret = printf("%s", buf);
  fflush(stdout);
  return ret;
}

void ocall_UaPrintMessage(const char* message) {
  printf("\033[34m%s\033[0m", message);
  fflush(stdout);
}

#ifdef __cplusplus
}
#endif
