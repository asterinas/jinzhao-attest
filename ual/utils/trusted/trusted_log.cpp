#include <cstdarg>
#include <cstdio>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

extern int ocall_UaPrintMessage(const char* message);

/// Implement of tee_printf function for trusted code.
/// NOTE: The protobuf files also include the std headers and use printf.
//        But we have replaced the printf to tee_printf to use this function.
int tee_printf(const char* fmt, ...) {
  constexpr size_t kMaxLogBufSize = 4096;
  char buf[kMaxLogBufSize] = {'\0'};
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, kMaxLogBufSize, fmt, ap);
  va_end(ap);

  // Add the special suffix to notify the limitation of buffer length
  if (strlen(buf) >= (kMaxLogBufSize - 5)) {
    buf[kMaxLogBufSize - 5] = '.';
    buf[kMaxLogBufSize - 4] = '.';
    buf[kMaxLogBufSize - 3] = '.';
    buf[kMaxLogBufSize - 2] = '\n';
    buf[kMaxLogBufSize - 1] = 0;
  }

  return ocall_UaPrintMessage(buf);
}

#ifdef __cplusplus
}
#endif
