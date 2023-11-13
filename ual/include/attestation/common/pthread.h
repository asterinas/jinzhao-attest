#ifndef UAL_INCLUDE_ATTESTATION_COMMON_PTHREAD_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_PTHREAD_H_

#if defined(UA_ENV_TYPE_SGXSDK) && defined(TEE_TRUSTED)
#include "./sgx_thread.h"
#define UA_MUTEX_T sgx_thread_mutex_t
#define UA_MUTEX_INITIALIZER SGX_THREAD_MUTEX_INITIALIZER
#define UA_MUTEX_INIT sgx_thread_mutex_init
#define UA_MUTEX_LOCK sgx_thread_mutex_lock
#define UA_MUTEX_UNLOCK sgx_thread_mutex_unlock
#define UA_THREAD_SELF sgx_thread_self
#define UA_THREAD_TYPE sgx_thread_t
#else  // For Occlum or NO TEE environment
#include "./pthread.h"
#define UA_MUTEX_T pthread_mutex_t
#define UA_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define UA_MUTEX_INIT pthread_mutex_init
#define UA_MUTEX_LOCK pthread_mutex_lock
#define UA_MUTEX_UNLOCK pthread_mutex_unlock
#define UA_THREAD_SELF pthread_self
#define UA_THREAD_TYPE pthread_t
#endif

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_PTHREAD_H_
