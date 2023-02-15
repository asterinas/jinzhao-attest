/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UAL_VERIFICATION_PLATFORMS_CSV_CSV_UTILS_H_
#define UAL_VERIFICATION_PLATFORMS_CSV_CSV_UTILS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int sm3_hmac(const char* key,
             size_t key_len,
             const unsigned char* data,
             size_t data_len,
             unsigned char* hmac,
             size_t expected_hmac_len);

#ifdef __cplusplus
}
#endif

#endif  // UAL_VERIFICATION_PLATFORMS_CSV_CSV_UTILS_H_
