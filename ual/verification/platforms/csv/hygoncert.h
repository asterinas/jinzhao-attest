/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 * Copyright (c) 2022 Ant Group
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UAL_VERIFICATION_PLATFORMS_CSV_HYGONCERT__H_
#define UAL_VERIFICATION_PLATFORMS_CSV_HYGONCERT__H_

#include <string>

#include "attestation/platforms/csv.h"

#ifdef __cplusplus
extern "C" {
#endif

int verify_hsk_cert(hygon_root_cert_t* cert);
int verify_cek_cert(hygon_root_cert_t* hsk_cert, csv_cert_t* cek_cert);
int verify_pek_cert(csv_cert_t* cek_cert, csv_cert_t* pek_cert);
int sm2_verify_attestation_report(csv_cert_t* pek_cert,
                                  csv_attestation_report* report);

#ifdef __cplusplus
}
#endif

#endif  // UAL_VERIFICATION_PLATFORMS_CSV_HYGONCERT__H_
