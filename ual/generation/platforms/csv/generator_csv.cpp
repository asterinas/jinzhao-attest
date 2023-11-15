/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 * Copyright (c) 2023-2024 Ant Group
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>  // for mmap
#include <unistd.h>    // for sleep() function
#include <algorithm>
#include <string>
#include <vector>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/sm3.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/platforms/csv.h"
#include "attestation/verification/ua_verification.h"

#include "generation/platforms/csv/generator_csv.h"
#include "network/hygon_kds_client.h"

#ifdef __cplusplus
extern "C" {
#endif

static void gen_random_bytes(void* buf, uint32_t len) {
  uint32_t i;
  uint8_t* buf_byte = (uint8_t*)buf;

  for (i = 0; i < len; i++) {
    buf_byte[i] = rand() & 0xFF;
  }
}

static uint64_t va_to_pa(uint64_t va) {
  FILE* fd = nullptr;
  uint64_t offset, pfn;
  uint64_t pa = 0;

  fd = fopen(PAGE_MAP_FILENAME, "rb");
  if (!fd) {
    TEE_LOG_ERROR("Failed to open %s", PAGE_MAP_FILENAME);
    return 0;
  }

  do {
    offset = ((uint64_t)va / PAGE_SIZE) * PAGEMAP_LEN;
    if (fseek(fd, offset, SEEK_SET) != 0) {
      TEE_LOG_ERROR("Failed to seek");
      break;
    }

    if (fread(&pfn, 1, PAGEMAP_LEN - 1, fd) != (PAGEMAP_LEN - 1)) {
      TEE_LOG_ERROR("Failed to read pagemap entry");
      break;
    }

    pa = (pfn & PAGE_MAP_PFN_MASK) << PAGE_SHIFT;
  } while (0);

  fclose(fd);
  return pa;
}

static TeeErrorCode do_hypercall(unsigned int nr,
                                 unsigned long p1,
                                 unsigned long len) {
  long ret = 0;
  asm volatile("vmmcall" : "=a"(ret) : "a"(nr), "b"(p1), "c"(len) : "memory");
  return (TeeErrorCode)ret;
}

static TeeErrorCode get_csv_attestation_report(const uint8_t* user_data_buf,
                                               size_t user_data_len,
                                               csv_attestation_report* report,
                                               std::string* chip_id_str) {
  TeeErrorCode ret = 0;
  uint64_t user_data_pa;
  csv_attester_user_data_t* user_data = NULL;

  /* Make sure the attestation report is within one page */
  if (sizeof(csv_attestation_report) > PAGE_SIZE) {
    TEE_LOG_ERROR("csv_attestation_report is too much large");
    return TEE_ERROR_RA_GENERATE_CSV_REPORT_STRUCT;
  }

  /* Request an private page which is used to communicate with CSV firmware.
   * When attester want collect claims from CSV firmware, it will set user
   * data to this private page. If CSV firmware returns successfully, it will
   * save claims to this private page.
   *
   * TODO: pin the mmapped page in this attester.
   */
  user_data = (csv_attester_user_data_t*)mmap(
      NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (user_data == MAP_FAILED) {
    TEE_LOG_ERROR("Failed to mmap\n");
    return TEE_ERROR_RA_GENERATE_CSV_MMAP;
  }
  TEE_LOG_DEBUG("mmap [%#016lx - %#016lx)\n", (unsigned long)user_data,
                (unsigned long)user_data + PAGE_SIZE);
  memset((void*)user_data, 0, PAGE_SIZE);

  do {
    /* Prepare user defined data (challenge and mnonce) */
    if (user_data_len > CSV_ATTESTATION_USER_DATA_SIZE) {
      user_data_len = CSV_ATTESTATION_USER_DATA_SIZE;
    }
    memcpy(user_data->data, user_data_buf, user_data_len);
    gen_random_bytes(user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);
    /* Save mnonce to check the timeliness of attestation report later */
    unsigned char cur_mnonce[CSV_ATTESTATION_MNONCE_SIZE];
    memcpy(cur_mnonce, user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);

    /* Prepare hash of user defined data */
    ret = kubetee::common::SM3Crypto::calHash(
        (const char*)user_data,
        CSV_ATTESTATION_USER_DATA_SIZE + CSV_ATTESTATION_MNONCE_SIZE,
        (char*)(&user_data->hash), sizeof(hash_block_t));
    if (ret != TEE_SUCCESS) {
      TEE_LOG_ERROR("Failed to compute sm3 hash");
      break;
    }

    /* Request ATTESTATION */
    user_data_pa = va_to_pa(RCAST(uint64_t, user_data));
    if (!user_data_pa) {
      TEE_LOG_ERROR("Fail get va from pa");
      break;
    }
    ret = do_hypercall(KVM_HC_VM_ATTESTATION, user_data_pa, PAGE_SIZE);
    if (ret) {
      TEE_LOG_ERROR("Failed to get attestation report: %d", ret);
      ret = TEE_ERROR_RA_GENERATE_CSV_VMCALL;
      break;
    }

    /* Check whether the attestation report is fresh */
    unsigned char report_mnonce[CSV_ATTESTATION_MNONCE_SIZE];
    csv_attestation_report* csv_report = (csv_attestation_report*)user_data;
    uint32_t anonce = csv_report->anonce;
    uint32_t* ptemp = (uint32_t*)csv_report->mnonce;
    for (int i = 0; i < CSV_ATTESTATION_MNONCE_SIZE / sizeof(uint32_t); i++)
      ((uint32_t*)report_mnonce)[i] = ptemp[i] ^ anonce;
    if (memcmp(cur_mnonce, report_mnonce, CSV_ATTESTATION_MNONCE_SIZE)) {
      TEE_LOG_ERROR("mnonce does not match");
      break;
    }

    /* Fill csv_attestation_report buffer with attestation report */
    memcpy(report, user_data, sizeof(csv_attestation_report));

    /* Retreive ChipId from attestation report */
    uint8_t chip_id[CSV_ATTESTATION_CHIP_SN_SIZE + 1] = {
        0,
    };
    ptemp = (uint32_t*)csv_report->chip_id;
    for (int i = 0; i < CSV_ATTESTATION_CHIP_SN_SIZE / sizeof(uint32_t); i++) {
      ((uint32_t*)chip_id)[i] = ptemp[i] ^ anonce;
    }
    chip_id_str->assign((char*)chip_id, CSV_ATTESTATION_CHIP_SN_SIZE + 1);
    TEE_LOG_DEBUG("Chip ID: %s", chip_id_str->c_str());
  } while (0);

  munmap(user_data, PAGE_SIZE);
  return ret;
}

#ifdef __cplusplus
}
#endif

namespace kubetee {
namespace attestation {

TeeErrorCode AttestationGeneratorCsv::Initialize(
    const std::string& tee_identity) {
  if (tee_identity.empty()) {
    TEE_LOG_ERROR("Enclave has not been created successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorCsv::GetQuote(
    const UaReportGenerationParameters& param,
    std::string* pquote_b64,
    std::string* chip_id) {
  // Prepare the user data buffer
  uint8_t report_data_buf[CSV_ATTESTATION_USER_DATA_SIZE] = {
      0,
  };
  TEE_CHECK_RETURN(PrepareReportData(param, report_data_buf,
                                     CSV_ATTESTATION_USER_DATA_SIZE));
  // Replace the higher 32 bytes by HASH UAK public key
  if (param.others.pem_public_key().empty() && !UakPublic().empty()) {
    kubetee::common::DataBytes pubkey(UakPublic());
    pubkey.ToSHA256().Export(report_data_buf + kSha256Size, kSha256Size).Void();
  }

  // Get the csv report and chip_id
  csv_attestation_report report;
  TEE_CHECK_RETURN(get_csv_attestation_report(
      report_data_buf, CSV_ATTESTATION_USER_DATA_SIZE, &report, chip_id));

  kubetee::common::DataBytes b64_quote;
  b64_quote.SetValue(RCAST(uint8_t*, &report), sizeof(csv_attestation_report));
  pquote_b64->assign(b64_quote.ToBase64().GetStr());
  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorCsv::CreateBgcheckReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get attestation quote
  kubetee::HygonCsvReport csv_report;
  std::string chip_id;
  TEE_CHECK_RETURN(GetQuote(param, csv_report.mutable_b64_quote(), &chip_id));
  csv_report.set_str_chip_id(chip_id);

  // Make the final report with quote only
  report->set_str_tee_platform(kUaPlatformCsv);
  report->set_str_report_type(kUaReportTypeBgcheck);
  PB2JSON(csv_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

TeeErrorCode AttestationGeneratorCsv::CreatePassportReport(
    const UaReportGenerationParameters& param,
    kubetee::UnifiedAttestationReport* report) {
  // Get attestation quote
  kubetee::HygonCsvReport csv_report;
  std::string chip_id;
  TEE_CHECK_RETURN(GetQuote(param, csv_report.mutable_b64_quote(), &chip_id));
  csv_report.set_str_chip_id(chip_id);

  // For CSV, the external reference data is HSK and CEK
  // Get the HSK and CEK from Hygon KDS
  kubetee::HygonCsvCertChain csv_certs;
  RaHygonKdsClient hygon_kds_client;
  TEE_CHECK_RETURN(hygon_kds_client.GetCsvHskCek(chip_id, &csv_certs));
  PB2JSON(csv_certs, csv_report.mutable_json_cert_chain());

  // Make the final report with quote only
  report->set_str_tee_platform(kUaPlatformCsv);
  report->set_str_report_type(kUaReportTypePassport);
  PB2JSON(csv_report, report->mutable_json_report());

  return TEE_SUCCESS;
}

}  // namespace attestation
}  // namespace kubetee
