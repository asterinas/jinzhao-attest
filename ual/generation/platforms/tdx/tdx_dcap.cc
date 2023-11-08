#include <assert.h>
#include <stdio.h>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include "sgx_urts.h"

#include <sgx_dcap_quoteverify.h>
#include <sgx_ql_quote.h>

#include <tdx_attest.h>

static void tdx_gen_report_data(uint8_t* reportdata) {
  srand(time(NULL));
  for (int i = 0; i < TDX_REPORT_DATA_SIZE; i++) {
    reportdata[i] = rand();
  }
}

static int tdx_generate_quote(uint8_t** quote_buf,
                              uint32_t& quote_size,
                              uint8_t* hash) {
  int ret = -1;

  tdx_report_data_t report_data = {{0}};
  tdx_report_t tdx_report = {{0}};
  tdx_uuid_t selected_att_key_id = {0};

  tdx_gen_report_data(report_data.d);
  // print_hex_dump("TDX report data\n", " ", report_data.d,
  // sizeof(report_data.d));

  if (TDX_ATTEST_SUCCESS != tdx_att_get_report(&report_data, &tdx_report)) {
    grpc_fprintf(stderr, "failed to get the report.\n");
    ret = 0;
  }
  // print_hex_dump("TDX report\n", " ", tdx_report.d, sizeof(tdx_report.d));

  if (TDX_ATTEST_SUCCESS != tdx_att_get_quote(&report_data, NULL, 0,
                                              &selected_att_key_id, quote_buf,
                                              &quote_size, 0)) {
    grpc_fprintf(stderr, "failed to get the quote.\n");
    ret = 0;
  }
  // print_hex_dump("TDX quote data\n", " ", *quote_buf, quote_size);

  // printf("tdx_generate_quote, sizeof %d, quote_size %d\n",
  // sizeof(*quote_buf), quote_size);

  realloc(*quote_buf, quote_size + SHA256_DIGEST_LENGTH);
  memcpy((*quote_buf) + quote_size, hash, SHA256_DIGEST_LENGTH);
  quote_size += SHA256_DIGEST_LENGTH;

  // printf("tdx_generate_quote, sizeof %d, quote_size %d\n",
  // sizeof(*quote_buf), quote_size);
  return ret;
};

std::vector<std::string> tdx_generate_key_cert() {
  return generate_key_cert(tdx_generate_quote);
}

int tdx_parse_quote(X509* x509, uint8_t** quote, uint32_t& quote_size) {
  return parse_quote(x509, quote, quote_size);
};

void tdx_verify_init() {
  generate_key_cert(dummy_generate_quote);
};

int tdx_verify_quote(uint8_t* quote_buf, size_t quote_size) {
  bool use_qve = false;
  (void)(use_qve);

  int ret = 0;
  time_t current_time = 0;
  uint32_t supplemental_data_size = 0;
  uint8_t* p_supplemental_data = nullptr;

  quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
  sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
  uint32_t collateral_expiration_status = 1;

  sgx_status_t sgx_ret = SGX_SUCCESS;
  uint8_t rand_nonce[16] = "59jslk201fgjmm;";
  sgx_ql_qe_report_info_t qve_report_info;
  sgx_launch_token_t token = {0};

  int updated = 0;
  quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;
  sgx_enclave_id_t eid = 0;

  // call DCAP quote verify library to get supplemental data size
  dcap_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
  if (dcap_ret == SGX_QL_SUCCESS &&
      supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
    printf(
        "Info: tdx_qv_get_quote_supplemental_data_size successfully "
        "returned.\n");
    p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
  } else {
    printf("Error: tdx_qv_get_quote_supplemental_data_size failed: 0x%04x\n",
           dcap_ret);
    supplemental_data_size = 0;
  }

  // set current time. This is only for sample purposes, in production mode a
  // trusted time should be used.
  current_time = time(NULL);

  // call DCAP quote verify library for quote verification
  print_hex_dump("TDX parse quote data\n", " ", quote_buf, quote_size);
  dcap_ret = tdx_qv_verify_quote(quote_buf, quote_size, NULL, current_time,
                                 &collateral_expiration_status,
                                 &quote_verification_result, NULL,
                                 supplemental_data_size, p_supplemental_data);
  if (dcap_ret == SGX_QL_SUCCESS) {
    printf("Info: App: tdx_qv_verify_quote successfully returned.\n");
  } else {
    printf("Error: App: tdx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
  }

  // check verification result
  switch (quote_verification_result) {
    case SGX_QL_QV_RESULT_OK:
      // check verification collateral expiration status
      // this value should be considered in your own attestation/verification
      // policy
      //
      if (collateral_expiration_status == 0) {
        printf("Info: App: Verification completed successfully.\n");
        ret = 0;
      } else {
        printf(
            "Warning: App: Verification completed, but collateral is out of "
            "date based on 'expiration_check_date' you provided.\n");
        ret = 1;
      }
      break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
      printf(
          "Warning: App: Verification completed with Non-terminal result: %x\n",
          quote_verification_result);
      ret = 1;
      break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
      printf("Error: App: Verification completed with Terminal result: %x\n",
             quote_verification_result);
      ret = -1;
      break;
  }

  return ret;
}

int tdx_verify_cert(const char* der_crt, size_t len) {
  int ret = 0;
  uint32_t quote_size = 0;
  uint8_t* quote_buf = nullptr;

  BIO* bio = BIO_new(BIO_s_mem());
  BIO_write(bio, der_crt, len);
  X509* x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (!x509) {
    printf("parse the crt failed.\n");
    goto out;
  }

  ret = tdx_parse_quote(x509, &quote_buf, quote_size);
  if (ret != 0) {
    printf("parse quote failed.\n");
    goto out;
  }

  ret = tdx_verify_quote(quote_buf, quote_size - SHA256_DIGEST_LENGTH);
  if (ret != 0) {
    printf("verify quote failed.\n");
    goto out;
  }

  ret = verify_pubkey_hash(x509, quote_buf + quote_size - SHA256_DIGEST_LENGTH,
                           SHA256_DIGEST_LENGTH);
  if (ret != 0) {
    printf("verify the public key hash failed.\n");
    goto out;
  }

  // ret = verify_measurement((const char *)&p_rep_body->mr_enclave,
  //                          (const char *)&p_rep_body->mr_signer,
  //                          (const char *)&p_rep_body->isv_prod_id,
  //                          (const char *)&p_rep_body->isv_svn);

out:
  BIO_free(bio);
  return ret;
}

ra_tls_measurement tdx_parse_measurement(const char* der_crt, size_t len) {
  // TODO
  return ra_tls_measurement();
}
