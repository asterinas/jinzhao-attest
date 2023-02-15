#include <cstring>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "attestation/common/log.h"

#include "verification/platforms/kunpeng/kunpengsecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _SHA256(d, n, md)      \
  {                            \
    SHA256_CTX ctx;            \
    SHA256_Init(&ctx);         \
    SHA256_Update(&ctx, d, n); \
    SHA256_Final(md, &ctx);    \
  }

// Declare static functions here
static bool verifysig(buffer_data* data,
                      buffer_data* sign,
                      buffer_data* cert,
                      uint32_t scenario);

// getDataFromReport get some data which have akcert & signak & signdata &
// scenario from report
static bool getDataFromReport(buffer_data* report,
                              buffer_data* akcert,
                              buffer_data* signak,
                              buffer_data* signdata,
                              uint32_t* scenario) {
  if (report->buf == NULL) {
    ELOG_ERROR("Report is null");
    return false;
  }

  struct report_response* re = (struct report_response*)report->buf;
  *scenario = re->scenario;
  uint32_t data_offset;
  uint32_t data_len;
  uint32_t param_count = re->param_count;
  if (param_count <= 0) {
    return false;
  }

  for (uint32_t i = 0; i < param_count; i++) {
    uint32_t param_info = re->params[i].tags;
    uint32_t param_type =
        (re->params[i].tags & 0xf0000000) >> 28;  // get high 4 bits
    if (param_type == 2) {
      data_offset = re->params[i].data.blob.data_offset;
      data_len = re->params[i].data.blob.data_len;
      if (data_offset + data_len > report->size) {
        return false;
      }
      switch (param_info) {
        case RA_TAG_CERT_AK:
          akcert->buf = report->buf + data_offset;
          akcert->size = data_len;
          break;
        case RA_TAG_SIGN_AK:
          signak->buf = report->buf + data_offset;
          signak->size = data_len;
          // get sign data
          signdata->buf = report->buf;
          signdata->size = data_offset;
          break;
        default:
          break;
      }
    }
  }

  return true;
}

static void restorePEMCert(uint8_t* data, int data_len, buffer_data* certdrk) {
  const char head[] = "-----BEGIN CERTIFICATE-----\n";
  const char end[] = "-----END CERTIFICATE-----\n";
  uint8_t* drktest =
      (uint8_t*)malloc(sizeof(uint8_t) * 2048);  // malloc a buffer big engough
  memcpy(drktest, head, strlen(head));

  uint8_t* src = data;
  uint8_t* dst = drktest + strlen(head);
  int loop = data_len / 64;
  int rem = data_len % 64;
  int i = 0;

  for (i = 0; i < loop; i++, src += 64, dst += 65) {
    memcpy(dst, src, 64);
    dst[64] = '\n';
  }
  if (rem > 0) {
    memcpy(dst, src, rem);
    dst[rem] = '\n';
    dst += rem + 1;
  }
  memcpy(dst, end, strlen(end));
  dst += strlen(end);
  certdrk->size = dst - drktest;
  certdrk->buf = drktest;

  // dumpDrkCert(certdrk);
}

// get some data which have signdata signdrk certdrk and akpub from akcert
bool getDataFromAkCert(buffer_data* akcert,
                       buffer_data* signdata,
                       buffer_data* signdrk,
                       buffer_data* certdrk,
                       buffer_data* akpub) {
  if (akcert->buf == NULL) {
    ELOG_ERROR("akcert is null");
    return false;
  }
  struct ak_cert* ak;
  ak = (struct ak_cert*)akcert->buf;
  uint32_t data_offset;
  uint32_t data_len;
  uint32_t param_count = ak->param_count;

  if (param_count <= 0) {
    return false;
  }
  for (uint32_t i = 0; i < param_count; i++) {
    uint32_t param_info = ak->params[i].tags;
    uint32_t param_type =
        (ak->params[i].tags & 0xf0000000) >> 28;  // get high 4 bits
    if (param_type == 2) {
      data_offset = ak->params[i].data.blob.data_offset;
      data_len = ak->params[i].data.blob.data_len;
      if (data_offset + data_len > akcert->size) {
        return false;
      }
      switch (param_info) {
        case RA_TAG_AK_PUB:
          akpub->buf = akcert->buf + data_offset;
          akpub->size = data_len;
          break;
        case RA_TAG_SIGN_DRK:
          signdrk->buf = akcert->buf + data_offset;
          signdrk->size = data_len;
          // get sign data (all before signdrk offset)
          signdata->size = data_offset;
          signdata->buf = akcert->buf;
          break;
        case RA_TAG_CERT_DRK:
          restorePEMCert(akcert->buf + data_offset, data_len, certdrk);
          break;
        default:
          break;
      }
    }
  }
  return true;
}

static EVP_PKEY* buildPubKeyFromModulus(buffer_data* pub) {
  EVP_PKEY* key = NULL;
  key = EVP_PKEY_new();

  BIGNUM* e = BN_new();
  BN_set_word(e, 0x10001);
  BIGNUM* n = BN_new();
  BN_bin2bn(pub->buf, pub->size, n);

  RSA* rsapub = RSA_new();
  RSA_set0_key(rsapub, n, e, NULL);

  EVP_PKEY_set1_RSA(key, rsapub);

  return key;
}

static EVP_PKEY* getPubKeyFromDrkIssuedCert(buffer_data* cert) {
  buffer_data datadrk, signdrk, certdrk, akpub;
  bool rt;
  EVP_PKEY* key = NULL;

  rt = getDataFromAkCert(cert, &datadrk, &signdrk, &certdrk, &akpub);
  if (!rt) {
    ELOG_ERROR("Get NOAS data is failed!");
    return NULL;
  }

  // verify the integrity of data in drk issued cert
  rt = verifysig(&datadrk, &signdrk, &certdrk, 1);
  if (!rt) {
    ELOG_ERROR("Validate drk cert failed!");
    return NULL;
  }

  // build a pub key with the modulus carried in drk issued cert
  key = buildPubKeyFromModulus(&akpub);
  return key;
}

static bool verifySigByKey(buffer_data* mhash,
                           buffer_data* sign,
                           EVP_PKEY* key) {
  if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
    ELOG_ERROR("The pub key type is not in supported type list(rsa)");
    return false;
  }

  uint8_t buf[512];
  int rt = RSA_public_decrypt(sign->size, sign->buf, buf,
                              EVP_PKEY_get1_RSA(key), RSA_NO_PADDING);
  if (rt == -1) {
    ELOG_ERROR("RSA public decrypt is failed with error %s",
               ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  // rt = RSA_verify_PKCS1_PSS_mgf1(EVP_PKEY_get1_RSA(key), mhash->buf,
  // EVP_sha256(), EVP_sha256(), buf, -2);
  rt = RSA_verify_PKCS1_PSS(EVP_PKEY_get1_RSA(key), mhash->buf, EVP_sha256(),
                            buf, -2);
  // rt = RSA_verify(EVP_PKEY_RSA_PSS, mhash->buf, SHA256_DIGEST_LENGTH,
  // signdrk.buf, signdrk.size, EVP_PKEY_get1_RSA(key));
  if (rt != 1) {
    ELOG_ERROR("Verify sign is failed with error %s",
               ERR_error_string(ERR_get_error(), NULL));
    return false;
  }

  return true;
}

static bool verifydatasig_bykey(buffer_data* data,
                                buffer_data* sign,
                                EVP_PKEY* key) {
  // caculate the digest of the data
  uint8_t digest[SHA256_DIGEST_LENGTH];
  _SHA256(data->buf, data->size, digest);

  // perform signature verification
  buffer_data mhash = {sizeof(digest), digest};
  bool rt = verifySigByKey(&mhash, sign, key);

  return rt;
}

static bool verifysig_drksignedcert(buffer_data* data,
                                    buffer_data* sign,
                                    buffer_data* cert) {
  // get the key for signature verification
  EVP_PKEY* key = getPubKeyFromDrkIssuedCert(cert);
  if (key == NULL) return false;

  bool rt = verifydatasig_bykey(data, sign, key);
  EVP_PKEY_free(key);

  return rt;
}

static void trim_ending_0(buffer_data* buf) {
  for (; buf->size > 0 && buf->buf[buf->size - 1] == 0; buf->size--)
    ;
}

static EVP_PKEY* getPubKeyFromCert(buffer_data* cert) {
  EVP_PKEY* key = NULL;
  X509* c = NULL;

  BIO* bp = BIO_new_mem_buf(cert->buf, cert->size);
  if ((c = PEM_read_bio_X509(bp, NULL, NULL, NULL)) == NULL) {
    ELOG_ERROR("Failed to get drkcert x509");
    return NULL;
  }

  key = X509_get_pubkey(c);
  if (key == NULL) {
    ELOG_ERROR("Error getting public key from certificate");
  }

  return key;
}

static bool verifysig_x509cert(buffer_data* data,
                               buffer_data* sign,
                               buffer_data* cert) {
  // trim ending 0's in cert buf
  trim_ending_0(cert);

  // get the key for signature verification
  EVP_PKEY* key = getPubKeyFromCert(cert);
  if (key == NULL) return false;

  bool rt = verifydatasig_bykey(data, sign, key);
  EVP_PKEY_free(key);

  return rt;
}

/*
verifysig will verify the signature in report
   data: data protected by signature, a byte array
   sign: the signature, a byte array
   cert: a byte array.
      A drk signed cert in self-defined format for scenario 0;
      A X509 PEM cert for scenario 1.
      A DAA cert scenario 2.
   scenario: 0, 1 or 2. refer to the description above.
   return value: true if the sigature verification succeeded, else false.
*/
static bool verifysig(buffer_data* data,
                      buffer_data* sign,
                      buffer_data* cert,
                      uint32_t scenario) {
  if (data->size <= 0 || sign->size <= 0 || cert->size <= 0 || scenario > 2) {
    return false;
  }

  switch (scenario) {
    case 0:
      return verifysig_drksignedcert(data, sign, cert);
    case 1:
      return verifysig_x509cert(data, sign, cert);
    case 2:
      //   return verifysig_daacert(data, sign, cert);
      ELOG_ERROR("Don't support DAA cert yet");
  }

  return false;
}

bool kunpensecl_verify_signature(buffer_data* report) {
  // get akcert signak signdata from report
  buffer_data akcert, signak, signdata;
  uint32_t scenario;
  bool rt = getDataFromReport(report, &akcert, &signak, &signdata, &scenario);
  if (!rt) {
    ELOG_ERROR("Get data from report is failed");
    return false;
  }

  // Verify the report signature
  rt = verifysig(&signdata, &signak, &akcert, scenario);
  if (!rt) {
    ELOG_ERROR("Verify signature is failed");
    return false;
  }

  return true;
}

#ifdef __cplusplus
}
#endif
