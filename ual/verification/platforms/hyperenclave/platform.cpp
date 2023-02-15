#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "attestation/common/bytes.h"
#include "attestation/common/log.h"
#include "attestation/common/type.h"

#include "verification/platforms/hyperenclave/platform.h"
#include "verification/platforms/hyperenclave/sm2.h"
#include "verification/platforms/hyperenclave/sm3.h"

#ifdef __cplusplus
extern "C" {
#endif

static uint16_t get_tpm_hash_alg() {
  return TPM_ALG_SM3_256;
}

static void _reverse_copy(uint8_t* out, uint8_t* in, uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    out[i] = in[count - i - 1];
  }
}

#define reverse_copy(out, in, count) \
  _reverse_copy((uint8_t*)(out), (uint8_t*)(in), count)

#define reverse_copy_in(out, var)                                  \
  {                                                                \
    _reverse_copy((uint8_t*)(out), (uint8_t*)&(var), sizeof(var)); \
    out += sizeof(var);                                            \
  }

#define reverse_copy_out(var, out)                                 \
  {                                                                \
    _reverse_copy((uint8_t*)&(var), (uint8_t*)(out), sizeof(var)); \
    out += sizeof(var);                                            \
  }

static uint16_t reverse_copy_sized_buf_out(TPM2B* dest, TPM2B* src) {
  uint16_t i, size;
  if (dest == NULL || src == NULL) {
    return 0;
  }
  reverse_copy(&size, &src->size, sizeof(src->size));
  if (size > dest->size) {
    return 0;
  }
  dest->size = size;
  for (i = 0; i < dest->size; i++) {
    dest->buffer[i] = src->buffer[i];
  }
  return (uint16_t)(sizeof(uint16_t) + dest->size);
}

static uint16_t reverse_copy_sized_buf_with_hash_alg_out(TPM2B* dest,
                                                         TPM2B* src) {
  uint16_t i, size;
  uint16_t hash_alg_len = 2;
  if (dest == NULL || src == NULL) {
    return 0;
  }
  reverse_copy(&size, &src->size, sizeof(src->size));
  size = (uint16_t)(size - hash_alg_len);  // skip the hash alg
  if (size > dest->size || size <= 0) {
    return 0;
  }
  dest->size = size;
  for (i = 0; i < dest->size; i++) {
    dest->buffer[i] = src->buffer[i + hash_alg_len];
  }
  return (uint16_t)(sizeof(uint16_t) + size + hash_alg_len);
}

static bool reverse_copy_pcr_selection_out(TPML_PCR_SELECTION* pcr_selection,
                                           uint8_t** other) {
  uint32_t i, k;
  if (pcr_selection == NULL) {
    return false;
  }
  reverse_copy_out(pcr_selection->count, *other);
  if (pcr_selection->count > HASH_COUNT) {
    return false;
  }
  for (i = 0; i < pcr_selection->count; i++) {
    reverse_copy_out(pcr_selection->selections[i].hash, *other);
    reverse_copy_out(pcr_selection->selections[i].size_of_select, *other);
    if (pcr_selection->selections[i].size_of_select >
        sizeof(pcr_selection->selections[i].pcr_select)) {
      return false;
    }
    for (k = 0; k < pcr_selection->selections[i].size_of_select; k++) {
      reverse_copy_out(pcr_selection->selections[i].pcr_select[k], *other);
    }
  }
  return true;
}

static uint32_t calc_pcr_digest(uint8_t* hv_pk_buf,
                                uint32_t buf_len,
                                uint8_t* pcr_array,
                                uint32_t array_size,
                                uint8_t* digest) {
  uint8_t hv_pub_pcr[HASH_LENGTH];
  uint8_t hv_pub_hash[HASH_LENGTH];
  uint8_t pcr_init_value[HASH_LENGTH];
  uint32_t sha_len = HASH_LENGTH;
  // pcr0-pcr5 platform measurement; pcr12 =hypervisor measurement
  if (!hv_pk_buf || !buf_len || !digest) return 0;
  memset(pcr_init_value, 0, sha_len);
  // calc the hash of the hv att pub key
  global_sm3_init();
  global_sm3_update(hv_pk_buf, buf_len);
  global_sm3_final(hv_pub_hash);
  // calc the pcr value of the extended hv att pub key
  global_sm3_init();
  global_sm3_update(pcr_init_value, sha_len);
  global_sm3_update(hv_pub_hash, sha_len);
  global_sm3_final(hv_pub_pcr);

  if (memcmp(hv_pub_pcr, &pcr_array[array_size - sha_len], sha_len) != 0) {
    ELOG_ERROR("PCR 13 does not match!");
    // PCR 13 will be update whne hyperenclave restart in runtime.
    // This will result in conflict to the baseline in the certificate.
    // The check of PCR13 requires we should not restart hyperenclave service.
    return 0;
  }
  memcpy(digest, pcr_array, sha_len);
  return sha_len;
}

static uint8_t byte_to_pcr_index(uint8_t byte, uint8_t* pos, uint8_t base) {
  // base is the starting pcr index of this byte
  uint8_t mask = 1;
  uint8_t* ptr = pos;
  if (!pos) {
    return 0;
  }
  for (int i = 0; i < 8; i++) {
    if (byte & mask) {
      *ptr++ = (uint8_t)(base + i);
    }
    mask = (uint8_t)(mask * 2);
  }
  return (uint8_t)(ptr - pos);
}

static uint8_t get_pcr_array(TPML_PCR_SELECTION* pcr_select,
                             uint8_t* pcr_index) {
  uint8_t i = 0, j = 0, num = 0, count = 0, total = 0;
  uint8_t base = 0;
  uint16_t tpm_hash_alg = 0;
  uint8_t* ptr = pcr_index;
  if (!pcr_select || !pcr_index) {
    ELOG_ERROR("get_pcr_array bad parameter");
    return 0;
  }
  ELOG_BUFFER("PCR_SELECT", pcr_select, sizeof(TPML_PCR_SELECTION));
  if (pcr_select->count <= 0) {
    ELOG_ERROR("Invalid PCR select count: %d", pcr_select->count);
    return 0;
  }
  tpm_hash_alg = get_tpm_hash_alg();

  for (i = 0; i < pcr_select->count; i++) {
    if (pcr_select->selections[i].hash != tpm_hash_alg) continue;
    num = pcr_select->selections[i].size_of_select;
    if (num > MAX_PCR_NUM / 8)  // max =24 pcrs
      continue;
    for (j = 0; j < num; j++) {
      count =
          byte_to_pcr_index(pcr_select->selections[i].pcr_select[j], ptr, base);
      base = (uint8_t)(base + 8); /*one byte = 8 pcr */
      ptr = ptr + count;
      total = (uint8_t)(total + count);
    }
  }
  return total;
}

void init_tpms_attest(TPMS_ATTEST* attest) {
  if (attest == NULL) return;
  attest->signer.t.size = sizeof(TPMU_NAME);
  attest->extra_data.t.size = sizeof(TPMT_HA);
  attest->quote.pcr_digest.t.size = sizeof(TPMU_HA);
}

bool decode_tpm_attest_data(uint8_t* data, uint16_t size, TPMS_ATTEST* attest) {
  uint8_t* ptr;
  uint16_t decode_size = 0;
  if (data == NULL || size <= 0 || attest == NULL) {
    ELOG_ERROR("decode_tpm_attest_data bad parameter");
    return false;
  }
  ptr = data;
  reverse_copy_out(attest->tpm_generated, ptr);
  reverse_copy_out(attest->type, ptr);
  decode_size = reverse_copy_sized_buf_with_hash_alg_out(
      (TPM2B*)&attest->signer.t, (TPM2B*)ptr);
  ptr += decode_size;
  if (decode_size <= 0 || ptr > data + size) {
    return false;
  }
  decode_size = reverse_copy_sized_buf_with_hash_alg_out(
      (TPM2B*)&attest->extra_data.t, (TPM2B*)ptr);
  ptr += decode_size;
  if (decode_size <= 0 || ptr > data + size) {
    return false;
  }
  reverse_copy_out(attest->clock.clock, ptr);
  reverse_copy_out(attest->clock.reset_count, ptr);
  reverse_copy_out(attest->clock.restart_count, ptr);
  reverse_copy_out(attest->clock.safe, ptr);
  reverse_copy_out(attest->firmware_version, ptr);
  if (!reverse_copy_pcr_selection_out(&attest->quote.pcr_select, &ptr)) {
    return false;
  }
  decode_size = reverse_copy_sized_buf_out((TPM2B*)&attest->quote.pcr_digest.t,
                                           (TPM2B*)ptr);
  ptr += decode_size;
  if (decode_size <= 0) {
    return false;
  }
  if (attest->tpm_generated != TPM_GENERATED_VALUE) {
    ELOG_ERROR("Invalid tpm generated");
    return false;
  }
  if (attest->type != TPM_ST_ATTEST_QUOTE) {
    ELOG_ERROR("invalid tpm attest type");
    return false;
  }
  return true;
}

bool verify_pcr_digest(TPMS_ATTEST* attest,
                       uint8_t* hv_att_key_buf,
                       uint32_t buf_len,
                       uint8_t* pcr_array,
                       uint32_t array_size) {
  uint8_t expected_pcr_index[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13};
  uint8_t quote_pcr_index[MAX_PCR_NUM], calced_pcr_digest[HASH_LENGTH];
  uint32_t pcr_digest_len = 0;
  uint8_t quote_pcr_count = 0;
  if (!attest || !hv_att_key_buf || !buf_len) return false;
  quote_pcr_count = get_pcr_array(&attest->quote.pcr_select, quote_pcr_index);
  if (quote_pcr_count <= 0 || quote_pcr_count != sizeof(expected_pcr_index)) {
    ELOG_ERROR("Invalid pcr index num: %d", quote_pcr_count);
    return false;
  }
  if (memcmp(expected_pcr_index, quote_pcr_index, sizeof(expected_pcr_index)) !=
      0) {
    ELOG_ERROR("PCR index verification failed");
    return false;
  }
  pcr_digest_len = calc_pcr_digest(hv_att_key_buf, buf_len, pcr_array,
                                   array_size, calced_pcr_digest);
  if (pcr_digest_len <= 0 ||
      memcmp(calced_pcr_digest, attest->quote.pcr_digest.t.buffer,
             pcr_digest_len) != 0) {
    ELOG_ERROR("PCR digest verifiction failed");
    return false;
  }
  return true;
}

//
// For SM2 certificate chain verification
//
// CFCA root certificate is used to verify ca certificate
// As we hard code certificate here, so ignore this check.

static const char* kCfcaAcsSm2Oca33Cert_dev = R"(
-----BEGIN CERTIFICATE-----
MIICXjCCAgOgAwIBAgIQIBUE2e8lluKcyjnK+jg3qDAMBggqgRzPVQGDdQUAMF4x
CzAJBgNVBAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkxHTAbBgNVBAMMFENGQ0EgQUNTIFRFU1QgU00yIENBMB4X
DTE3MTAyNDA0Mjk1NVoXDTM3MTAxOTA0Mjk1NVowYTELMAkGA1UEBhMCQ04xMDAu
BgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEg
MB4GA1UEAwwXQ0ZDQSBBQ1MgVEVTVCBTTTIgT0NBMzMwWTATBgcqhkjOPQIBBggq
gRzPVQGCLQNCAARwpk5fN81AcD1HhLZghTcjgew5d12LfTbTdOG9bj/7BPhSL7l4
DWwwYWJ+H6xjXLRlVCrdvzhGyhm06y5+tIISo4GdMIGaMB8GA1UdIwQYMBaAFOWt
1/TFu8chuxS07pumdRXym3nMMA8GA1UdEwEB/wQFMAMBAf8wNwYDVR0fBDAwLjAs
oCqgKIYmaHR0cDovLzIxMC43NC40Mi4zL0FDU19DQS9TTTIvY3JsMS5jcmwwDgYD
VR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQObS0zBI7wCm48/LZ8tTP1uhF7+DAMBggq
gRzPVQGDdQUAA0cAMEQCIHv5SI4cmJ/3pfmpSTgsKLg9rUuHwNtBbEY1Ml1vM9Fc
AiAtPNvgHkQih6a0cAb+isGs5iz+SHAflBIZ4XSTPzKSIQ==
-----END CERTIFICATE-----
)";

static const char* kCfcaAcsSm2Oca33Cert_prod = R"(
-----BEGIN CERTIFICATE-----
MIICpjCCAkqgAwIBAgIFEAAAACEwDAYIKoEcz1UBg3UFADBYMQswCQYDVQQGEwJD
TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRcwFQYDVQQDDA5DRkNBIENTIFNNMiBDQTAeFw0xNzA5MDQwNjA5NTBaFw0z
NTA3MDQwNjA5NTBaMFwxCzAJBgNVBAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5h
bmNpYWwgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxGzAZBgNVBAMMEkNGQ0EgQUNT
IFNNMiBPQ0EzMzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABPKsFb94jy++PGk3
E8pqrjIgchl4Xt19wzu81SQGxLSFXrHW2rwsd4qxCHMLwmRBsGuw3Yp6mVYfGFoA
N8BOakSjgfowgfcwHwYDVR0jBBgwFoAU5I7d1KPntg/uHSeWzXXcJSVyad0wDwYD
VR0TAQH/BAUwAwEB/zCBkwYDVR0fBIGLMIGIMFWgU6BRpE8wTTELMAkGA1UEBhMC
Q04xEzARBgNVBAoMCkNGQ0EgQ1MgQ0ExDDAKBgNVBAsMA0NSTDEMMAoGA1UECwwD
U00yMQ0wCwYDVQQDDARjcmwxMC+gLaArhilodHRwOi8vY3JsLmNmY2EuY29tLmNu
L2NzcmNhL1NNMi9jcmwxLmNybDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFBHQ
KCGe9HJZ/mQI6Z3bpGmEEnG8MAwGCCqBHM9VAYN1BQADSAAwRQIgF34Iz+NKqyZc
sAkqp0xRg8s9o264LqsPhNsliSqZnIkCIQDiCdM6jFxmwCWRL3tmqUTG3mPNVgJq
S2zGghB33R/kLg==
-----END CERTIFICATE-----
)";

static const char* kLocalcaAcsSm2Oca33Cert = R"(
-----BEGIN CERTIFICATE-----
MIIBojCCAUigAwIBAgIJAJ8N93M4HhRiMAoGCCqBHM9VAYN1MCwxCzAJBgNVBAYT
AkNOMQswCQYDVQQIDAJCSjEQMA4GA1UEAwwHUk9PVCBDQTAeFw0yMTA3MjAwNzI0
MDNaFw0yMjA3MjAwNzI0MDNaMCwxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJCSjEQ
MA4GA1UEAwwHUk9PVCBDQTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABPrZys4y
mi1rjMSIS/QY0Si0N5Wbn7vpP43w23GMszmKUyKWQo98JG2CmYSz/rYgPPVxMOX/
/AueSCXoMkHG0GOjUzBRMB0GA1UdDgQWBBR7JvYS5oU8PI+y7mjm4RJ8Yx3rJjAf
BgNVHSMEGDAWgBR7JvYS5oU8PI+y7mjm4RJ8Yx3rJjAPBgNVHRMBAf8EBTADAQH/
MAoGCCqBHM9VAYN1A0gAMEUCIF7fpA/8znc8O07lROxPWBmGTaiiQABCaIvWGFad
AYImAiEAvyH0n+H+V3r0ngc/8GKLpxpGrPLy3Z+5Ndtds4j8XpM=
-----END CERTIFICATE-----  
)";
static const char* cfcaIssuer_dev = R"(CFCA ACS TEST SM2 OCA33)";
static const char* cfcaIssuer_prod = R"(CFCA ACS SM2 OCA33)";
static const char* cnPrefix = R"(/CN=)";

static int parse_sequence(uint8_t* seq, uint8_t** p_content) {
  int len = 0;
  uint8_t* ptr = seq;
  if (*ptr != 0x30) {
    return 0;
  }

  if (*(++ptr) < 0x80) {
    len = (*(ptr++) + 2);
    *p_content = ptr;
    return len;
  }

  int len_of_len = *(ptr++) - 0x80;
  for (int i = 0; i < len_of_len; i++) {
    len = (len)*256 + *(ptr++);
  }
  *p_content = ptr;
  return len_of_len + len + 2;
}

static int decode_x_or_y(uint8_t* der_sig, uint8_t* raw_sig) {
  uint8_t* src = der_sig;
  uint8_t* dst = raw_sig;
  int len = 0;

  if (*src != 0x02) {
    return 0;
  }

  if (*(++src) == 0x20) {
    src++;
    len = 2;
  } else {
    src += 2;
    len = 3;
  }
  memcpy(dst, src, SM2_COOR_SIZE);
  return len + SM2_COOR_SIZE;
}

static int der_decode_signature(uint8_t* der_sig, uint8_t* raw_sig) {
  uint8_t* src = der_sig;
  uint8_t* dst = raw_sig;
  int x_len = 0;

  if (*src != 0x30) {
    return 0;
  }

  int sig_len = *(++src);
  src++;
  x_len = decode_x_or_y(src, dst);
  if (x_len <= 0) {
    return 0;
  }

  dst += SM2_COOR_SIZE;
  src += x_len;
  x_len = decode_x_or_y(src, dst);
  if (x_len <= 0) {
    return 0;
  }
  return sig_len + 2;
}

static int parse_signature(uint8_t* cert, int len, uint8_t* sig) {
  uint8_t* ptr = cert + len - (8 + SM2_COOR_SIZE * 2);
  uint8_t* end = cert + len;
  int i = 0;

  while (i < 3) {
    if (*ptr == 0x30 && *(ptr + 1) == (uint8_t)(end - (ptr + 2)) &&
        *(ptr + 2) == 0x02) {
      break;
    }
    ptr++;
    i++;
  }
  if (i >= 3) {
    return 0;
  }
  return der_decode_signature(ptr, sig);
}

static int parse_der_cert(uint8_t* cert,
                          int cert_len,
                          uint8_t* tbs_cert,
                          int* ptbs_len,
                          uint8_t* cert_sig,
                          int* psig_len) {
  if (!cert || cert_len <= 0 || !tbs_cert || !ptbs_len || !cert_sig ||
      !psig_len) {
    ELOG_ERROR("Invalid parameter");
    return 0;
  }

  uint8_t* ptr = NULL;
  int len = parse_sequence(cert, &ptr);
  if (len <= 0 || !ptr) {
    ELOG_ERROR("Fail to parse certificate");
    return 0;
  }
  uint8_t* head = ptr;
  len = parse_sequence(head, &ptr);
  if (len <= 0 || !ptr) {
    ELOG_ERROR("Fail to parse certificate");
    return 0;
  }
  if (*ptbs_len < len) {
    ELOG_ERROR("Too small tbs_cert buff: %d<%d", *ptbs_len, len);
    return 0;
  }
  memcpy(tbs_cert, head, len);
  *ptbs_len = len;
  len = parse_signature(cert, cert_len, cert_sig);
  if (len <= 0) {
    ELOG_ERROR("Fail to parse certificate");
    return 0;
  }
  if (*psig_len < 2 * SM2_COOR_SIZE) {
    ELOG_ERROR("Invalid signature buffer");
    return 0;
  }
  *psig_len = 2 * SM2_COOR_SIZE;
  return len;
}

static int der_encode_x_or_y(uint8_t* coordinate,
                             unsigned int len,
                             uint8_t* der_sig) {
  unsigned int added = 0;
  uint8_t byte = *coordinate;
  uint8_t* ptr = der_sig;
  *ptr++ = 0x02;
  if (byte & 0x80) {
    *ptr++ = 0x21;
    *ptr++ = 0x00;
    added = 3;
  } else {
    *ptr++ = 0x20;
    added = 2;
  }
  memcpy(ptr, coordinate, len);
  return len + added;
}

static int der_encode_signature(uint8_t* raw_sig,
                                unsigned int raw_sig_len,
                                uint8_t* der_sig) {
  if (!raw_sig || !der_sig || raw_sig_len != SM2_SIG_SIZE) {
    ELOG_ERROR("Invalid parameter");
    return 0;
  }
  uint8_t* ptr = der_sig;
  uint8_t* half = raw_sig + (raw_sig_len / 2);
  *ptr = 0x30;
  ptr += 2;
  int len = der_encode_x_or_y(raw_sig, raw_sig_len / 2, ptr);
  ptr += len;
  len += der_encode_x_or_y(half, raw_sig_len / 2, ptr);
  *(der_sig + 1) = len;
  return len + 2;  // 0x30+len
}

static int sm2_compute_z_digest(uint8_t* out,
                                const EVP_MD* digest,
                                const uint8_t* id,
                                const size_t id_len,
                                const EC_KEY* key) {
  UniqueEvpMdCtx md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  UniqueBnCtx bn_ctx(BN_CTX_new(), BN_CTX_free);
  EVP_MD_CTX* hash = md_ctx.get();
  BN_CTX* ctx = bn_ctx.get();
  if (hash == nullptr || ctx == nullptr) {
    return 0;
  }

  BIGNUM* p = BN_CTX_get(ctx);
  BIGNUM* a = BN_CTX_get(ctx);
  BIGNUM* b = BN_CTX_get(ctx);
  BIGNUM* xG = BN_CTX_get(ctx);
  BIGNUM* yG = BN_CTX_get(ctx);
  BIGNUM* xA = BN_CTX_get(ctx);
  BIGNUM* yA = BN_CTX_get(ctx);
  if (yA == NULL) {
    return 0;
  }

  if (!EVP_DigestInit(hash, digest)) {
    return 0;
  }

  if (id_len >= (UINT16_MAX / 8)) {
    ELOG_ERROR("Too large id length");
    return 0;
  }
  uint16_t entl = (uint16_t)(8 * id_len);
  uint8_t e_byte = entl >> 8;
  if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
    return 0;
  }
  e_byte = entl & 0xFF;
  if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
    return 0;
  }

  if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
    return 0;
  }

  const EC_GROUP* group = EC_KEY_get0_group(key);
  if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
    return 0;
  }

  int p_bytes = BN_num_bytes(p);
  UniqueOpensslBuf openssl_buf((uint8_t*)malloc(p_bytes), free);
  uint8_t* buf = openssl_buf.get();
  if (buf == nullptr) {
    return 0;
  }
  if (BN_bn2binpad(a, buf, p_bytes) < 0 ||
      !EVP_DigestUpdate(hash, buf, p_bytes) ||
      BN_bn2binpad(b, buf, p_bytes) < 0 ||
      !EVP_DigestUpdate(hash, buf, p_bytes) ||
      !EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group),
                                       xG, yG, ctx) ||
      BN_bn2binpad(xG, buf, p_bytes) < 0 ||
      !EVP_DigestUpdate(hash, buf, p_bytes) ||
      BN_bn2binpad(yG, buf, p_bytes) < 0 ||
      !EVP_DigestUpdate(hash, buf, p_bytes) ||
      !EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key), xA,
                                       yA, ctx) ||
      BN_bn2binpad(xA, buf, p_bytes) < 0 ||
      !EVP_DigestUpdate(hash, buf, p_bytes) ||
      BN_bn2binpad(yA, buf, p_bytes) < 0 ||
      !EVP_DigestUpdate(hash, buf, p_bytes) ||
      !EVP_DigestFinal(hash, out, NULL)) {
    return 0;
  }

  return 1;
}

static BIGNUM* sm2_compute_msg_hash(const EVP_MD* digest,
                                    const EC_KEY* key,
                                    const uint8_t* id,
                                    const size_t id_len,
                                    const uint8_t* msg,
                                    size_t msg_len) {
  UniqueEvpMdCtx hash(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (hash.get() == nullptr) {
    return NULL;
  }

  const int md_size = EVP_MD_size(digest);
  if (md_size <= 0) {
    return NULL;
  }

  UniqueOpensslBuf zbuf((uint8_t*)malloc(md_size), free);
  if (zbuf.get() == nullptr) {
    return NULL;
  }

  if (!sm2_compute_z_digest(zbuf.get(), digest, id, id_len, key)) {
    return NULL;
  }

  if (!EVP_DigestInit(hash.get(), digest) ||
      !EVP_DigestUpdate(hash.get(), zbuf.get(), md_size) ||
      !EVP_DigestUpdate(hash.get(), msg, msg_len) ||
      !EVP_DigestFinal(hash.get(), zbuf.get(), NULL)) {
    return NULL;
  }

  return BN_bin2bn(zbuf.get(), md_size, NULL);
}

static int sm2_signature_verify(const EC_KEY* key,
                                const ECDSA_SIG* sig,
                                const BIGNUM* e) {
  const EC_GROUP* group = EC_KEY_get0_group(key);
  const BIGNUM* order = EC_GROUP_get0_order(group);
  const BIGNUM* r = NULL;
  const BIGNUM* s = NULL;

  UniqueBnCtx bn_ctx(BN_CTX_new(), BN_CTX_free);
  UniqueEcPoint ec_point(EC_POINT_new(group), EC_POINT_free);
  BN_CTX* ctx = bn_ctx.get();
  EC_POINT* pt = ec_point.get();
  if (ctx == nullptr || pt == nullptr) {
    return 0;
  }

  BN_CTX_start(ctx);
  BIGNUM* t = BN_CTX_get(ctx);
  BIGNUM* x1 = BN_CTX_get(ctx);
  if (x1 == NULL) {
    return 0;
  }
  ECDSA_SIG_get0(sig, &r, &s);
  if (BN_cmp(r, BN_value_one()) < 0 || BN_cmp(s, BN_value_one()) < 0 ||
      BN_cmp(order, r) <= 0 || BN_cmp(order, s) <= 0) {
    return 0;
  }

  if (!BN_mod_add(t, r, s, order, ctx)) {
    return 0;
  }
  if (BN_is_zero(t)) {
    return 0;
  }

  if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx) ||
      !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
    return 0;
  }

  if (!BN_mod_add(t, e, x1, order, ctx)) {
    return 0;
  }

  if (BN_cmp(r, t) != 0) {
    return 0;
  }

  return 1;
}

static int sm2_do_verify_sig(const EC_KEY* key,
                             const EVP_MD* digest,
                             const ECDSA_SIG* sig,
                             const uint8_t* id,
                             const size_t id_len,
                             const uint8_t* msg,
                             size_t msg_len) {
  UniqueBigNum e(sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len),
                 BN_free);
  if (e.get() == nullptr) {
    return 0;
  }
  return sm2_signature_verify(key, sig, e.get());
}

static int crypto_sm2_verify(uint8_t* msg,
                             int msg_len,
                             uint8_t* sig,
                             int sig_len,
                             uint8_t* user_id,
                             int user_id_len,
                             uint8_t* raw_key,
                             int raw_key_len) {
  UniqueEcGroup g(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
  UniqueEcPoint p(EC_POINT_new(g.get()), EC_POINT_free);
  EC_POINT_oct2point(g.get(), p.get(), raw_key, raw_key_len, NULL);
  UniqueEcKey eckey(EC_KEY_new(), EC_KEY_free);
  EC_KEY* ec_key = eckey.get();
  if (!ec_key || EC_KEY_set_group(ec_key, g.get()) <= 0) {
    ELOG_ERROR("EC_KEY_set_group err");
    return 0;
  }
  int ret = EC_KEY_set_public_key(ec_key, p.get());
  if (ret != 1) {
    ELOG_ERROR("EC_KEY_set_public_key ret=%d", ret);
    return 0;
  }

  uint8_t der_sig[128];
  int der_sig_len = der_encode_signature(sig, sig_len, der_sig);
  uint8_t* p_sig = (uint8_t*)der_sig;
  UniqueEcdsaSig ecdsa_sig(
      d2i_ECDSA_SIG(NULL, (const uint8_t**)&p_sig, der_sig_len),
      ECDSA_SIG_free);
  if (ecdsa_sig.get() == nullptr) {
    ELOG_ERROR("ecdsa_sig is null");
    return 0;
  }
  ret = sm2_do_verify_sig(ec_key, EVP_sm3(), ecdsa_sig.get(), user_id,
                          user_id_len, msg, msg_len);
  ELOG_DEBUG("sm2_do_verify ret=%d", ret);
  ELOG_DEBUG("msg_len=%d sig_len=%d raw_key_len=%d", msg_len, sig_len,
             raw_key_len);
  return ret;
}

static TeeErrorCode get_cer_into_der(uint8_t* pem_cert,
                                     int cert_len,
                                     std::string* der_cert) {
  char base64_cert[PEM_CERT_BUF_SIZE] = {0};
  memset(base64_cert, 0, sizeof(base64_cert));
  char* base64_cert_ptr = RCAST(char*, base64_cert);
  constexpr int kTempBufLen = 256;
  char buff[kTempBufLen];
  int buf_index = 0;
  int left = sizeof(base64_cert);
  for (int i = 0; i < cert_len; i++) {
    if (pem_cert[i] != '\r' && pem_cert[i] != '\n') {
      buff[buf_index++] = pem_cert[i];
      if (buf_index >= kTempBufLen) {
        return TEE_ERROR_CRYPTO_CERT;
      }
      if ((i + 1) != cert_len) {
        continue;
      }
    }
    // Get line and handle it, ignore the "-----xxx-----" line
    // For '\r\n' case, buf_index will also be zero at '\n'
    buff[buf_index] = 0;
    if (buff[0] != '-' && buf_index != 0) {
      strncat(base64_cert_ptr, buff, left);
      base64_cert_ptr += strlen(buff);
      left -= strlen(buff);
    }
    buf_index = 0;
  }
  size_t count = base64_cert_ptr - base64_cert;
  DataBytes b64_cert(RCAST(uint8_t*, base64_cert), count);
  der_cert->assign(b64_cert.FromBase64().GetStr());
  return TEE_SUCCESS;
}

static TeeErrorCode get_pubkey_from_cert(uint8_t* cert,
                                         int cert_len,
                                         sm2_pub_key_t* pubkey) {
  std::string der_cert;
  TEE_CHECK_RETURN(get_cer_into_der(cert, cert_len, &der_cert));
  const uint8_t* cert_ptr = RCCAST(uint8_t*, der_cert.data());
  int der_len = der_cert.size();
  UniqueX509 cert_x509(d2i_X509(NULL, &cert_ptr, der_len), X509_free);
  if (cert_x509.get() == nullptr) {
    ELOG_ERROR("Fail to load ca certificate");
    return TEE_ERROR_CRYPTO_CERT;
  }
  UniquePkey pkey(X509_get_pubkey(cert_x509.get()), EVP_PKEY_free);
  if (pkey.get() == nullptr) {
    ELOG_ERROR("Fail to get public key from ca certificate");
    return TEE_ERROR_CRYPTO_CERT;
  }
  UniqueEcKey eckey(EVP_PKEY_get1_EC_KEY(pkey.get()), EC_KEY_free);
  if (eckey.get() == nullptr) {
    ELOG_ERROR("Fail to get the EC key from public key");
    return TEE_ERROR_CRYPTO_CERT;
  }

  size_t keylen = sizeof(sm2_pub_key_t);
  const EC_GROUP* group = EC_KEY_get0_group(eckey.get());
  const EC_POINT* point = EC_KEY_get0_public_key(eckey.get());
  if (keylen != EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   pubkey->key, keylen, NULL)) {
    ELOG_ERROR("Fail to get the raw pub key");
    return TEE_ERROR_CRYPTO_CERT;
  }

  return TEE_SUCCESS;
}

static int verify_der_cert(uint8_t* der_cert,
                           int der_cert_len,
                           uint8_t* ca_cert,
                           int ca_cert_len) {
  sm2_pub_key_t pubkey;
  if (TEE_SUCCESS != get_pubkey_from_cert(ca_cert, ca_cert_len, &pubkey)) {
    return 0;
  }

  uint8_t tbs_cert[DER_CERT_BUF_SIZE];
  uint8_t cert_sig[SM2_SIG_SIZE];
  int tbs_cert_len = sizeof(tbs_cert);
  int cert_sig_len = sizeof(cert_sig);
  int ret = parse_der_cert(der_cert, der_cert_len, tbs_cert, &tbs_cert_len,
                           cert_sig, &cert_sig_len);
  if (ret <= 0 || tbs_cert_len <= 0 || cert_sig_len <= 0) {
    ELOG_ERROR("Fail to parse the der certificate");
    return 0;
  }
  uint8_t user_id[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
  return crypto_sm2_verify(tbs_cert, tbs_cert_len, cert_sig, cert_sig_len,
                           user_id, sizeof(user_id), pubkey.key,
                           sizeof(sm2_pub_key_t));
}

static int check_cfca_cert_issuer(uint8_t* der_cert, int cert_len) {
  UniqueX509 cert_x509(d2i_X509(NULL, (const uint8_t**)&der_cert, cert_len),
                       X509_free);
  if (cert_x509.get() == nullptr) {
    ELOG_ERROR("Fail to load ca certificate");
    return TEE_ERROR_CRYPTO_CERT;
  }

  char* issuer =
      X509_NAME_oneline(X509_get_issuer_name(cert_x509.get()), NULL, 0);
  if (!issuer) {
    ELOG_ERROR("Fail to get issuer");
    return TEE_ERROR_CRYPTO_CERT;
  }

  char* pcn = strstr(issuer, cnPrefix);
  if (!pcn) {
    ELOG_ERROR("pcn info error");
    return TEE_ERROR_CRYPTO_CERT;
  }

  pcn += strlen(cnPrefix);
  if ((memcmp(cfcaIssuer_dev, pcn, strlen(cfcaIssuer_dev)) == 0) ||
      (memcmp(cfcaIssuer_prod, pcn, strlen(cfcaIssuer_prod)) == 0)) {
    return TEE_SUCCESS;
  }

  return TEE_ERROR_CRYPTO_CERT;
}

bool verify_cert_chain_local(uint8_t* der_cert, int der_cert_len) {
  uint8_t* ca_cert = RCCAST(uint8_t*, kLocalcaAcsSm2Oca33Cert);
  int ca_cert_len = strlen(kLocalcaAcsSm2Oca33Cert);
  return verify_der_cert(der_cert, der_cert_len, ca_cert, ca_cert_len);
}

bool verify_cert_chain_cfca(uint8_t* der_cert, int der_cert_len) {
  uint8_t* ca_cert = RCCAST(uint8_t*, kCfcaAcsSm2Oca33Cert_prod);
  int ca_cert_len = strlen(kCfcaAcsSm2Oca33Cert_prod);
  bool ret = verify_der_cert(der_cert, der_cert_len, ca_cert, ca_cert_len);
  if (!ret) {
    uint8_t* ca_cert_dev = RCCAST(uint8_t*, kCfcaAcsSm2Oca33Cert_dev);
    int ca_cert_dev_len = strlen(kCfcaAcsSm2Oca33Cert_dev);
    ret = verify_der_cert(der_cert, der_cert_len, ca_cert_dev, ca_cert_dev_len);
  }
  return ret;
}

bool verify_peer_cert(uint8_t* der_cert, int der_cert_len) {
  // We have not verified the before/after data time in certificate
  // as we have no trusted time in enclave.
  if (!der_cert || !der_cert_len) {
    ELOG_ERROR("Invalid certificate to be verified");
    return false;
  }

  bool ret = false;
  if (check_cfca_cert_issuer(der_cert, der_cert_len) == TEE_SUCCESS) {
    ret = verify_cert_chain_cfca(der_cert, der_cert_len);
  } else {
    ret = verify_cert_chain_local(der_cert, der_cert_len);
  }

  if (ret) {
    ELOG_DEBUG("Verify peer certificate successfully");
  } else {
    ELOG_ERROR("Fail to verify peer certificate");
  }

  return ret;
}

#ifdef __cplusplus
}
#endif
