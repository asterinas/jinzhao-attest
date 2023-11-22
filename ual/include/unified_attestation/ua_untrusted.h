#ifndef UAL_INCLUDE_UNIFIED_ATTESTATION_UA_UNTRUSTED_H_
#define UAL_INCLUDE_UNIFIED_ATTESTATION_UA_UNTRUSTED_H_

// Should add the following PATH to the header include path
// ${UAL_TOP_DIR}/include

#ifndef TEE_UNTRUSTED
#define TEE_UNTRUSTED
#endif

// Header files in unified attestation
#include "attestation/common/aes.h"
#include "attestation/common/asymmetric_crypto.h"
#include "attestation/common/attestation.h"
#include "attestation/common/bytes.h"
#include "attestation/common/envelope.h"
#include "attestation/common/error.h"
#include "attestation/common/log.h"
#include "attestation/common/protobuf.h"
#include "attestation/common/rsa.h"
#include "attestation/common/scope.h"
#include "attestation/common/table.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/generation/core/generator.h"
#include "attestation/generation/core/generator_interface.h"
#include "attestation/generation/ua_generation.h"
#include "attestation/generation/unified_attestation_generation.h"
#include "attestation/instance/unified_attestation_instance.h"
#include "attestation/instance/untrusted_ree_instance.h"
#include "attestation/instance/untrusted_ree_instance_interface.h"
#include "attestation/instance/untrusted_unified_function.h"
#include "attestation/verification/core/verifier.h"
#include "attestation/verification/core/verifier_interface.h"
#include "attestation/verification/ua_verification.h"
#include "attestation/verification/unified_attestation_verification.h"
#ifdef UA_ENV_TYPE_SGXSDK
#include "grpc/untrusted_grpc_client.h"
#include "grpc/untrusted_grpc_server.h"
#endif
#include "network/hygon_kds_client.h"
#include "network/ias_client.h"
#include "network/pccs_client.h"
#include "network/report_convert.h"
#include "network/uas_client.h"
#include "utils/untrusted/untrusted_fs.h"
#include "utils/untrusted/untrusted_json.h"
#include "utils/untrusted/untrusted_ua_config.h"

#endif  // UAL_INCLUDE_UNIFIED_ATTESTATION_UA_UNTRUSTED_H_
