#ifndef UAL_INCLUDE_UNIFIED_ATTESTATION_UA_TRUSTED_H_
#define UAL_INCLUDE_UNIFIED_ATTESTATION_UA_TRUSTED_H_

// Should add the following PATH to the header include path
// ${UAL_TOP_DIR}/include

#ifndef TEE_TRUSTED
#define TEE_TRUSTED
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
#include "attestation/common/sm2.h"
#include "attestation/common/table.h"
#include "attestation/common/type.h"
#include "attestation/common/uak.h"
#include "attestation/instance/trusted_tee_instance.h"
#include "attestation/instance/trusted_tee_instance_interface.h"
#include "attestation/instance/trusted_unified_function.h"
#include "attestation/verification/core/verifier.h"
#include "attestation/verification/core/verifier_interface.h"
#include "attestation/verification/ua_verification.h"
#include "attestation/verification/unified_attestation_verification.h"

#endif  // UAL_INCLUDE_UNIFIED_ATTESTATION_UA_TRUSTED_H_
