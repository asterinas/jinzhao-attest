#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_UNIFIED_FUNCTION_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_UNIFIED_FUNCTION_H_

#include <string>

#include "attestation/common/error.h"
#include "attestation/common/table.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace attestation {

// ReeUnifiedFunctions is to manage untrusted unified functions
class ReeUnifiedFunctions {
 public:
  // Gets the singleton manager instance handler
  static ReeUnifiedFunctions& Mgr() {
    static ReeUnifiedFunctions mgr_instance_;
    return mgr_instance_;
  }

  /// Get the unified functions table
  kubetee::common::DataTable<UnifiedFunction>& Functions() {
    return functions_;
  }

  /// Register all the untrusted UnifiedFunctions (from TEE ot REE)
  TeeErrorCode RegisterFunctions();

 private:
  // Hide construction functions
  ReeUnifiedFunctions() {
    is_functions_registed_ = false;
  }
  ReeUnifiedFunctions(const ReeUnifiedFunctions&);
  void operator=(ReeUnifiedFunctions const&);

  bool is_functions_registed_;
  kubetee::common::DataTable<UnifiedFunction> functions_;
};

}  // namespace attestation
}  // namespace kubetee

#define ADD_UNTRUSTED_UNIFIED_FUNCTION(f) \
  kubetee::attestation::ReeUnifiedFunctions::Mgr().Functions().Add(#f, f)

#ifdef __cplusplus
extern "C" {
#endif

extern TeeErrorCode RegisterUntrustedUnifiedFunctionsInternal();
extern TeeErrorCode RegisterUntrustedUnifiedFunctionsEx();

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_UNTRUSTED_UNIFIED_FUNCTION_H_
