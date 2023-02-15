#ifndef UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_UNIFIED_FUNCTION_H_
#define UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_UNIFIED_FUNCTION_H_

#include <string>

#include "attestation/common/error.h"
#include "attestation/common/table.h"
#include "attestation/common/type.h"

namespace kubetee {
namespace attestation {

// TeeUnifiedFunctions is to manage trusted unified functions
class TeeUnifiedFunctions {
 public:
  // Gets the singleton manager instance handler
  static TeeUnifiedFunctions& Mgr() {
    static TeeUnifiedFunctions mgr_instance_;
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
  TeeUnifiedFunctions() {
    is_functions_registed_ = false;
  }
  TeeUnifiedFunctions(const TeeUnifiedFunctions&);
  void operator=(TeeUnifiedFunctions const&);

  bool is_functions_registed_;
  kubetee::common::DataTable<UnifiedFunction> functions_;
};

}  // namespace attestation
}  // namespace kubetee

#define ADD_TRUSTED_UNIFIED_FUNCTION(f) \
  kubetee::attestation::TeeUnifiedFunctions::Mgr().Functions().Add(#f, f)

#ifdef __cplusplus
extern "C" {
#endif

extern TeeErrorCode RegisterTrustedUnifiedFunctionsInternal();
extern TeeErrorCode RegisterTrustedUnifiedFunctionsEx();

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_INSTANCE_TRUSTED_UNIFIED_FUNCTION_H_
