#ifndef UAL_INCLUDE_ATTESTATION_COMMON_ATTESTATION_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_ATTESTATION_H_

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

// Const variables for attestation
#define USER_DATA_MAX 32

// Current UnifiedAttestationReport version
extern const char kCurrentUarVersion[];
// Current Unified Attestation Library version
extern const char kCurrentUalVersion[];

// TEE platform names
extern const char kUaPlatformSgxEpid[];
extern const char kUaPlatformSgxDcap[];
extern const char kUaPlatformHyperEnclave[];
extern const char kUaPlatformCsv[];
extern const char kUaPlatformTdx[];
extern const char kUaPlatformKunpeng[];

// Unified attestation report type names
extern const char kUaReportTypeBgcheck[];
extern const char kUaReportTypePassport[];
extern const char kUaReportTypeUas[];

// Trust application attributes names
extern const char kUaAttrPlatform[];
extern const char kUaAttrPlatformHwVer[];
extern const char kUaAttrPlatformSwVer[];
extern const char kUaAttrSecureFlags[];
extern const char kUaAttrMrplatform[];
extern const char kUaAttrMrboot[];
extern const char kUaAttrTeeName[];
extern const char kUaAttrTeeID[];
extern const char kUaAttrMrTa[];
extern const char kUaAttrMrTaDyn[];
extern const char kUaAttrSigner[];
extern const char kUaAttrProdID[];
extern const char kUaAttrIsvSvn[];
extern const char kUaAttrDebugDisabled[];
extern const char kUaAttrUserData[];
extern const char kUaAttrPublickey[];
extern const char kUaAttrNonce[];
extern const char kUaAttrSpid[];
extern const char kUaAttrVerifiedTime[];

extern const char kUaNestedGroupName[];
extern const char kUaNestedGroupID[];

// Size of each type of UnifiedAttestationReport
extern const int kUaReportSizeBgcheck;
extern const int kUaReportSizePassport;
extern const int kUaReportSizeUas;

// when generation ra report for occlum/VMTEE, Eid is not used
// But the interfaces need a eid, so define this dummy one
extern const char kDummyTeeIdentity[];

// Empty TEE identity
extern const char kEmptyTeeIdentity[];

// C++ API for both trusted code nad untrusted code
//
// Nothing for C++ here, now
//

// C API for both trusted code nad untrusted code

/// @brief C API for get the pre-alloc ua_report_buf or auth_report_buf size
///
/// @param report_type: The type of unified attestation report
///
/// @return The size of buf which is large enough, but not the exact size.
///
extern int UnifiedAttestationReportSize(const char* report_type,
                                        unsigned int* report_size);

#ifdef __cplusplus
}
#endif

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_ATTESTATION_H_
