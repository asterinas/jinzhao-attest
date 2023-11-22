set(UAL_TOP_DIR ${CMAKE_SOURCE_DIR}/ual)
list(APPEND CMAKE_MODULE_PATH ${UA_TOP_DIR}/cmake)
include(${UA_TOP_DIR}/cmake/CheckTeeEnv.cmake)

# Set the default enclave settings to what in UAL
if(HAS_TEE STREQUAL "ON")
    set(ENCLAVE_KEY ${UAL_TOP_DIR}/enclave/enclave_private.pem)
    set(ENCLAVE_LDS ${UAL_TOP_DIR}/enclave/lds/enclave_${TEE_TYPE}.lds)
    set(ENCLAVE_XML ${UAL_TOP_DIR}/enclave/config/enclave.config.${BUILD_MODE}.xml)
    set(ENCLAVE_EDL_SEARCH_PATHS_UAL
        ${UAL_TOP_DIR}/enclave/edl
        ${UAL_TOP_DIR}/include
        ${SGXSSL_INCLUDE_DIR}
    )
endif()

# How to build the samples for different environment
# For LibOS like OCCLUM, all samples run in trusted environment
message("SGXSSL INC: ${SGXSSL_INCLUDE_DIR}")
# Only support the following samples for static building
add_subdirectory(unified-attestation-verification-untrusted)
add_subdirectory(unified-attestation-instance-ree)
if(BUILD_STATIC STREQUAL "OFF")
    add_subdirectory(unified-attestation-generation)
    add_subdirectory(unified-attestation-report-convert)
    if(HAS_TEE STREQUAL "ON")
        add_subdirectory(unified-attestation-verification-trusted)
        add_subdirectory(unified-attestation-multi-threads)
    endif()
endif()
# Don't support the neste report sample in SGXSDK mode
# Because we need to make sure nested result and signature
# is generated in trusted code
if(NOT ENV_TYPE STREQUAL "SGXSDK")
    add_subdirectory(unified-attestation-nested-report)
endif()
