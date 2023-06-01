set(UAL_TOP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
list(APPEND CMAKE_MODULE_PATH ${UA_TOP_DIR}/cmake)
include(${UA_TOP_DIR}/cmake/CheckTeeEnv.cmake)

if(HAS_TEE STREQUAL "ON")
    # Common settings for add_enclave_library
    set(ENCLAVE_KEY ${UAL_TOP_DIR}/enclave/enclave_private.pem)
    set(ENCLAVE_LDS ${UAL_TOP_DIR}/enclave/lds/enclave_${TEE_TYPE}.lds)
    set(ENCLAVE_XML ${UAL_TOP_DIR}/enclave/config/enclave.config.${BUILD_MODE}.xml)
    set(ENCLAVE_EDL_SEARCH_PATHS_UAL
        ${UAL_TOP_DIR}/enclave/edl
        ${UAL_TOP_DIR}/include
        ${SGXSSL_INCLUDE_DIR}
    )
endif()

# Build the unified attestation libraries
# For LibOS like OCCLUM, untrusted code also run in trusted environment
if(BUILD_MERGED_LIBS STREQUAL "OFF")
    add_subdirectory(network)
    add_subdirectory(instance/untrusted)
    add_subdirectory(generation/untrusted)
    add_subdirectory(verification/untrusted)
    if(HAS_TEE STREQUAL "ON")
        # Libraries for SDK partation mode
        add_subdirectory(external/protobuf-cpp/src/google/protobuf)
        add_subdirectory(instance/trusted)
        add_subdirectory(generation/trusted)
        add_subdirectory(verification/trusted)
    endif()
else() # BUILD_MERGED_LIBS == ON 
    add_subdirectory(cmake/ual_untrusted)
    if(HAS_TEE STREQUAL "ON")
        add_subdirectory(cmake/ual_trusted)
    endif()
endif()
if(ENV_TYPE STREQUAL "SGXSDK")
    # Don't build GRPC by default for OCCLUM and VMTEE
    add_subdirectory(grpc)
endif()

# Install all header files in include directory
install(DIRECTORY include
        DESTINATION ${CMAKE_INSTALL_PREFIX}
        FILES_MATCHING
        PATTERN "google" EXCLUDE
        PATTERN "rapidjson" EXCLUDE
        PATTERN "cppcodec" EXCLUDE
        PATTERN "*")
install(DIRECTORY external/cppcodec/cppcodec
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
        FILES_MATCHING PATTERN "*")
install(DIRECTORY external/protobuf-cpp/src/google
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY external/rapidjson/include/rapidjson
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
        FILES_MATCHING PATTERN "*")
