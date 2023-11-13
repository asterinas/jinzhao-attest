set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${ENCLAVE_EDL_SEARCH_PATHS_UAL}
)
set(E_SRCS
    ${PROTO_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.cpp
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${UAL_TOP_DIR}/include
)

# Build the trusted enclave
if(ENV_TYPE STREQUAL "SGXSDK")
    set(TLIBS ${UAL_T_LIBS_NAME})
    set(SAMPLEENCLAVE sample-unified-attestation-generation)
    add_enclave_library(
        ${SAMPLEENCLAVE}
        SRCS ${E_SRCS}
        TRUSTED_LIBS ${TLIBS}
        EDL ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.edl
        EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
        LDSCRIPT ${ENCLAVE_LDS}
    )
    target_include_directories(
        ${SAMPLEENCLAVE} PRIVATE
        ${SGXSSL_INCLUDE_DIR}
    )
    enclave_sign(
        ${SAMPLEENCLAVE}
        KEY ${ENCLAVE_KEY}
        CONFIG ${ENCLAVE_XML}
    )
endif()  #  if(ENV_TYPE STREQUAL "SGXSDK")

# Build the untrusted app
set(SAMPLEAPP app-sample-unified-attestation-generation)
set(SRCS
    ${PROTO_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/app/app.cpp
)
if(ENV_TYPE STREQUAL "SGXSDK")
    add_untrusted_executable(
        ${SAMPLEAPP}
        SRCS ${SRCS}
        EDL ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.edl
        EDL_SEARCH_PATHS ${EX_EDL_SEARCH_PATHS}
    )
else()
    add_executable(
        ${SAMPLEAPP}
        ${SRCS}
    )
endif()

target_link_libraries(
    ${SAMPLEAPP} ${UA_LINK_OPTIONS}
    -L${LIBRARY_OUTPUT_PATH} -L/usr/lib64
    -Wl,--start-group ${UAL_LIBS_LINK} -Wl,--end-group
    -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
)
add_dependencies(${SAMPLEAPP} ${UAL_LIBS_NAME})
