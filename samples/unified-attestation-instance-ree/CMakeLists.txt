if(BUILD_STATIC STREQUAL "ON")
set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

find_package(Protobuf REQUIRED)
set(PROTO_FILES
    ${UAL_TOP_DIR}/proto/attestation.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${UAL_TOP_DIR}/include
)

set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${ENCLAVE_EDL_SEARCH_PATHS_UAL}
)
set(E_SRCS
    ${PROTO_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.cpp
)

# Build the trusted enclave for SGXSDK only
if(ENV_TYPE STREQUAL "SGXSDK")
    set(TLIBS ${UAL_T_LIBS_NAME})
    set(SAMPLEENCLAVE sample-unified-attestation-instance-ree)
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

# Build the application for both SGXSDK/OCCLUM/VMTEE
set(SAMPLEAPP app-sample-unified-attestation-instance-ree)
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

if(BUILD_STATIC STREQUAL "OFF")
    target_link_libraries(
        ${SAMPLEAPP} ${UA_LINK_OPTIONS}
        -L${LIBRARY_OUTPUT_PATH} -L/usr/lib64
        -Wl,--start-group ${UAL_LIBS_LINK} -Wl,--end-group
        -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
    )
else()
    target_link_libraries(
        ${SAMPLEAPP} -static -fPIC
        -L${LIBRARY_OUTPUT_PATH} -L/usr/lib64
        -Wl,--start-group ${UAL_LIBS_LINK} -ldl -Wl,--end-group
        -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
    )
endif()
add_dependencies(${SAMPLEAPP} ual)
