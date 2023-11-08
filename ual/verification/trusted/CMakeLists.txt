set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format -DTEE_TRUSTED -DSGX_TRUSTED")

find_package(Protobuf REQUIRED)
file(GLOB PROTO_FILES
    ${UAL_TOP_DIR}/proto/attestation.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

file(GLOB COMMON_SRCS ${UAL_TOP_DIR}/common/*.cpp)
file(GLOB COMMON_PLATFORMS_SRCS ${UAL_TOP_DIR}/common/platforms/*.cpp)
file(GLOB UTILS_SRCS ${UAL_TOP_DIR}/utils/trusted/*.cpp)
file(GLOB CORE_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../core/*.cpp)
file(GLOB TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
# Add the platform files
file(GLOB PLATFORM_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/*.cpp)
# Add the platform special files for UAS
file(GLOB UAS_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../uas/*.cpp)
# Add the platform special files for SGX1 EPID
file(GLOB PLATFORM_SGX1_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/sgx1/*.cpp)
# Add the platform special files for HyperEnclave
file(GLOB PLATFORM_HYEN_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/hyperenclave/*.cpp)
# Add the platform special files for SGX2 DCAP
set(PLATFORM_SRC_DIR_SGX2_QV ${UAL_TOP_DIR}/external/dcap/QuoteVerification)
set(PLATFORM_SRC_DIR_SGX2_QVL ${UAL_TOP_DIR}/external/dcap/QuoteVerification/QVL/Src)
set(PLATFORM_SRC_DIR_SGX2_QVE ${UAL_TOP_DIR}/external/dcap/QuoteVerification/QvE)
file(GLOB_RECURSE PLATFORM_SGX2_SRCS_QVL_COMMONS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/sgx2/Utils/*.cpp)
file(GLOB_RECURSE PLATFORM_SGX2_SRCS_QVL_LIBRARY ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationLibrary/*.cpp)
file(GLOB_RECURSE PLATFORM_SGX2_SRCS_QVL_PARSERS ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationParsers/*.cpp)
file(GLOB PLATFORM_SGX2_SRCS_VERIFICATION ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/sgx2/*.cpp)
set(PLATFORM_SGX2_SRCS
    ${PLATFORM_SRC_DIR_SGX2_QVE}/Enclave/qve.cpp
    ${PLATFORM_SGX2_SRCS_QVL_COMMONS}
    ${PLATFORM_SGX2_SRCS_QVL_LIBRARY}
    ${PLATFORM_SGX2_SRCS_QVL_PARSERS}
    ${PLATFORM_SGX2_SRCS_VERIFICATION}
)
# Add the platform special files for Hygon CSV
file(GLOB_RECURSE PLATFORM_CSV_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/csv/*.cpp)
# Add the platform special files for Intel TDX
file(GLOB_RECURSE PLATFORM_TDX_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/tdx/*.cpp)
# Add the platform special files for Kunpeng
file(GLOB_RECURSE PLATFORM_KUNPENG_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../platforms/kunpeng/*.cpp)
set(PLATFORM_INCS
    ./
    ${PLATFORM_SRC_DIR_SGX2_QV}/dcap_quoteverify/inc/
    ${PLATFORM_SRC_DIR_SGX2_QVE}/Include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationCommons/include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationCommons/include/Utils
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationLibrary/include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationLibrary/src
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationParsers/include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationParsers/src
)

set(LIB_UA_TVERIFICATION ua_tverification)
set(T_SRCS
    ${PROTO_SRCS}
    ${COMMON_SRCS}
    ${COMMON_PLATFORMS_SRCS}
    ${UTILS_SRCS}
    ${CORE_SRCS}
    ${PLATFORM_SRCS}
    ${UAS_SRCS}
    ${PLATFORM_SGX1_SRCS}
    ${PLATFORM_SGX2_SRCS}
    ${PLATFORM_HYEN_SRCS}
    ${PLATFORM_CSV_SRCS}
    ${PLATFORM_TDX_SRCS}
    ${PLATFORM_KUNPENG_SRCS}
    ${TRUSTED_SRCS}
)

include_directories(
    ${PLATFORM_INCS}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/rapidjson/include
    ${UAL_TOP_DIR}/external/protobuf-cpp/src/
    ${SGXSSL_INCLUDE_DIR}
)

add_trusted_library_without_edl(
    ${LIB_UA_TVERIFICATION}
    SRCS ${T_SRCS}
)

target_link_libraries(
    ${LIB_UA_TVERIFICATION}
    -ltprotobuf
)

add_dependencies(${LIB_UA_TVERIFICATION} tprotobuf)

install(
    TARGETS ${LIB_UA_TVERIFICATION}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
