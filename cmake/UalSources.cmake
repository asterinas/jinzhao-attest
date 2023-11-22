message(STATUS "UAL top directory: ${UAL_TOP_DIR}")
file(GLOB_RECURSE COMMON_SRCS ${UAL_TOP_DIR}/common/*.cpp)
file(GLOB UTILS_U_SRCS ${UAL_TOP_DIR}/utils/untrusted/*.cpp)
file(GLOB UTILS_T_SRCS ${UAL_TOP_DIR}/utils/trusted/*.cpp)
file(GLOB_RECURSE NETWORK_U_SRCS ${UAL_TOP_DIR}/network/*.cpp)
file(GLOB_RECURSE GRPC_U_SRCS ${UAL_TOP_DIR}/grpc/*.cpp)

# Proto files
find_package(Protobuf REQUIRED)
file(GLOB UAL_PROTO_FILES ${UAL_TOP_DIR}/proto/*.proto)
PROTOBUF_GENERATE_CPP(UAL_PROTO_SRCS UAL_PROTO_HDRS ${CMAKE_BINARY_DIR} ${UAL_PROTO_FILES})

# Collect all the instance source files
set(INSTANCE_SRC_DIR ${UAL_TOP_DIR}/instance)
set(INSTANCE_SRC_PLATFORM_DIR ${UAL_TOP_DIR}/instance/platforms)
file(GLOB INSTANCE_UNTRUSTED_SRCS ${INSTANCE_SRC_DIR}/untrusted/*.cpp)
file(GLOB INSTANCE_TRUSTED_SRCS ${INSTANCE_SRC_DIR}/trusted/*.cpp)
if(ENV_TYPE STREQUAL "SGXSDK")
# For TEE_TYEP STREQUAL "HYPERENCLAVE"|"SGX1"|"SGX2"
file(GLOB INSTANCE_PLATFORM_U_SRCS ${INSTANCE_SRC_PLATFORM_DIR}/sgx/untrusted/*.cpp)
file(GLOB INSTANCE_PLATFORM_T_SRCS ${INSTANCE_SRC_PLATFORM_DIR}/sgx/trusted/*.cpp)
endif()
if(ENV_TYPE STREQUAL "OCCLUM")
# For TEE_TYEP STREQUAL "OCCLUM"
file(GLOB INSTANCE_PLATFORM_U_SRCS ${INSTANCE_SRC_PLATFORM_DIR}/occlum/*.cpp)
# Empty INSTANCE_PLATFORM_T_SRCS
endif()
set(INSTANCE_U_SRCS
    ${INSTANCE_UNTRUSTED_SRCS}
    ${INSTANCE_PLATFORM_U_SRCS}
)
set(INSTANCE_T_SRCS
    ${INSTANCE_TRUSTED_SRCS}
    ${INSTANCE_PLATFORM_T_SRCS}
)

# Collect all the generation source files
set(GENERATION_SRC_DIR ${UAL_TOP_DIR}/generation)
set(GENERATION_SRC_PLATFORM_DIR ${UAL_TOP_DIR}/generation/platforms)
file(GLOB GENERATION_CORE_SRCS ${GENERATION_SRC_DIR}/core/*.cpp)
file(GLOB GENERATION_UNTRUSTED_SRCS ${GENERATION_SRC_DIR}/untrusted/*.cpp)
file(GLOB GENERATION_TRUSTED_SRCS ${GENERATION_SRC_DIR}/trusted/*.cpp)
if(ENV_TYPE STREQUAL "SGXSDK")
    file(GLOB GENERATION_PLATFORM_C_U_SRCS ${GENERATION_SRC_PLATFORM_DIR}/sgx_common/untrusted/*.cpp)
    file(GLOB GENERATION_PLATFORM_C_T_SRCS ${GENERATION_SRC_PLATFORM_DIR}/sgx_common/trusted/*.cpp)
endif()
if(TEE_TYPE STREQUAL "HYPERENCLAVE")
    file(GLOB GENERATION_PLATFORM_U_SRCS ${GENERATION_SRC_PLATFORM_DIR}/hyperenclave/untrusted/*.cpp)
elseif(TEE_TYPE STREQUAL "SGX1")
    file(GLOB GENERATION_PLATFORM_U_SRCS ${GENERATION_SRC_PLATFORM_DIR}/sgx1/untrusted/*.cpp)
elseif(TEE_TYPE STREQUAL "SGX2")
    file(GLOB GENERATION_PLATFORM_U_SRCS ${GENERATION_SRC_PLATFORM_DIR}/sgx2/untrusted/*.cpp)
elseif(TEE_TYPE STREQUAL "CSV")
    file(GLOB GENERATION_PLATFORM_U_SRCS ${GENERATION_SRC_PLATFORM_DIR}/csv/*.cpp)
elseif(TEE_TYPE STREQUAL "TDX")
    file(GLOB GENERATION_PLATFORM_U_SRCS ${GENERATION_SRC_PLATFORM_DIR}/tdx/*.cpp)
endif()
set(GENERATION_U_SRCS
    ${GENERATION_CORE_SRCS}
    ${GENERATION_UNTRUSTED_SRCS}
    ${GENERATION_PLATFORM_C_U_SRCS}
    ${GENERATION_PLATFORM_U_SRCS}
)
set(GENERATION_T_SRCS
    ${GENERATION_TRUSTED_SRCS}
    ${GENERATION_PLATFORM_C_T_SRCS}
)

# Collect all the verification source files
set(VERIFICATION_SRC_DIR ${UAL_TOP_DIR}/verification)
set(VERIFICATION_SRC_PLATFORM_DIR ${UAL_TOP_DIR}/verification/platforms)
file(GLOB VERIFICATION_CORE_SRCS ${VERIFICATION_SRC_DIR}/core/*.cpp)
file(GLOB VERIFICATION_UNTRUSTED_SRCS ${VERIFICATION_SRC_DIR}/untrusted/*.cpp)
file(GLOB VERIFICATION_TRUSTED_SRCS ${VERIFICATION_SRC_DIR}/trusted/*.cpp)
file(GLOB_RECURSE VERIFICATION_UAS_SRCS ${VERIFICATION_SRC_DIR}/uas/*.cpp)
file(GLOB_RECURSE VERIFICATION_PLATFORM_HYPERENCLAVE_SRCS ${VERIFICATION_SRC_PLATFORM_DIR}/hyperenclave/*.cpp)
file(GLOB_RECURSE VERIFICATION_PLATFORM_SGX1_SRCS ${VERIFICATION_SRC_PLATFORM_DIR}/sgx1/*.cpp)
file(GLOB_RECURSE VERIFICATION_PLATFORM_KUNPENG_SRCS ${VERIFICATION_SRC_PLATFORM_DIR}/kunpeng/*.cpp)
file(GLOB_RECURSE VERIFICATION_PLATFORM_CSV_SRCS ${VERIFICATION_SRC_PLATFORM_DIR}/csv/*.cpp)
file(GLOB_RECURSE VERIFICATION_PLATFORM_TDX_SRCS ${VERIFICATION_SRC_PLATFORM_DIR}/tdx/*.cpp)
# For SGX2 platform
set(PLATFORM_SRC_DIR_SGX2_QE ${UAL_TOP_DIR}/external/dcap/QuoteGeneration)
set(PLATFORM_SRC_DIR_SGX2_QV ${UAL_TOP_DIR}/external/dcap/QuoteVerification)
set(PLATFORM_SRC_DIR_SGX2_QVL ${UAL_TOP_DIR}/external/dcap/QuoteVerification/QVL/Src)
set(PLATFORM_SRC_DIR_SGX2_QVE ${UAL_TOP_DIR}/external/dcap/QuoteVerification/QvE)
file(GLOB_RECURSE PLATFORM_SGX2_SRCS_QVL_COMMONS ${VERIFICATION_SRC_PLATFORM_DIR}/sgx2/Utils/*.cpp)
file(GLOB_RECURSE PLATFORM_SGX2_SRCS_QVL_LIBRARY ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationLibrary/src/*.cpp)
file(GLOB_RECURSE PLATFORM_SGX2_SRCS_QVL_PARSERS ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationParsers/src/*.cpp)
file(GLOB PLATFORM_SGX2_SRCS_VERIFICATION ${VERIFICATION_SRC_PLATFORM_DIR}/sgx2/*.cpp)
set(VERIFICATION_PLATFORM_SGX2_SRCS
    ${PLATFORM_SRC_DIR_SGX2_QVE}/Enclave/qve.cpp
    ${PLATFORM_SGX2_SRCS_QVL_COMMONS}
    ${PLATFORM_SGX2_SRCS_QVL_LIBRARY}
    ${PLATFORM_SGX2_SRCS_QVL_PARSERS}
    ${PLATFORM_SGX2_SRCS_VERIFICATION}
)

set(VERIFICATION_U_SRCS
    ${VERIFICATION_CORE_SRCS}
    ${VERIFICATION_UNTRUSTED_SRCS}
    ${VERIFICATION_UAS_SRCS}
    ${VERIFICATION_PLATFORM_HYPERENCLAVE_SRCS}
    ${VERIFICATION_PLATFORM_SGX1_SRCS}
    ${VERIFICATION_PLATFORM_SGX2_SRCS}
    ${VERIFICATION_PLATFORM_KUNPENG_SRCS}
    ${VERIFICATION_PLATFORM_CSV_SRCS}
    ${VERIFICATION_PLATFORM_TDX_SRCS}
)
set(VERIFICATION_T_SRCS
    ${VERIFICATION_CORE_SRCS}
    ${VERIFICATION_TRUSTED_SRCS}
    ${VERIFICATION_UAS_SRCS}
    ${VERIFICATION_PLATFORM_HYPERENCLAVE_SRCS}
    ${VERIFICATION_PLATFORM_SGX1_SRCS}
    ${VERIFICATION_PLATFORM_SGX2_SRCS}
    ${VERIFICATION_PLATFORM_KUNPENG_SRCS}
    ${VERIFICATION_PLATFORM_CSV_SRCS}
    ${VERIFICATION_PLATFORM_TDX_SRCS}
)
set(VERIFICATION_PLATFORM_SGX2_QVL_INCS
    ${PLATFORM_SRC_DIR_SGX2_QE}/quote_wrapper/common/inc
    ${PLATFORM_SRC_DIR_SGX2_QV}/dcap_quoteverify/inc/
    ${PLATFORM_SRC_DIR_SGX2_QVE}/Include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationCommons/include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationCommons/include/Utils
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationLibrary/include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationLibrary/src
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationParsers/include
    ${PLATFORM_SRC_DIR_SGX2_QVL}/AttestationParsers/src
)

# Collect all the trusted protobuf source files
set(PROTOBUF_SRC_DIR ${UAL_TOP_DIR}/external/protobuf-cpp/src/google/protobuf)
set(PROTOBUF_T_SRCS
    ${PROTOBUF_SRC_DIR}/any.cc
    ${PROTOBUF_SRC_DIR}/any_lite.cc
    ${PROTOBUF_SRC_DIR}/any.pb.cc
    ${PROTOBUF_SRC_DIR}/api.pb.cc
    ${PROTOBUF_SRC_DIR}/arena.cc
    ${PROTOBUF_SRC_DIR}/arenastring.cc
    ${PROTOBUF_SRC_DIR}/descriptor.cc
    ${PROTOBUF_SRC_DIR}/descriptor_database.cc
    ${PROTOBUF_SRC_DIR}/descriptor.pb.cc
    ${PROTOBUF_SRC_DIR}/duration.pb.cc
    ${PROTOBUF_SRC_DIR}/dynamic_message.cc
    ${PROTOBUF_SRC_DIR}/empty.pb.cc
    ${PROTOBUF_SRC_DIR}/extension_set.cc
    ${PROTOBUF_SRC_DIR}/extension_set_heavy.cc
    ${PROTOBUF_SRC_DIR}/field_mask.pb.cc
    ${PROTOBUF_SRC_DIR}/generated_enum_util.cc
    ${PROTOBUF_SRC_DIR}/generated_message_bases.cc
    ${PROTOBUF_SRC_DIR}/generated_message_reflection.cc
    ${PROTOBUF_SRC_DIR}/generated_message_tctable_full.cc
    ${PROTOBUF_SRC_DIR}/generated_message_tctable_lite.cc
    ${PROTOBUF_SRC_DIR}/generated_message_util.cc
    ${PROTOBUF_SRC_DIR}/implicit_weak_message.cc
    ${PROTOBUF_SRC_DIR}/inlined_string_field.cc
    ${PROTOBUF_SRC_DIR}/io/coded_stream.cc
    ${PROTOBUF_SRC_DIR}/io/gzip_stream.cc
    ${PROTOBUF_SRC_DIR}/io/io_win32.cc
    ${PROTOBUF_SRC_DIR}/io/printer.cc
    ${PROTOBUF_SRC_DIR}/io/strtod.cc
    ${PROTOBUF_SRC_DIR}/io/tokenizer.cc
    ${PROTOBUF_SRC_DIR}/io/zero_copy_stream.cc
    ${PROTOBUF_SRC_DIR}/io/zero_copy_stream_impl.cc
    ${PROTOBUF_SRC_DIR}/io/zero_copy_stream_impl_lite.cc
    ${PROTOBUF_SRC_DIR}/map.cc
    ${PROTOBUF_SRC_DIR}/map_field.cc
    ${PROTOBUF_SRC_DIR}/message.cc
    ${PROTOBUF_SRC_DIR}/message_lite.cc
    ${PROTOBUF_SRC_DIR}/parse_context.cc
    ${PROTOBUF_SRC_DIR}/reflection_ops.cc
    ${PROTOBUF_SRC_DIR}/repeated_field.cc
    ${PROTOBUF_SRC_DIR}/repeated_ptr_field.cc
    ${PROTOBUF_SRC_DIR}/service.cc
    ${PROTOBUF_SRC_DIR}/source_context.pb.cc
    ${PROTOBUF_SRC_DIR}/struct.pb.cc
    ${PROTOBUF_SRC_DIR}/stubs/bytestream.cc
    ${PROTOBUF_SRC_DIR}/stubs/common.cc
    ${PROTOBUF_SRC_DIR}/stubs/int128.cc
    ${PROTOBUF_SRC_DIR}/stubs/status.cc
    ${PROTOBUF_SRC_DIR}/stubs/statusor.cc
    ${PROTOBUF_SRC_DIR}/stubs/stringpiece.cc
    ${PROTOBUF_SRC_DIR}/stubs/stringprintf.cc
    ${PROTOBUF_SRC_DIR}/stubs/structurally_valid.cc
    ${PROTOBUF_SRC_DIR}/stubs/strutil.cc
    ${PROTOBUF_SRC_DIR}/stubs/substitute.cc
    ${PROTOBUF_SRC_DIR}/stubs/time.cc
    ${PROTOBUF_SRC_DIR}/text_format.cc
    ${PROTOBUF_SRC_DIR}/timestamp.pb.cc
    ${PROTOBUF_SRC_DIR}/type.pb.cc
    ${PROTOBUF_SRC_DIR}/unknown_field_set.cc
    ${PROTOBUF_SRC_DIR}/util/delimited_message_util.cc
    ${PROTOBUF_SRC_DIR}/util/field_comparator.cc
    ${PROTOBUF_SRC_DIR}/util/field_mask_util.cc
    ${PROTOBUF_SRC_DIR}/util/internal/datapiece.cc
    ${PROTOBUF_SRC_DIR}/util/internal/default_value_objectwriter.cc
    ${PROTOBUF_SRC_DIR}/util/internal/error_listener.cc
    ${PROTOBUF_SRC_DIR}/util/internal/field_mask_utility.cc
    ${PROTOBUF_SRC_DIR}/util/internal/json_escaping.cc
    ${PROTOBUF_SRC_DIR}/util/internal/json_objectwriter.cc
    ${PROTOBUF_SRC_DIR}/util/internal/json_stream_parser.cc
    ${PROTOBUF_SRC_DIR}/util/internal/object_writer.cc
    ${PROTOBUF_SRC_DIR}/util/internal/protostream_objectsource.cc
    ${PROTOBUF_SRC_DIR}/util/internal/protostream_objectwriter.cc
    ${PROTOBUF_SRC_DIR}/util/internal/proto_writer.cc
    ${PROTOBUF_SRC_DIR}/util/internal/type_info.cc
    ${PROTOBUF_SRC_DIR}/util/internal/utility.cc
    ${PROTOBUF_SRC_DIR}/util/json_util.cc
    ${PROTOBUF_SRC_DIR}/util/message_differencer.cc
    ${PROTOBUF_SRC_DIR}/util/type_resolver_util.cc
    ${PROTOBUF_SRC_DIR}/wire_format.cc
    ${PROTOBUF_SRC_DIR}/wire_format_lite.cc
    ${PROTOBUF_SRC_DIR}/wrappers.pb.cc
)