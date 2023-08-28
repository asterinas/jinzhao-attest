set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Prepare protobuf files
find_package(Protobuf REQUIRED)
file(GLOB PROTO_FILES ${UAL_TOP_DIR}/proto/*.proto)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

file(GLOB COMMON_SRCS ${UAL_TOP_DIR}/common/*.cpp)
file(GLOB UTILS_SRCS ${UAL_TOP_DIR}/utils/untrusted/*.cpp)
file(GLOB NETWORK_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
file(GLOB IAS_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/ias/*.cpp)
file(GLOB PCCS_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/pccs/*.cpp)
file(GLOB HYGON_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/hygon/*.cpp)
file(GLOB UAS_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/uas/*.cpp)

# Build the ua_ugeneration library
set(LIB_UA_UNETWORK ua_unetwork)
set(U_SRCS
    ${PROTO_SRCS}
    ${COMMON_SRCS}
    ${UTILS_SRCS}
    ${NETWORK_SRCS}
    ${IAS_SRCS}
    ${PCCS_SRCS}
    ${HYGON_SRCS}
    ${UAS_SRCS}
)

if(HAS_TEE STREQUAL "OFF")
    add_library(
        ${LIB_UA_UNETWORK} ${UA_LIB_TYPE}
        ${U_SRCS}
    )
else()
    add_untrusted_library_without_edl(
        ${LIB_UA_UNETWORK} ${UA_LIB_TYPE}
        SRCS ${U_SRCS}
    )
endif()

target_include_directories(
    ${LIB_UA_UNETWORK} PUBLIC
    ${OCCLUM_INSTALLDIR}/include
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/include/network
    ${UAL_TOP_DIR}/include/sgx
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/rapidjson/include
    ${OPENSSL_INC_DIR}
)

set(U_LIBS "-lcurl -lprotobuf -lssl -lcrypto")
if(TEE_TYPE STREQUAL "SGX2" AND ENV_TYPE STREQUAL "SGXSDK")
    list(APPEND U_LIBS "-lsgx_dcap_ql -lsgx_quote_ex")
endif()
target_link_libraries(
    ${LIB_UA_UNETWORK}
    -L${LIBRARY_OUTPUT_PATH}
    -Wl,--start-group ${U_LIBS} -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)

install(
    TARGETS ${LIB_UA_UNETWORK}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
