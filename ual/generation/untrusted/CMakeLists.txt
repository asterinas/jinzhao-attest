set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -DTEE_UNTRUSTED")

file(GLOB COMMON_PLATFORMS_SRCS ${UAL_TOP_DIR}/common/platforms/*.cpp)
file(GLOB CORE_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/../core/*.cpp)
file(GLOB UNTRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
# Add the platform special files and libraries
set(PLATFORM_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../platforms)
if(TEE_TYPE STREQUAL "HYPERENCLAVE")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/hyperenclave/*.cpp)
elseif(TEE_TYPE STREQUAL "SGX1")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/sgx1/*.cpp)
elseif(TEE_TYPE STREQUAL "SGX2")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/sgx2/*.cpp)
elseif(TEE_TYPE STREQUAL "CSV")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/csv/*.cpp)
elseif(TEE_TYPE STREQUAL "TDX")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/tdx/*.cpp)
endif()

# Build the ua_ugeneration library
set(LIB_UA_UGENERATION ua_ugeneration)
set(U_SRCS
    ${COMMON_PLATFORMS_SRCS}
    ${CORE_SRCS}
    ${PLATFORM_SRCS}
    ${UNTRUSTED_SRCS}
)

if(HAS_TEE STREQUAL "OFF")
# For Occlum LibOS, all code is in trusted environment 
# So, it also compile the trusted_enclave.cpp to manage
# current attester attributes and UAK
add_library(
    ${LIB_UA_UGENERATION} ${UA_LIB_TYPE}
    ${U_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../trusted/trusted_enclave.cpp
)
else()
add_untrusted_library_without_edl(
    ${LIB_UA_UGENERATION} ${UA_LIB_TYPE}
    SRCS ${U_SRCS}
)
endif()

target_include_directories(
    ${LIB_UA_UGENERATION} PUBLIC
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/include/sgx
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/rapidjson/include
    ${OPENSSL_INC_DIR}
)

set(U_LIBS "-lua_ree -lua_unetwork -lcrypto")
if(TEE_TYPE STREQUAL "SGX2" AND ENV_TYPE STREQUAL "SGXSDK")
    list(APPEND U_LIBS "-lsgx_dcap_ql -lsgx_quote_ex")
endif()
target_link_libraries(
    ${LIB_UA_UGENERATION}
    -L${LIBRARY_OUTPUT_PATH}
    -lprotobuf
    -Wl,--start-group ${U_LIBS} -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)

add_dependencies(${LIB_UA_UGENERATION} ua_ree ua_unetwork)

install(
    TARGETS ${LIB_UA_UGENERATION}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
