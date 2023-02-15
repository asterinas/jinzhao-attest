set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -DTEE_UNTRUSTED")

file(GLOB COMMON_SRCS ${UAL_TOP_DIR}/common/*.cpp)
file(GLOB UTILS_SRCS ${UAL_TOP_DIR}/utils/untrusted/*.cpp)
file(GLOB UNTRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

# Add the platform special files and libraries
if(ENV_TYPE STREQUAL "SGXSDK")
set(PLATFORM_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../platforms)
if(TEE_TYPE STREQUAL "HYPERENCLAVE")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/hyperenclave/*.cpp)
elseif(TEE_TYPE STREQUAL "SGX1")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/sgx1/*.cpp)
elseif(TEE_TYPE STREQUAL "SGX2")
    file(GLOB PLATFORM_SRCS ${PLATFORM_SRC_DIR}/sgx2/*.cpp)
endif()
endif()

# Build the ua_ree library
set(LIB_UA_REE ua_ree)
set(U_SRCS
    ${COMMON_SRCS}
    ${UTILS_SRCS}
    ${PLATFORM_SRCS}
    ${UNTRUSTED_SRCS}
)

if(HAS_TEE STREQUAL "OFF")
# For Occlum LibOS, all code is in trusted environment 
# So, it also compile the trusted_enclave.cpp to manage
# current attester attributes and UAK
add_library(
    ${LIB_UA_REE} ${UA_LIB_TYPE}
    ${U_SRCS}
)
else()
add_untrusted_library_without_edl(
    ${LIB_UA_REE} ${UA_LIB_TYPE}
    SRCS ${U_SRCS}
)
endif()

target_include_directories(
    ${LIB_UA_REE} PUBLIC
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/include/sgx
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/rapidjson/include
    ${OPENSSL_INC_DIR}
)

set(U_LIBS "-lcrypto")
target_link_libraries(
    ${LIB_UA_REE}
    -L${LIBRARY_OUTPUT_PATH}
    -lprotobuf
    -Wl,--start-group ${U_LIBS} -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
)

install(
    TARGETS ${LIB_UA_REE}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
