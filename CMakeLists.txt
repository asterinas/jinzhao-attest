cmake_minimum_required(VERSION 3.5)
project(kubetee-unified-attestation)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread")
if(BUILD_MODE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g2")
endif()

set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install)
link_directories(${LIBRARY_OUTPUT_PATH})
# Smoe libraries may be installed into this directory
# for example, protobuf in occlum environment
link_directories(/usr/local/lib64)

set(UA_TOP_DIR ${CMAKE_SOURCE_DIR})

# Set the compiler for occlum programming environment.
if(ENV_TYPE STREQUAL "OCCLUM" AND OCCLUM_LIBC STREQUAL "musl")
    message(STATE "Using compiler: occlum-gcc/occlum-g++")
    set(OCCLUM_BINDIR "/usr/local/occlum/bin")
    set(CMAKE_C_COMPILER ${OCCLUM_BINDIR}/occlum-gcc)
    set(CMAKE_CXX_COMPILER ${OCCLUM_BINDIR}/occlum-g++)
endif()

# For sample applications and test with based on ULA/USA/UAW
set(UAL_U_LIBS_DEPS -lcurl -lprotobuf -lssl -lcrypto)
if(ENV_TYPE STREQUAL "SGXSDK")
    if(TEE_TYPE STREQUAL "SGX2")
        list(APPEND UAL_U_LIBS_DEPS -lsgx_dcap_ql -lsgx_quote_ex)
    endif()
endif()
if(ENV_TYPE STREQUAL "VMTEE")
    if(TEE_TYPE STREQUAL "TDX")
        list(APPEND UAL_U_LIBS_DEPS -lsgx_dcap_quoteverify -ltdx_attest)
    endif()
endif()
if(BUILD_MERGED_LIBS STREQUAL "OFF")
    if(ENV_TYPE STREQUAL "SGXSDK")
        SET(UAL_LIBS_LINK -lua_unetwork -lua_ree -lua_ugeneration -lua_uverification ${UAL_U_LIBS_DEPS})
        SET(UAL_LIBS_NAME ua_unetwork ua_ree ua_ugeneration ua_uverification)
    else()
        # For OCCLUM, VMTEE or no TEE
        SET(UAL_LIBS_LINK -lua_unetwork -lua_ugeneration -lua_uverification ${UAL_U_LIBS_DEPS})
        SET(UAL_LIBS_NAME ua_unetwork ua_ugeneration ua_uverification)
    endif()
    SET(UAL_T_LIBS_LINK -lua_tee -lua_tgeneration -lua_tverification -ltprotobuf)
    SET(UAL_T_LIBS_NAME ua_tee ua_tgeneration ua_tverification tprotobuf)
else()
    if(ENV_TYPE STREQUAL "SGXSDK")
        SET(UAL_LIBS_LINK -lual_u ${UAL_U_LIBS_DEPS})
        SET(UAL_LIBS_NAME ual_u)
    else()
        SET(UAL_LIBS_LINK -lual ${UAL_U_LIBS_DEPS})
        SET(UAL_LIBS_NAME ual)
    endif()
    SET(UAL_T_LIBS_LINK -lual_t)
    SET(UAL_T_LIBS_NAME ual_t)
endif()
message(STATUS "UAL_LIBS_NAME: ${UAL_LIBS_LINK}")

# Build the unified attestation source code
add_subdirectory(ual)

# If samples code build option is enabled
if(BUILD_SAMPLES STREQUAL "ON")
    add_subdirectory(samples)
endif()
