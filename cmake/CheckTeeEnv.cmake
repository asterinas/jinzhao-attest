# Check current TEE platform and programming/building environment
#

# Check the TEE platform
if(TEE_TYPE STREQUAL "")
    if(EXISTS /dev/isgx)
        set(TEE_TYPE "SGX1")
    elseif(EXISTS /dev/sgx_enclave)
        set(TEE_TYPE "SGX2")
    elseif(EXISTS /dev/sgx/enclave)
        set(TEE_TYPE "SGX2")
    elseif(EXISTS /dev/jailhouse)
        set(TEE_TYPE "HYPERENCLAVE")
    elseif(EXISTS /dev/hyperenclave)
        set(TEE_TYPE "HYPERENCLAVE")
    else()
        message(WARNING "NOT TEE Platform")
        set(TEE_TYPE "NONE")
    endif()
endif()
message(STATUS "TEE Type: ${TEE_TYPE}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUA_TEE_TYPE_${TEE_TYPE}")

# Check the programming environment
if(ENV_TYPE STREQUAL "")
    if(EXISTS /opt/occlum/build/bin/occlum)
        set(ENV_TYPE "OCCLUM")
    else()
        set(ENV_TYPE "SGXSDK")
    endif()
endif()
message(STATUS "ENV Type: ${ENV_TYPE}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUA_ENV_TYPE_${ENV_TYPE}")

# Set the HAS_TEE top flag for later use
if(NOT TEE_TYPE STREQUAL "NONE" AND ENV_TYPE STREQUAL "SGXSDK")
    set(HAS_TEE "ON")
    find_package(SGX REQUIRED)
else()
    set(HAS_TEE "OFF")
endif()
message(STATUS "HAS_TEE: ${HAS_TEE}")

# Set the occlum special configurations
if(ENV_TYPE STREQUAL "OCCLUM")
    if(NOT DEFINED OCCLUM_BINDIR)
        set(OCCLUM_BINDIR "/usr/local/occlum/bin")
    endif()
    message(STATUS "OCCLUM_BINDIR: '${OCCLUM_BINDIR}'")
    if(NOT DEFINED OCCLUM_INSTALLDIR)
        set(OCCLUM_INSTALLDIR "/usr/local/occlum/x86_64-linux-${OCCLUM_LIBC}")
    endif()
    message(STATUS "OCCLUM_INSTALLDIR: '${OCCLUM_INSTALLDIR}'")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${OCCLUM_INSTALLDIR}/include")
    link_directories(${OCCLUM_INSTALLDIR}/lib)
endif()

# Check current log level 
if(LOG_LEVEL STREQUAL "OFF")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNOLOG")
elseif(LOG_LEVEL STREQUAL "DEBUG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUGLOG")
elseif(LOG_LEVEL STREQUAL "TRACE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUGLOG -DTRACELOG")
endif()

# Special options for static libraries and link
if(BUILD_STATIC STREQUAL "ON")
    set(UA_LIB_TYPE STATIC)
    # UA_LINK_OPTIONS is used when link sample app
    # but there is not static lib for sgx_urts, curl
    # in dev container yet, so just use ua static lib
    # but link the final app in shared mode.
    # set(UA_LINK_OPTIONS "-static -fPIC")
    set(UA_LINK_OPTIONS)
else()
    set(UA_LIB_TYPE SHARED)
    set(UA_LINK_OPTIONS)
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
message(STATUS "UA_LIB_TYPE: ${UA_LIB_TYPE}")

# Add macro define for build special code for sample code
if(BUILD_SAMPLES STREQUAL "ON")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWITH_SAMPLES")
endif()

# Set the openssl include path for untrusted code if it haven't been set yet.
# The intel sgxssl directories for tusted code is set in FindSGX.cmake
if(NOT DEFINED OPENSSL_INC_DIR)
    if(ENV_TYPE STREQUAL "OCCLUM")
        set(OPENSSL_INC_DIR "${OCCLUM_INSTALLDIR}/include")
    else()
        set(OPENSSL_INC_DIR "/usr/include/openssl/../")
    endif()
endif()

if(BUILD_SM STREQUAL "ON")
    message(STATUS "Build SM mode")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSM_MODE")
endif()