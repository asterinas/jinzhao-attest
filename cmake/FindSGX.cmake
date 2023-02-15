# FindPackage cmake file for Intel SGX SDK
#
# BSD 3-Clause License
#
# Copyright (c) 2018, Xin Zhang
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include(CMakeParseArguments)

set(SGX_FOUND "NO")

if(EXISTS SGX_DIR)
    set(SGX_PATH ${SGX_DIR})
elseif(EXISTS SGX_ROOT)
    set(SGX_PATH ${SGX_ROOT})
elseif(EXISTS $ENV{SGX_SDK})
    set(SGX_PATH $ENV{SGX_SDK})
elseif(EXISTS $ENV{SGX_DIR})
    set(SGX_PATH $ENV{SGX_DIR})
elseif(EXISTS $ENV{SGX_ROOT})
    set(SGX_PATH $ENV{SGX_ROOT})
else()
    set(SGX_PATH "/opt/intel/sgxsdk")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SGX_COMMON_CFLAGS -m32)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib32)
    set(SGX_SIGNER_PATH ${SGX_PATH}/bin/x86)
else()
    set(SGX_COMMON_CFLAGS -m64)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib64)
    set(SGX_SIGNER_PATH ${SGX_PATH}/bin/x64)
endif()

find_path(SGX_INCLUDE_DIR sgx.h "${SGX_PATH}/include" NO_DEFAULT_PATH)
find_path(SGX_LIBRARY_DIR libsgx_urts_sim.so "${SGX_LIBRARY_PATH}" NO_DEFAULT_PATH)
find_path(SGXSSL_INCLUDE_DIR tSgxSSL_api.h "/opt/intel/sgxssl/include" NO_DEFAULT_PATH)
find_path(SGXSSL_LIBRARY_DIR libsgx_tsgxssl.a "/opt/intel/sgxssl/lib64/" NO_DEFAULT_PATH)

if(SGX_INCLUDE_DIR AND SGX_LIBRARY_DIR)
    set(SGX_FOUND "YES")
    set(SGX_INCLUDE_DIR "${SGX_PATH}/include" CACHE PATH "Intel SGX include directory" FORCE)
    set(SGX_TLIBC_INCLUDE_DIR "${SGX_INCLUDE_DIR}/tlibc" CACHE PATH "Intel SGX tlibc include directory" FORCE)
    set(SGX_LIBCXX_INCLUDE_DIR "${SGX_INCLUDE_DIR}/libcxx" CACHE PATH "Intel SGX libcxx include directory" FORCE)
    set(SGX_INCLUDE_DIRS ${SGX_INCLUDE_DIR} ${SGX_TLIBC_INCLUDE_DIR} ${SGX_LIBCXX_INCLUDE_DIR})
    mark_as_advanced(SGX_INCLUDE_DIR SGX_TLIBC_INCLUDE_DIR SGX_LIBCXX_INCLUDE_DIR SGX_LIBRARY_DIR)
    message(STATUS "Found Intel SGX SDK.")
endif()

if(SGX_FOUND)
    set(SGX_MODE HW CACHE STRING "SGX hareware mode: HW; SIM; HYPER.")
    set(BUILD_MODE PreRelease CACHE STRING "SGX build mode: Debug; PreRelease; Release.")
    message(STATUS "BUILD_MODE=${BUILD_MODE}")
    message(STATUS "SGX_MODE=${SGX_MODE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DTEE_MODE_${TEE_TYPE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSGX_MODE_${SGX_MODE}")
    link_directories(${SGXSSL_LIBRARY_DIR})

    if(SGX_MODE STREQUAL "HW")
        set(SGX_SIGNER_NAME sgx_sign)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
        set(PCL_LIB_NAME sgx_pcl)
    elseif(SGX_MODE STREQUAL "SIM")
        set(SGX_SIGNER_NAME sgx_sign)
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
        set(PCL_LIB_NAME sgx_pclsim)
    elseif(SGX_MODE STREQUAL "HYPER")
        set(SGX_EDGER8R_SGX_MODE --sgx-mode HYPER)
        set(SGX_SIGNER_NAME sgx_sign_hyper)
        set(SGX_URTS_LIB sgx_urts_hyper)
        set(SGX_USVC_LIB sgx_uae_service_hyper)
        set(SGX_TRTS_LIB sgx_trts_hyper)
        set(SGX_TSVC_LIB sgx_tservice_hyper)
        set(PCL_LIB_NAME sgx_pclhyper) # not existed and used yet
    else()
        message(FATAL_ERROR "SGX_MODE ${SGX_MODE} is not HW, SIM or Hyper.")
    endif()

    if(BUILD_MODE STREQUAL "Debug")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g2 -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(BUILD_MODE STREQUAL "PreRelease")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -DEDEBUG")
    elseif(BUILD_MODE STREQUAL "Release")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -UEDEBUG")
    else()
        message(FATAL_ERROR "BUILD_MODE ${BUILD_MODE} is not Debug, PreRelease or Release.")
    endif()

    set(SGX_ENCLAVE_SIGNER ${SGX_SIGNER_PATH}/${SGX_SIGNER_NAME})
    set(SGX_EDGER8R ${SGX_PATH}/bin/x64/sgx_edger8r)

    set(ENCLAVE_INC_FLAGS "-I${SGX_INCLUDE_DIR} -I${SGX_TLIBC_INCLUDE_DIR} -I${SGX_LIBCXX_INCLUDE_DIR}")
    set(ENCLAVE_C_FLAGS "${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong -ffunction-sections -fdata-sections ${ENCLAVE_INC_FLAGS}")
    set(ENCLAVE_CXX_FLAGS "${ENCLAVE_C_FLAGS} -nostdinc++")

    set(APP_INC_FLAGS "-I${SGX_PATH}/include")
    set(APP_C_FLAGS "${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes ${APP_INC_FLAGS}")
    set(APP_CXX_FLAGS "${APP_C_FLAGS}")

    function(_build_edl_obj edl edl_search_paths use_prefix)
        get_filename_component(EDL_NAME ${edl} NAME_WE)
        get_filename_component(EDL_ABSPATH ${edl} ABSOLUTE)
        set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
        set(SEARCH_PATHS "")
        foreach(path ${edl_search_paths})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
        if(${use_prefix})
            set(USE_PREFIX "--use-prefix")
        endif()
        add_custom_command(OUTPUT ${EDL_T_C}
                           COMMAND ${SGX_EDGER8R} ${USE_PREFIX} ${SGX_EDGER8R_SGX_MODE} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(${target}-edlobj OBJECT ${EDL_T_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")
    endfunction()

    # build trusted static library to be linked into enclave library
    function(add_trusted_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file search paths are not provided!")
        endif()
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()

        _build_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})

        add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0")
    endfunction()

    function(add_trusted_library_without_edl target)
        set(multiValueArgs SRCS)
        cmake_parse_arguments("SGX" "" "" "${multiValueArgs}" ${ARGN})

        add_library(${target} STATIC ${SGX_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0")
    endfunction()


    # build enclave shared library
    function(add_enclave_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS TRUSTED_LIBS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file search paths are not provided!")
        endif()
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()

        _build_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})

        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        set(TLIB_LIST "")
        foreach(TLIB ${SGX_TRUSTED_LIBS})
            string(APPEND TLIB_LIST "$<TARGET_FILE:${TLIB}> ")
            add_dependencies(${target} ${TLIB})
        endforeach()

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
            -Wl,-z,relro,-z,now,-z,noexecstack \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -L${SGXSSL_LIBRARY_DIR} \
            -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive \
            -Wl,--start-group ${TLIB_LIST} -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -lsgx_pthread -lsgx_tsgxssl_crypto -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections")
    endfunction()

    # sign the enclave, according to configurations one-step or two-step signing will be performed.
    # default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
    function(enclave_sign target)
        set(oneValueArgs KEY CONFIG OUTPUT)
        cmake_parse_arguments("SGX" "" "${oneValueArgs}" "" ${ARGN})
        if("${SGX_CONFIG}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave config is not provided!")
        endif()
        if("${SGX_KEY}" STREQUAL "")
            if (NOT SGX_MODE STREQUAL "HW" OR NOT BUILD_MODE STREQUAL "Release")
                message(FATAL_ERROR "Private key used to sign enclave is not provided!")
            endif()
        else()
            get_filename_component(KEY_ABSPATH ${SGX_KEY} ABSOLUTE)
        endif()
        if("${SGX_OUTPUT}" STREQUAL "")
            set(OUTPUT_NAME "${target}.signed.so")
        else()
            set(OUTPUT_NAME ${SGX_OUTPUT})
        endif()

        get_filename_component(CONFIG_ABSPATH ${SGX_CONFIG} ABSOLUTE)

        if(SGX_MODE STREQUAL "HW" AND BUILD_MODE STREQUAL "Release")
            add_custom_target(${target}-sign ALL
                              COMMAND ${SGX_ENCLAVE_SIGNER} gendata -config ${CONFIG_ABSPATH}
                                      -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${target}_hash.hex
                              COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                                  --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/${target}_hash.hex for second step"
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        else()
            add_custom_target(${target}-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${KEY_ABSPATH} -config ${CONFIG_ABSPATH}
                              -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME}
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        endif()

        set(CLEAN_FILES "$<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME};$<TARGET_FILE_DIR:${target}>/${target}_hash.hex")
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")
    endfunction()

    function(add_untrusted_library target mode)
        set(optionArgs USE_PREFIX)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file search paths are not provided!")
        endif()

        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} ${SGX_EDGER8R_SGX_MODE} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

            list(APPEND EDL_U_SRCS ${EDL_U_C})
        endforeach()

        add_library(${target} ${mode} ${SGX_SRCS} ${EDL_U_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -L${SGXSSL_LIBRARY_DIR} \
                                         -Wl,--start-group -lsgx_usgxssl -lcrypto -Wl,--end-group \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_USVC_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lpthread")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

    function(add_untrusted_executable target)
        set(optionArgs USE_PREFIX)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file search paths are not provided!")
        endif()

        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} ${SGX_EDGER8R_SGX_MODE} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

            list(APPEND EDL_U_SRCS ${EDL_U_C})
        endforeach()

        add_executable(${target} ${SGX_SRCS} ${EDL_U_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -L${SGXSSL_LIBRARY_DIR} \
                                         -L/usr/lib64 \
                                         -Wl,--start-group -lsgx_usgxssl -lcrypto -Wl,--end-group \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_USVC_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lpthread")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

    function(add_untrusted_library_without_edl target mode)
        set(multiValueArgs SRCS)
        cmake_parse_arguments("SGX" "" "" "${multiValueArgs}" ${ARGN})

        add_library(${target} ${mode} ${SGX_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_USVC_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lpthread")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

    function(add_untrusted_executable_without_edl target)
        set(multiValueArgs SRCS)
        cmake_parse_arguments("SGX" "" "" "${multiValueArgs}" ${ARGN})

        add_executable(${target} ${SGX_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -L/usr/lib64 \
                                         -L${SGXSSL_LIBRARY_DIR} \
                                         -Wl,--start-group -lsgx_usgxssl -lcrypto -Wl,--end-group \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_USVC_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lpthread")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

else(SGX_FOUND)
    message(WARNING "Intel SGX SDK not found!")
    if(SGX_FIND_REQUIRED)
        message(FATAL_ERROR "Could NOT find Intel SGX SDK!")
    endif()
endif(SGX_FOUND)
