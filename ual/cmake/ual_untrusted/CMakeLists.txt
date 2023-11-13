set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format -DTEE_UNTRUSTED")

include(${UA_TOP_DIR}/cmake/UalSources.cmake)
message(STATUS "Build for merged UAL ...")
include_directories(
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/include/sgx
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/rapidjson/include
    ${UAL_TOP_DIR}/external/protobuf-cpp/src/
    ${VERIFICATION_PLATFORM_SGX2_QVL_INCS}
    ${OPENSSL_INC_DIR}
)

if(ENV_TYPE STREQUAL "SGXSDK")
    # UAL untrusted library
    set(LIB_UAL_U ual_u)
    set(UAL_U_SRCS
        ${UAL_PROTO_SRCS}
        ${COMMON_SRCS}
        ${UTILS_U_SRCS}
        ${NETWORK_U_SRCS}
        ${INSTANCE_U_SRCS}
        ${GENERATION_U_SRCS}
        ${VERIFICATION_U_SRCS}
    )
    add_untrusted_library_without_edl(
        ${LIB_UAL_U} ${UA_LIB_TYPE}
        SRCS ${UAL_U_SRCS}
    )
    target_link_libraries(
        ${LIB_UAL_U}
        -L/usr/lib64
        -Wl,--start-group ${UAL_U_LIBS_DEPS} -Wl,--end-group
        -Wl,-rpath=.:/usr/lib64:/lib64:/lib:/usr/lib:/usr/local/lib:/usr/local/lib64:${SGX_LIBRARY_DIR}
    )
endif()

# For Occlum LibOS and VMTEE, one library including genaration and verification
if(ENV_TYPE STREQUAL "OCCLUM" OR ENV_TYPE STREQUAL "VMTEE")
    set(LIB_UAL ual)
    set(UAL_SRCS
        ${UAL_PROTO_SRCS}
        ${COMMON_SRCS}
        ${UTILS_U_SRCS}
        ${NETWORK_U_SRCS}
        ${INSTANCE_U_SRCS}
        ${GENERATION_U_SRCS}
        ${VERIFICATION_U_SRCS}
    )
    add_library(
        ${LIB_UAL} ${UA_LIB_TYPE}
        ${UAL_SRCS}
    )
    target_link_libraries(
        ${LIB_UAL}
        -L/usr/lib64
        ${UAL_U_LIBS_DEPS}
        -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
    )
# For no TEE, only untrusted verification
# For SGXSDK, also provide untrusted verification lib for sample code 
elseif(ENV_TYPE STREQUAL "SGXSDK" OR TEE_TYPE STREQUAL "NONE")
    set(LIB_UAL ual)
    set(UAL_SRCS
        ${UAL_PROTO_SRCS}
        ${COMMON_SRCS}
        ${UTILS_U_SRCS}
        ${NETWORK_U_SRCS}
        ${VERIFICATION_U_SRCS}
    )
    add_library(
        ${LIB_UAL} ${UA_LIB_TYPE}
        ${UAL_SRCS}
    )
    target_link_libraries(
        ${LIB_UAL}
        ${UAL_U_LIBS_DEPS}
    )
endif()

if(ENV_TYPE STREQUAL "SGXSDK")
    install(TARGETS ${LIB_UAL_U} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS ${LIB_UAL} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
