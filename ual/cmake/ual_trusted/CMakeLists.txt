# For different pthread functions in common/attestatio/pthread.h
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format -DTEE_TRUSTED")

# For prrintf in protobuf source code
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Dprintf=tee_printf")

include(${UA_TOP_DIR}/cmake/UalSources.cmake)

include_directories(
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/rapidjson/include
    ${UAL_TOP_DIR}/external/protobuf-cpp/src/
    ${VERIFICATION_PLATFORM_SGX2_QVL_INCS}
)

if(ENV_TYPE STREQUAL "SGXSDK")
    # UAL trusted library
    set(LIB_UAL_T ual_t)
    set(UAL_T_SRCS
        ${UAL_PROTO_SRCS}
        ${COMMON_SRCS}
        ${UTILS_T_SRCS}
        ${PROTOBUF_T_SRCS}
        ${INSTANCE_T_SRCS}
        ${GENERATION_T_SRCS}
        ${VERIFICATION_T_SRCS}
    )
    add_trusted_library_without_edl(
        ${LIB_UAL_T}
        SRCS ${UAL_T_SRCS}
    )
    target_include_directories(
        ${LIB_UAL_T} PUBLIC
        ${SGXSSL_INCLUDE_DIR}
    )
endif()

if(ENV_TYPE STREQUAL "SGXSDK")
    install(TARGETS ${LIB_UAL_T} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
