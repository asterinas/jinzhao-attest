set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -DTEE_TRUSTED")

find_package(Protobuf REQUIRED)
set(PROTO_FILES
    ${UAL_TOP_DIR}/proto/tee.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

file(GLOB COMMON_SRCS ${UAL_TOP_DIR}/common/*.cpp)
file(GLOB UTILS_SRCS ${UAL_TOP_DIR}/utils/trusted/*.cpp)
file(GLOB TRUSTED_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

set(LIB_UA_TEE ua_tee)
set(T_SRCS
    ${PROTO_SRCS}
    ${COMMON_SRCS}
    ${UTILS_SRCS}
    ${TRUSTED_SRCS}
)

include_directories(
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
    ${UAL_TOP_DIR}/external/cppcodec
    ${UAL_TOP_DIR}/external/protobuf-cpp/src/
    ${SGXSSL_INCLUDE_DIR}
)

add_trusted_library_without_edl(
    ${LIB_UA_TEE}
    SRCS ${T_SRCS}
)

target_link_libraries(
    ${LIB_UA_TEE}
    -ltprotobuf
)

add_dependencies(${LIB_UA_TEE} tprotobuf)

install(
    TARGETS ${LIB_UA_TEE}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
