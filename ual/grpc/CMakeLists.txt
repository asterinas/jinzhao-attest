list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

# Create the ua_ugrpc library
file(GLOB UNTRUSTED_GRPC_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
set(UNTRUSTED_GRPC_LIB ua_ugrpc)
add_library(
    ${UNTRUSTED_GRPC_LIB} ${UA_LIB_TYPE}
    ${UNTRUSTED_GRPC_SRCS}
)
target_include_directories(
    ${UNTRUSTED_GRPC_LIB} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${UAL_TOP_DIR}
    ${UAL_TOP_DIR}/include
)
target_link_libraries(
    ${UNTRUSTED_GRPC_LIB}
    -lcurl -lssl -lprotobuf
    gRPC::grpc++_reflection
    -Wl,-rpath=.:/usr/lib64:/usr/local/lib:/usr/local/lib64
)
