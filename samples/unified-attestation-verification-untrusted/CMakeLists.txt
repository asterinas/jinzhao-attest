if(BUILD_STATIC STREQUAL "ON")
set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

find_package(Protobuf REQUIRED)
set(PROTO_FILES
    ${UAL_TOP_DIR}/proto/attestation.proto
    ${UAL_TOP_DIR}/proto/crypto.proto
)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_BINARY_DIR} ${PROTO_FILES})

set(SAMPLEAPP app-sample-unified-attestation-verification-untrusted)
set(SRCS
    ${PROTO_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/app/app.cpp
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${UAL_TOP_DIR}/include
)
add_executable(
    ${SAMPLEAPP}
    ${SRCS}
)
if(BUILD_STATIC STREQUAL "OFF")
    target_link_libraries(
        ${SAMPLEAPP} ${UA_LINK_OPTIONS}
        -L${LIBRARY_OUTPUT_PATH} -L/usr/lib64
        -Wl,--start-group -lual ${UAL_U_LIBS_DEPS} -Wl,--end-group
        -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
    )
else()
    target_link_libraries(
        ${SAMPLEAPP} -static -fPIC
        -L${LIBRARY_OUTPUT_PATH} -L/usr/lib64
        -Wl,--start-group -lual -lprotobuf -lcrypto -lcurl -lssl -ldl -Wl,--end-group
        -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
    )
endif()
add_dependencies(${SAMPLEAPP} ual)
