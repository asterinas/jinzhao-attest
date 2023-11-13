set(INC_EX ${UAL_TOP_DIR}/sdk/include)

set(SAMPLEAPP app-sample-unified-attestation-report-convert)
set(SRCS
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

target_link_libraries(
    ${SAMPLEAPP} ${UA_LINK_OPTIONS}
    -L${LIBRARY_OUTPUT_PATH} -L/usr/lib64
    -Wl,--start-group  -lual ${UAL_U_LIBS_DEPS} -Wl,--end-group
    -Wl,-rpath=.:/usr/lib64:/lib64:/usr/lib:/usr/local/lib
)
add_dependencies(${SAMPLEAPP} ual)
