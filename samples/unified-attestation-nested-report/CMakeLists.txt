set(EX_EDL_SEARCH_PATHS
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave
    ${ENCLAVE_EDL_SEARCH_PATHS_UAL}
)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${UAL_TOP_DIR}/include
)

# Build the untrusted app
set(SAMPLEAPP app-sample-unified-attestation-nested-report)
set(SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/app/app.cpp
)
add_executable(
    ${SAMPLEAPP}
    ${SRCS}
)

target_link_libraries(
    ${SAMPLEAPP} ${UA_LINK_OPTIONS}
    -L${LIBRARY_OUTPUT_PATH}
    -Wl,--start-group ${UAL_LIBS_LINK} -Wl,--end-group
    -Wl,-rpath=.:/lib64:/usr/lib:/usr/local/lib
)
add_dependencies(${SAMPLEAPP} ${UAL_LIBS_NAME})
