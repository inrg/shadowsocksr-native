
include_directories(${MBEDTLS_ROOT_DIR}/include)
add_executable(minicli minicli.c cmd_line_parser.c)
target_link_libraries(minicli mbedtls)
