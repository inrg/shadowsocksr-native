
include_directories(${SSR_MAIN_DIR})
include_directories(${MBEDTLS_ROOT_DIR}/include)
add_executable(minicli minicli.c cmd_line_parser.c ${SSR_MAIN_DIR}/picohttpparser.c)
target_link_libraries(minicli mbedtls)

