set(HEADER_LIST
  "${teepee_SOURCE_DIR}/include/teepee/teepee.h" 
  "${teepee_SOURCE_DIR}/include/teepee/getipaddr.h"
  "${teepee_SOURCE_DIR}/include/teepee/port.h")

find_package(OpenSSL 3.0.16 REQUIRED)

add_library(teepee teepee.c getipaddr.c ${HEADER_LIST})

target_include_directories(teepee PUBLIC ../include)

target_compile_features(teepee PUBLIC c_std_11)

target_link_libraries(teepee OpenSSL::SSL)

add_compile_definitions(_POSIX_C_SOURCE=200112L)

source_group(
  TREE "${PROJECT_SOURCE_DIR}/include"
  PREFIX "Header Files"
  FILES ${HEADER_LIST})