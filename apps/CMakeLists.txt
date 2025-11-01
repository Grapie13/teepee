add_executable(example example.c)
target_compile_features(example PRIVATE c_std_11)

target_link_libraries(example PRIVATE teepee)