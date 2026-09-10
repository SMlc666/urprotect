cmake_minimum_required(VERSION 3.22.1)
project(urprotect_fixture C)

add_library(fixture SHARED fixture.c)
target_compile_features(fixture PRIVATE c_std_11)
