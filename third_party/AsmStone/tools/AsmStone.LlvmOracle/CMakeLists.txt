cmake_minimum_required(VERSION 3.20)

project(AsmStoneLlvmOracle LANGUAGES CXX)

find_package(LLVM CONFIG REQUIRED)

message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM include directories: ${LLVM_INCLUDE_DIRS}")
message(STATUS "LLVM library directories: ${LLVM_LIBRARY_DIRS}")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

llvm_map_components_to_libnames(LLVM_LIBS
    AArch64Desc
    AArch64Disassembler
    AArch64Info
    AArch64Utils
    MC
    MCDisassembler
    Support)

add_executable(asmstone-llvm-oracle main.cpp)
target_compile_features(asmstone-llvm-oracle PRIVATE cxx_std_17)
target_link_libraries(asmstone-llvm-oracle PRIVATE ${LLVM_LIBS})
