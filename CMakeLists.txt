cmake_minimum_required(VERSION 3.2)

project(areion)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native")

include_directories(include)

add_library(areion ref/areion.c ref/opp-256.c ref/opp-512.c)
add_executable(areion-test test/areion-test.c)
target_link_libraries(areion-test areion)
add_executable(areion-benchmark benchmark/areion-benchmark.c)
target_link_libraries(areion-benchmark areion)
