# Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.2)

project(areion C ASM)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

include_directories(include)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    list(APPEND DEFAULT_C_FLAGS -march=native -mtune=native)
    list(APPEND AVX2_C_FLAGS -mavx2 -maes -mtune=native)
    list(APPEND VAES_C_FLAGS -mavx512f -mavx512dq -mavx512vl -mvaes -maes -mtune=native)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    list(APPEND DEFAULT_C_FLAGS -march=armv8-a+crypto)
else()
endif()

function(add_optimized ARCH FLAG_VAR)
    add_library(areion-${ARCH} ${ARGN})
    target_compile_options(areion-${ARCH} PRIVATE "${${FLAG_VAR}}")

    add_executable(areion-test-${ARCH} test/areion-test.c)
    target_link_libraries(areion-test-${ARCH} areion-${ARCH})

    if(NOT "${ARCH}" STREQUAL "ref")
        add_executable(ref-compare-test-${ARCH} test/ref-compare-test.c)
        target_link_libraries(ref-compare-test-${ARCH} areion-${ARCH})
    endif()

    add_executable(areion-benchmark-${ARCH} benchmark/areion-benchmark.c benchmark/perf.c)
    target_link_libraries(areion-benchmark-${ARCH} areion-${ARCH})
endfunction()

set(REF_SRC ref/areion.c ref/dm.c ref/md.c ref/opp-256.c ref/opp-512.c)

add_optimized(ref DEFAULT_C_FLAGS ${REF_SRC} ref/impl-ref.c)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    add_optimized(baseline DEFAULT_C_FLAGS ${REF_SRC} baseline/opp-256.c baseline/opp-512.c baseline/impl-baseline.c)
    add_optimized(AVX2 AVX2_C_FLAGS ${REF_SRC}  AVX2/opp-256.c AVX2/opp-512.c AVX2/impl-AVX2.c)
    add_optimized(AVX512F-VL-DQ-VAES VAES_C_FLAGS ${REF_SRC} AVX512F-VL-DQ-VAES/opp-256.c AVX512F-VL-DQ-VAES/mem-256.s AVX512F-VL-DQ-VAES/opp-512.c AVX512F-VL-DQ-VAES/mem-512.s AVX512F-VL-DQ-VAES/impl-AVX512F-VL-DQ-VAES.c)
endif()
