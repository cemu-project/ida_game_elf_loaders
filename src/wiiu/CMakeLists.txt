cmake_minimum_required(VERSION 3.27)
project(wiiuldr LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Production build by default; single-config generators only.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(ELF_COMMON_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../elf_common")
set(IDA_SDK_ROOT "${REPO_ROOT}/third_party/ida-sdk/src")
set(IDA_INCLUDE_DIR "${IDA_SDK_ROOT}/include")
set(IDA_LOADER_DIR "${IDA_SDK_ROOT}/ldr")

if(NOT EXISTS "${IDA_INCLUDE_DIR}/ida.hpp")
    message(FATAL_ERROR
        "The ida-sdk submodule was not found at ${IDA_SDK_ROOT}. "
        "Initialize submodules before configuring this project.")
endif()

# IDA 9.4 SDK ships import libraries per host/arch/ea-size under
# lib/<arch>_<plat>_<bits>. Loaders are 64-bit EA (IDA 9.x is __EA64__ only
# in practice), and the official Windows builds are MSVC x64.
if(WIN32 OR (CMAKE_SYSTEM_NAME STREQUAL "Windows"))
    # MSVC, MinGW, or a cross-compile targeting Windows all link the
    # Windows import library.
    set(IDA_LIBRARY "${IDA_SDK_ROOT}/lib/x64_win_64/ida.lib")
elseif(APPLE)
    set(IDA_LIBRARY "${IDA_SDK_ROOT}/lib/x64_mac_64/libida.dylib")
elseif(UNIX)
    set(IDA_LIBRARY "${IDA_SDK_ROOT}/lib/x64_linux_64/libida.so")
else()
    message(FATAL_ERROR "Unsupported host for the Wii U loader build.")
endif()

if(NOT EXISTS "${IDA_LIBRARY}")
    message(FATAL_ERROR
        "The 64-bit IDA import library was not found at ${IDA_LIBRARY}.")
endif()

if(WIN32 AND NOT (MSVC OR MINGW))
    message(FATAL_ERROR "The Wii U loader on Windows requires MSVC or MinGW.")
endif()

set(SOURCES
    "${ELF_COMMON_PATH}/elf_reader.h"
    "${ELF_COMMON_PATH}/elf.h"
    cafe.h
    cafe_loader.h
    cafe_loader.cpp
    wiiu.cpp
)

add_library(wiiuldr SHARED ${SOURCES})

target_include_directories(wiiuldr PRIVATE
    "${IDA_INCLUDE_DIR}"
    "${IDA_LOADER_DIR}"
    "${ELF_COMMON_PATH}"
)

target_compile_definitions(wiiuldr PRIVATE
    __IDP__
    __EA64__
)

# MinGW cross builds don't define _MSC_VER, so pro.h can't autodetect the
# Windows platform; tell the SDK headers explicitly.
if(MINGW)
    target_compile_definitions(wiiuldr PRIVATE __NT__)
endif()

target_link_libraries(wiiuldr PRIVATE "${IDA_LIBRARY}")

if(MSVC)
    set_target_properties(wiiuldr PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL"
        OUTPUT_NAME "wiiu"
        PREFIX ""
        SUFFIX ".dll")
elseif(MINGW)
    # MinGW-built DLLs must export the loader entry point LDSC.
    # GNU ld on Windows only auto-exports functions, not data, so use a
    # def file (matches the SDK's own ldr/exports.def).
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wiiu.def"
"LIBRARY wiiu\n"
"EXPORTS\n"
"    LDSC\n")
    target_sources(wiiuldr PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/wiiu.def")
    set_target_properties(wiiuldr PROPERTIES
        OUTPUT_NAME "wiiu"
        PREFIX ""
        SUFFIX ".dll")
    if(CMAKE_CXX_COMPILER_TARGET)
        set_target_properties(wiiuldr PROPERTIES
            LINK_FLAGS "-static-libgcc -static-libstdc++")
    endif()
else()
    set_target_properties(wiiuldr PROPERTIES
        OUTPUT_NAME "wiiu"
        PREFIX "")
endif()
