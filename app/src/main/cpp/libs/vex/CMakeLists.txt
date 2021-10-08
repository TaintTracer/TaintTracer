cmake_minimum_required(VERSION 3.10)

add_library(vex STATIC IMPORTED GLOBAL)
if(NOT ${CMAKE_ANDROID_ARCH_ABI} STREQUAL arm64-v8a)
    message(FATAL_ERROR "VEX has been precompiled for arm64 instead of ${CMAKE_ANDROID_ARCH_ABI}")
endif()
set_target_properties(vex PROPERTIES
        IMPORTED_LOCATION "${CMAKE_CURRENT_LIST_DIR}/libvex.a"
        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}/pub"
        )
