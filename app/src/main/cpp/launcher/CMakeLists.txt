cmake_minimum_required(VERSION 3.10)
set (CMAKE_CXX_STANDARD 17)

find_library(log-lib log)

add_executable(launcher
        main.cpp
)
target_include_directories(launcher
        PRIVATE
        ../
)

target_link_libraries(launcher
        log
        ghc_filesystem
)