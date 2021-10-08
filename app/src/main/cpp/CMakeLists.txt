cmake_minimum_required(VERSION 3.10)
# Don't rely on gradle to set the C++ standard.
# target_compile_features of included libraries could otherwise downgrade it to C++ 11
set (CMAKE_CXX_STANDARD 17)

# set(STRIP true)  # Significantly reduces binary size of executable and helper library
set (CMAKE_BUILD_TYPE RelWithDebInfo)

add_compile_options(-Wall -Wno-unused-variable -Wno-unused-private-field -Wno-reorder -Wno-writable-strings -Wno-unused-value -Werror)

# Enable assertions for RelWithDebInfo
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

add_library(native-lib SHARED
        android/logging.cpp
        android/Debugging.cpp
        native-lib.cpp
        )
target_include_directories(native-lib PRIVATE android)

add_library(source-sink SHARED
        source-sink-lib.cpp)

add_library(tainttracer STATIC
        android/Debugging.cpp
        debugger/arch/aarch64.cpp
        debugger/binder/BinderDriver.cpp
        debugger/binder/Parcel.cpp
        debugger/binder/services/ActivityManagerService.cpp
        debugger/binder/services/BinderService.cpp
        debugger/binder/services/ContactsProvider2.cpp
        debugger/binder/services/LocationManager.cpp
        debugger/binder/services/ServiceManager.cpp
        debugger/breakpoint/InstructionBreakpoint.cpp
        debugger/breakpoint/BreakpointHandler.cpp
        debugger/breakpoint/ImageBreakpoints.cpp
        debugger/files/FileDescriptorTable.cpp
        debugger/memory/MemoryRegion.cpp
        debugger/memory/MergingRegionSet.cpp
        debugger/memory/MemoryMap.cpp
        debugger/memory/PhysicalMemory.cpp
        debugger/memory/VirtualAddressSpace.cpp
        debugger/taint/TaintEvent.cpp
        debugger/taint/TaintValues.cpp
        debugger/taint/MemoryToTaint.cpp
        debugger/taint/source/TaintSource.cpp
        debugger/taint/source/GenericNativeSource.cpp
        debugger/taint/source/NativeMethodSource.cpp
        debugger/taint/sink/GenericNativeSink.cpp
        debugger/taint/sink/NativeMethodSink.cpp
        debugger/taint/execution/ExecutionUnit.cpp
        debugger/taint/execution/InstructionUnit.cpp
        debugger/taint/execution/SystemCallUnit.cpp
        debugger/Debugger.cpp
        debugger/PendingProcessEvents.cpp
        debugger/ELFImage.cpp
        debugger/InstructionAnalyzer.cpp
        debugger/Process.cpp
        debugger/TaintpropBreakpointOptimizer.cpp
        debugger/procfs/Process.cpp
        debugger/procfs/ProcessMapsEntry.cpp
        debugger/procfs/ProcessMapState.cpp
        debugger/WaitEvent.cpp
        debugger/Syscall.cpp
        debugger/vex/IRSBResult.cpp
        debugger/vex/VEXLifter.cpp
        )

target_include_directories(tainttracer
        PUBLIC
            .
        )

add_subdirectory(launcher)

# Add fork of libvex, suitable for lifting with customizable VEX optimization options
add_subdirectory(libs/vex)

# Add capstone
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "")
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "")
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "")
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "")
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "")
add_subdirectory(libs/capstone)
target_include_directories(tainttracer
        PUBLIC
            libs/capstone/include
        )

# Add magic_enum
add_subdirectory(libs/magic_enum)
# Support large enums (e.g. all ARM64 register names)
target_compile_definitions(tainttracer PRIVATE MAGIC_ENUM_RANGE_MAX=512)

# Add std::filesystem implementation that hasn't made it into the NDK yet
add_subdirectory(libs/filesystem)

# Add string formatting library
add_subdirectory(libs/fmt)

# Add ELF and DWARF parsing library
# It is fork of libelfin with CMake and relocation symbol support by deadly-platypus
# We have modified the lists file to have Android Studio recognize the header files
add_subdirectory(libs/libelfin)

add_library(custom-log
        android/logging.cpp
        )
find_library(log-lib log)
target_link_libraries(custom-log
        ${log-lib})
target_link_libraries(native-lib custom-log)
target_link_libraries(tainttracer
        custom-log
        vex
        capstone-static
        magic_enum
        ghc_filesystem
        fmt::fmt
        elf++_static
        dwarf++_static
        )
target_link_libraries(source-sink log)

# Only files with filename lib*.so gets copied under lib/$arch to APK
add_executable(libtainttracer-executable.so main.cpp)
target_link_libraries(libtainttracer-executable.so tainttracer)

if (STRIP)
    add_custom_command(TARGET libtainttracer-executable.so POST_BUILD
            COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -g -S -d --strip-debug
            "$<TARGET_FILE:libtainttracer-executable.so>")
    add_custom_command(TARGET native-lib POST_BUILD
            COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -g -S -d --strip-debug
            "$<TARGET_FILE:libtainttracer-executable.so>")
endif()

### Test target
add_executable(tainttracer-test.so
        test/runner.cpp
        test/taint_fns.c
        test/AnnotatedAddressSpace-test.cpp
        test/VirtualAddressSpace-test.cpp
        test/mmap-test.cpp
        test/ptrace-test.cpp
        test/hwbkpt-test.cpp
        test/VEXLifter-test.cpp
        test/NativeTaintPropagation-test.cpp
        )
add_subdirectory(libs/Catch2)
target_link_libraries(tainttracer-test.so
        tainttracer
        Catch2
        )
