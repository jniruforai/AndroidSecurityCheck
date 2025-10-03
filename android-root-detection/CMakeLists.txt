# CMakeLists.txt for Native Root Detection Library
cmake_minimum_required(VERSION 3.4.1)

# Set the library name
set(LIB_NAME "nativerootdetection")

# Create the shared library
add_library(${LIB_NAME} SHARED NativeRootDetection.cpp)

# Find and link required libraries
find_library(log-lib log)
find_library(android-lib android)
find_library(dl-lib dl)

# Link libraries
target_link_libraries(${LIB_NAME}
    ${log-lib}
    ${android-lib}
    ${dl-lib}
)

# Compiler flags for security and optimization
target_compile_options(${LIB_NAME} PRIVATE
    -O2                    # Optimization level 2
    -fstack-protector     # Stack protection
    -D_FORTIFY_SOURCE=2   # Fortify source
    -fPIE                 # Position Independent Executable
    -Wformat              # Format string vulnerability detection
    -Wformat-security     # Additional format security
    -Wall                 # Enable most warnings
    -Wextra              # Enable extra warnings
)

# Linker flags for security
target_link_options(${LIB_NAME} PRIVATE
    -Wl,-z,relro         # Read-only relocations
    -Wl,-z,now           # Immediate binding
    -Wl,--exclude-libs,ALL # Hide all symbols
)

# Set C++ standard
set_property(TARGET ${LIB_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${LIB_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)

# Include directories (if needed)
# target_include_directories(${LB_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Strip debug symbols in release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET ${LIB_NAME} POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${LIB_NAME}>
        COMMENT "Stripping debug symbols from ${LIB_NAME}")
endif()