cmake_minimum_required(VERSION 3.10)
project(RSAProject C)

# Enforce C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Define project directory paths
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(DATA_DIR "${CMAKE_SOURCE_DIR}/data")
set(BIN_DIR "${CMAKE_SOURCE_DIR}/bin")

# Automatically gather all C source files in src/
file(GLOB SRC_FILES "${SRC_DIR}/*.c")

# Create executable target
add_executable(rsa ${SRC_FILES})

# Set runtime data path definition (optional, for locating files at runtime)
target_compile_definitions(rsa PRIVATE DATA_DIR="${DATA_DIR}")

# Include headers from include/
target_include_directories(rsa PRIVATE ${INCLUDE_DIR})

# Link necessary external libraries (GMP, OpenSSL)
target_link_libraries(rsa gmp ssl crypto)

# Set output binary location
set_target_properties(rsa PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}")
