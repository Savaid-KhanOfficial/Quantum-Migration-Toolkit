cmake_minimum_required(VERSION 3.20)
project(QuantumScanner)

# Set C++17 standard (required for filesystem)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Create executable
add_executable(QuantumScanner scanner_main.cpp)

# On some systems, filesystem requires explicit linking
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(QuantumScanner stdc++fs)
endif()
