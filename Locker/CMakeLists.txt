cmake_minimum_required(VERSION 3.20)
project(MyQuantumApp)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL (required for production-level encryption)
find_package(OpenSSL REQUIRED)

# Point this to the SDK we just created
set(QS_SDK_PATH "D:/Quantum/liboqs/qs_sdk")

include_directories(${QS_SDK_PATH}/include)
link_directories(${QS_SDK_PATH}/lib)

add_executable(MyQuantumApp main.cpp QuantumKyber.cpp AES.cpp FileEncryptor.cpp)

# Link against oqs.lib and OpenSSL
target_link_libraries(MyQuantumApp oqs OpenSSL::Crypto)
