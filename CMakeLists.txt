cmake_minimum_required(VERSION 3.14)
project(comyc_ice_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic)

# Add 'src' to the include search path so files can include headers globally if needed
include_directories(src)

# Target executable for the ICE Server
add_executable(ice_server 
    src/ice_server/main.cpp
)

message(STATUS "Build setup ready for ICE Server executable.")