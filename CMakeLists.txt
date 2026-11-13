cmake_minimum_required(VERSION 3.20)
project(Comyc LANGUAGES CXX)

if (POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_COLOR_DIAGNOSTICS ON)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
            -fdiagnostics-color=always
            -fno-elide-type
            -fdiagnostics-show-template-tree
            -ftemplate-backtrace-limit=2
    )
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(
            -fcolor-diagnostics
            -ftemplate-backtrace-limit=5
    )
endif()

# build type: debug defaulted
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# release flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")


# debug flags. uncomment either asan or tsan.
# asan
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -fno-omit-frame-pointer -fsanitize=address,undefined")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")
# tsan
#set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -fno-omit-frame-pointer -fsanitize=thread")
#set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=thread")


# QUILL
add_compile_definitions(
        -DQUILL_COMPILE_ACTIVE_LOG_LEVEL=$<IF:$<CONFIG:Debug>,QUILL_COMPILE_ACTIVE_LOG_LEVEL_DEBUG,QUILL_COMPILE_ACTIVE_LOG_LEVEL_INFO>
)


find_package(Boost REQUIRED COMPONENTS headers)
find_package(quill REQUIRED)
find_package(Threads REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# NETWORK
add_library(network
        src/network/packets/packets.cpp
        src/network/sockets/utun.cpp
)
target_include_directories(network PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(network PRIVATE Boost::headers quill::quill Threads::Threads fmt::fmt-header-only OpenSSL::Crypto)

# NODE APP
add_executable(node_app
        src/node/main.cpp
        src/node/node.cpp
        src/node/roles/client.cpp
        src/node/roles/relay.cpp
        src/node/roles/exit.cpp
)
set_target_properties(node_app PROPERTIES OUTPUT_NAME "node")
target_include_directories(node_app PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(node_app PRIVATE network Boost::headers quill::quill Threads::Threads fmt::fmt-header-only OpenSSL::Crypto)