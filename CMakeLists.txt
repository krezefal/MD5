cmake_minimum_required(VERSION 3.17)
project(md5)

set(CMAKE_CXX_STANDARD 14)

file(GLOB SOURCES

        src/bigint/BigInt.hpp

        src/md5/MD5.hpp
        src/main/Main.cpp
        )

add_executable(md5 ${SOURCES})