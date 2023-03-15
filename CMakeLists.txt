cmake_minimum_required(VERSION 3.12)

project(capsuleflow VERSION 1.0.0 LANGUAGES CXX C)


set(CMAKE_CXX_FLAGS "-g -O0 -fpermissive -fopenmp -fPIC")


find_package(Threads REQUIRED)

# Import Microsoft SEAL
find_package(SEAL 4.1.1 EXACT REQUIRED)


add_executable(test1
    test.cpp
    base64.cpp
    )

target_link_libraries(test1 SEAL::seal)


