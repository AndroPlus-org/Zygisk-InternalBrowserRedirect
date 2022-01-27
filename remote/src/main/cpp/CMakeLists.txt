cmake_minimum_required(VERSION 3.4.1)
project(zygisk_ibr)

include_directories(.)
find_package(cxx REQUIRED CONFIG)
add_library(zygisk_ibr SHARED main.cc elf_util.cpp)
target_link_libraries(zygisk_ibr cxx::cxx log)
