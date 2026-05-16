cmake_minimum_required(VERSION 3.20)
project(pqcb_cpp LANGUAGES C CXX)

add_library(pqcb_headers INTERFACE)
target_include_directories(pqcb_headers INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
