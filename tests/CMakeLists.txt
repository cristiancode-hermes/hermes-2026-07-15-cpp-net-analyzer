cmake_minimum_required(VERSION 3.28)
project(net-analyzer-tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_suite test_main.cpp)
target_link_libraries(test_suite PRIVATE
  Catch2::Catch2WithMain
  net-analyzer-lib
)

include(CTest)
add_test(NAME test_suite COMMAND test_suite)
