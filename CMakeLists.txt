cmake_minimum_required(VERSION 3.5)

project(BackTrace LANGUAGES CXX)
set(EXECUTABLE_OUTPUT_PATH ./bin)

add_executable(${PROJECT_NAME} main.cpp)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE dl)
target_link_libraries(${PROJECT_NAME} PRIVATE dw)

if (CMAKE_COMPILER_IS_GNUCXX)
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -Wall -g2 -ggdb")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O3 -Wall -g2 -ggdb")
endif()

#g++ main.cpp -ldl -ldw -ggdb -O0

