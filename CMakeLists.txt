project(stalk)
#    VERSION 1.0)
#set(PROJECT_VERSION 1.0 CACHE STRING "Project Version")
set(PROJECT_VERSION 1.0)

cmake_minimum_required(VERSION 3.4)

include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

include(CMakeIncludes.txt)

set(tool_dest "bin")
set(include_dest "include/${PROJECT_NAME}-${PROJECT_VERSION}")
set(main_lib_dest "lib")

add_subdirectory(external/logger)
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(examples)

