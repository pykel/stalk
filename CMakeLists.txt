cmake_minimum_required(VERSION 3.12)

project(stalk VERSION 1.0.0)

include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

include(CMakeIncludes.txt)

set(tool_dest "bin")
set(include_dest "include/${PROJECT_NAME}-${CMAKE_PROJECT_VERSION_MAJOR}.0")
set(main_lib_dest "lib")

option(STALK__ENABLE_TESTS "Enable building tests" OFF)
option(STALK__ENABLE_EXAMPLES "Enable building examples" OFF)

add_subdirectory(src)

if (STALK__ENABLE_TESTS)
    add_subdirectory(tests)
endif()
if (STALK__ENABLE_EXAMPLES)
    add_subdirectory(examples)
endif()

