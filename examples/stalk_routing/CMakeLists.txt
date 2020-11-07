project(stalk-routing-example)

cmake_minimum_required(VERSION 3.4)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})

find_package(Boost COMPONENTS system REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
#link_directories(${Boost_LIBRARY_DIRS})

find_package(Threads REQUIRED)
find_package(PkgConfig)
pkg_check_modules(OPENSSL openssl)

include_directories(${FMT_INCLUDEDIR})
include_directories(${OPENSSL_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARY_DIRS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${PROJ_SOURCE_DIR})
include_directories(${PROJ_SOURCE_DIR}/include)
include_directories(${EXTERNAL_DIR}/logger/include)
include_directories(${EXTERNAL_DIR}/doctest_1.2.7)
include_directories(${EXTERNAL_DIR}/nlohmann-json-3.1.0)

add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)

set(SOURCE_FILES
    stalk_routing_example.cpp
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME}
    stalk
    ${OPENSSL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_dependencies(${PROJECT_NAME} stalk)

