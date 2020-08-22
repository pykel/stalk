project(stalk_test)

include(CMakeIncludes.txt)

cmake_minimum_required(VERSION 3.4)

enable_testing()

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})

find_package(Boost COMPONENTS system REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
#link_directories(${Boost_LIBRARY_DIRS})

find_package(Threads REQUIRED)
find_package(PkgConfig)
pkg_check_modules(OPENSSL openssl)

include_directories(${OPENSSL_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARY_DIRS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${PROJ_SOURCE_DIR}/include)
include_directories(${PROJ_SOURCE_DIR}/web_client)
include_directories(${EXTERNAL_DIR}/logger)
include_directories(${PROJ_SOURCE_DIR}/include)
include_directories(${EXTERNAL_DIR}/doctest_1.2.7)
include_directories(${EXTERNAL_DIR}/nlohmann-json-3.1.0)

add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)

set(SOURCE_FILES
    stalk_test_main.cpp
    stalk_test_router.cpp
    stalk_test_threads.cpp
    stalk_test_websocket.cpp
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME}
    logger
    stalk
    ${OPENSSL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_test(NAME ${PROJECT_NAME}
         COMMAND ${PROJECT_NAME})

add_dependencies(${PROJECT_NAME} logger stalk)
