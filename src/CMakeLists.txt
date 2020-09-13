project(stalk)
set(PROJECT_VERSION 1.0)

cmake_minimum_required(VERSION 3.4)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})

find_package(Boost COMPONENTS system REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
#link_directories(${Boost_LIBRARY_DIRS})

find_package(Threads REQUIRED)
find_package(PkgConfig)

pkg_check_modules(OPENSSL openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARY_DIRS})

include_directories(${FMT_INCLUDEDIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/)

set(HEADER_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include/stalk/)
set(HEADER_FILES
    ${HEADER_PATH}/stalk_client.h
    ${HEADER_PATH}/stalk_status.h
    ${HEADER_PATH}/stalk_verb.h
    ${HEADER_PATH}/stalk_request.h
    ${HEADER_PATH}/stalk_connection_detail_ostream.h
    ${HEADER_PATH}/stalk_types.h
    ${HEADER_PATH}/stalk_route.h
    ${HEADER_PATH}/stalk_websocket_session.h
    ${HEADER_PATH}/stalk_response.h
    ${HEADER_PATH}/stalk_field.h
    ${HEADER_PATH}/stalk_connection_detail.h
    ${HEADER_PATH}/stalk_websocket_client.h
    ${HEADER_PATH}/stalk_server.h
    ${HEADER_PATH}/stalk_router.h
    ${HEADER_PATH}/stalk_header.h
    )

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_logger.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_web_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_request.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_response.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_websocket_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_websocket_session_impl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_router.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_server.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_client.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_websocket_client.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_verb_convert.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_field_convert.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_connection_detail_builder.cpp
    )

add_library(${PROJECT_NAME} STATIC
            ${SOURCE_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 1)

target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION "${main_lib_dest}")
INSTALL(FILES ${HEADER_FILES} DESTINATION "${include_dest}/stalk")

set(DEST_DIR "${CMAKE_INSTALL_PREFIX}")
set(INCLUDE_PATH "/${PROJECT_NAME}-${PROJECT_VERSION}")
foreach(LIB ${PROJECT_NAME})
  set(PRIVATE_LIBS "${PRIVATE_LIBS} -l${LIB}")
endforeach()
CONFIGURE_FILE("${PROJECT_NAME}.pc.in" "${PROJECT_NAME}-${PROJECT_VERSION}.pc" @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-${PROJECT_VERSION}.pc DESTINATION lib/pkgconfig)

