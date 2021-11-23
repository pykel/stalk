cmake_minimum_required(VERSION 3.12)

project(stalk VERSION 1.0.0)

# make cache variables for install destinations
include(GNUInstallDirs)

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
    ${HEADER_PATH}/stalk_connection_detail_fmt.h
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
    ${HEADER_PATH}/stalk_logger_interface.h
    )

set(SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_logger.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_web_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_request.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_response.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_websocket_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_websocket_session_impl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_router.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stalk_route.cpp
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
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR})

target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(${PROJECT_NAME} PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>"
)

INSTALL(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}Targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
INSTALL(FILES ${HEADER_FILES} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/stalk")

set(DEST_DIR "${CMAKE_INSTALL_PREFIX}")
set(INCLUDE_PATH "/${PROJECT_NAME}-${CMAKE_PROJECT_VERSION_MAJOR}.0")
foreach(LIB ${PROJECT_NAME})
  set(PRIVATE_LIBS "${PRIVATE_LIBS} -l${LIB}")
endforeach()

CONFIGURE_FILE("${PROJECT_NAME}.pc.in" "${PROJECT_NAME}-${CMAKE_PROJECT_VERSION_MAJOR}.0.pc" @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-${CMAKE_PROJECT_VERSION_MAJOR}.0.pc DESTINATION lib/pkgconfig)

install(EXPORT ${PROJECT_NAME}Targets
        FILE ${PROJECT_NAME}Targets.cmake
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/stalk
)

export(EXPORT ${PROJECT_NAME}Targets
       FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/${PROJECT_NAME}Targets.cmake"
       NAMESPACE ${PROJECT_NAME}::
)

include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
# generate the version file for the config file
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  VERSION "${version}"
  COMPATIBILITY AnyNewerVersion
)
install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

## PACKAGING ##
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_STRIP_FILES TRUE)
#set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)
