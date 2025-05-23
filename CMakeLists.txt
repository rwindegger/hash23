cmake_minimum_required(VERSION 3.28)

project(hash23 LANGUAGES C CXX VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

add_library(
        hash23
        INTERFACE
        include/hash23/hash23.h
        include/hash23/sha2_512.h
)
add_library(hash23::hash23 ALIAS hash23)

target_compile_features(hash23 INTERFACE cxx_std_23)

target_include_directories(
        hash23
        INTERFACE
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

install(
        TARGETS hash23
        EXPORT hash23Targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
        DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

set(hash23_CMAKE_CONFIG_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/hash23")

install(
        EXPORT hash23Targets
        FILE hash23Targets.cmake
        NAMESPACE hash23::
        DESTINATION ${hash23_CMAKE_CONFIG_DESTINATION}
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/hash23ConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
)
configure_package_config_file(
        ${CMAKE_CURRENT_LIST_DIR}/cmake/hash23Config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/hash23Config.cmake
        INSTALL_DESTINATION ${hash23_CMAKE_CONFIG_DESTINATION}
)

install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/hash23ConfigVersion.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/hash23Config.cmake
        DESTINATION ${hash23_CMAKE_CONFIG_DESTINATION}
)

export(
        EXPORT hash23Targets
        FILE ${CMAKE_CURRENT_BINARY_DIR}/hash23Targets.cmake
        NAMESPACE hash23::
)
export(PACKAGE hash23)

option(BUILD_TESTING "..." ON)
if (BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif ()
