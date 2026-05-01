cmake_minimum_required(VERSION 3.10)
project(pcloudcc)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 99)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZLIB REQUIRED zlib)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(READLINE REQUIRED readline)

# FUSE
pkg_check_modules(FUSE3 fuse3)
if(FUSE3_FOUND)
    set(FUSE_LIBS ${FUSE3_LIBRARIES})
    set(FUSE_CFLAGS ${FUSE3_CFLAGS})
    add_definitions(-DFUSE_USE_VERSION=30)
else()
    pkg_check_modules(FUSE REQUIRED fuse)
    set(FUSE_LIBS ${FUSE_LIBRARIES})
    set(FUSE_CFLAGS ${FUSE_CFLAGS})
    add_definitions(-DFUSE_USE_VERSION=26)
endif()

# mbedTLS
pkg_check_modules(MBEDTLS REQUIRED mbedtls mbedx509 mbedcrypto)

# udev
pkg_check_modules(UDEV REQUIRED libudev)

# Sources
file(GLOB PCLSYNC_SOURCES "pclsync/*.c")
set(PCLOUDCC_SOURCES
    main.cpp
    control_tools.cpp
    pclsync_lib.cpp
    rpcclient.cpp
)

add_executable(pcloudcc ${PCLOUDCC_SOURCES} ${PCLSYNC_SOURCES})

target_include_directories(pcloudcc PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/pclsync
    ${ZLIB_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
    ${READLINE_INCLUDE_DIRS}
    ${FUSE_INCLUDE_DIRS}
    ${MBEDTLS_INCLUDE_DIRS}
    ${UDEV_INCLUDE_DIRS}
)

target_link_libraries(pcloudcc 
    ${ZLIB_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    ${READLINE_LIBRARIES}
    ${FUSE_LIBS}
    ${MBEDTLS_LIBRARIES}
    ${UDEV_LIBRARIES}
    pthread
)

add_definitions(-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE)
