cmake_minimum_required(VERSION 3.5)
project(pcloudcc)

#INCLUDE(CPack)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
unset(Boost_INCLUDE_DIR CACHE)
unset(Boost_LIBRARY_DIRS CACHE)

find_package(Boost COMPONENTS system program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
#set (CMAKE_CXX_FLAGS "-static -Wl,-Bstatic")
#set (CMAKE_CXX_FLAGS "-Wl,-Bstatic")
set (CMAKE_C_FLAGS "-fPIC")
set (PCLSYNC_PATH ${CMAKE_SOURCE_DIR}/lib/pclsync)
set (MBEDTLS_PATH ${CMAKE_SOURCE_DIR}/lib/mbedtls-1.3.10)
set (CMD_PATH ${CMAKE_SOURCE_DIR}/cmd/pcloudcc)

#add_subdirectory(${MBEDTLS_PATH})

include_directories(${PCLSYNC_PATH})
add_custom_target(
  pclsync
  COMMAND make fs
  WORKING_DIRECTORY ${PCLSYNC_PATH}
)
add_custom_target(
  mbedtls
  COMMAND cmake . && make
  WORKING_DIRECTORY ${MBEDTLS_PATH}
) 

set (OVERLAY_CLENT_PATH ${CMAKE_SOURCE_DIR}/lib/poverlay_linux)
include_directories(${OVERLAY_CLENT_PATH})

add_library(pcloudcc_lib SHARED ${CMD_PATH}/pclsync_lib_c.cpp ${CMD_PATH}/pclsync_lib.cpp ${CMD_PATH}/control_tools.cpp ${OVERLAY_CLENT_PATH}/overlay_client.c ${OVERLAY_CLENT_PATH}/debug.c )

target_link_libraries(pcloudcc_lib
	${PCLSYNC_PATH}/psynclib.a
	${MBEDTLS_PATH}/build/library/libmbedtls.a
	fuse
	pthread
	sqlite3
	z
	dl
	udev)

add_executable(pcloudcc ${CMD_PATH}/main.cpp)

target_link_libraries(pcloudcc pcloudcc_lib)

target_link_libraries(pcloudcc ${Boost_LIBRARIES})

link_directories(${PCLSYNC_PATH} ${MBEDTLS_PATH}/build/library ${OVERLAY_CLENT_PATH})

install(TARGETS pcloudcc RUNTIME DESTINATION bin)
install(TARGETS pcloudcc_lib LIBRARY DESTINATION lib)


