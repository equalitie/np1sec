project(np1sec)
cmake_minimum_required(VERSION 2.8.12)

include(FindPackageHandleStandardArgs)
include(FindPkgConfig)

find_path(GCRYPT_INCLUDE_DIR gcrypt.h)
find_library(GCRYPT_LIBRARY NAMES gcrypt libgcrypt)
set( gcrypt_FIND_REQUIRED TRUE )
find_package_handle_standard_args(gcrypt DEFAULT_MSG GCRYPT_INCLUDE_DIR GCRYPT_LIBRARY)

pkg_check_modules(GLIB REQUIRED glib-2.0)
pkg_check_modules(PURPLE REQUIRED purple)

find_path(READLINE_INCLUDE_DIR readline/readline.h)
find_library(READLINE_LIBRARY NAMES readline libreadline)
set( readline_FIND_REQUIRED TRUE )
find_package_handle_standard_args(readline DEFAULT_MSG READLINE_INCLUDE_DIR READLINE_LIBRARY)





include_directories(${GCRYPT_INCLUDE_DIR})
include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${PURPLE_INCLUDE_DIRS})
include_directories(${READLINE_INCLUDE_DIRS})


add_compile_options(-std=c++11)

add_executable(jabberling
	src/base64.cc
	src/channel.cc
	src/channelcreation.cc
	src/channelsearch.cc
	src/crypto.cc
	src/jabberling.cc
	src/main.cc
	src/message.cc
	src/room.cc
)
target_link_libraries(jabberling
	${GCRYPT_LIBRARY}
	${GLIB_LIBRARIES}
	${PURPLE_LIBRARIES}
	${READLINE_LIBRARY}
)
