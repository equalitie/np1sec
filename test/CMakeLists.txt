include(FindPkgConfig)

pkg_check_modules(GLIB REQUIRED glib-2.0)
pkg_check_modules(PURPLE REQUIRED purple)

find_path(READLINE_INCLUDE_DIR readline/readline.h)
find_library(READLINE_LIBRARY NAMES readline libreadline)
set( readline_FIND_REQUIRED TRUE )
find_package_handle_standard_args(readline DEFAULT_MSG READLINE_INCLUDE_DIR READLINE_LIBRARY)



include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${PURPLE_INCLUDE_DIRS})
include_directories(${READLINE_INCLUDE_DIRS})

add_executable(jabberite
	test/jabberite/cli-ui.cc
	test/jabberite/jabberite.cc
)
target_link_libraries(jabberite
	np1sec
	${GLIB_LIBRARIES}
	${PURPLE_LIBRARIES}
	${READLINE_LIBRARY}
)
