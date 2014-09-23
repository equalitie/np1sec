AC_INIT([libmpotr], [0.0.0])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AM_PROG_AR
LT_INIT

AC_PROG_CXX
AC_LANG([C++])

CXXFLAGS="-std=c++11 -Wall -Wextra -Wno-error"

GTEST_BASE=contrib/gtest
GTEST_INCLUDE=${GTEST_BASE}/include
AC_SUBST(GTEST_BASE)
AC_SUBST(GTEST_INCLUDE)



AC_CHECK_HEADERS([arpa/nameser_compat.h sys/time.h])

dnl Check for GLib
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.16.0 gobject-2.0 gmodule-2.0 gthread-2.0], , [
	AC_MSG_RESULT(no)
	AC_MSG_ERROR([No GLib])
])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM
AC_CHECK_SIZEOF(time_t, , [
	#include <stdio.h>
	#include <time.h>
])

dnl Check for LibXML2
PKG_CHECK_MODULES(LIBXML, [libxml-2.0 >= 2.6.0], , [
	AC_MSG_RESULT(no)
	AC_MSG_ERROR([No libxml2])
])
PKG_CHECK_EXISTS([libxml-2.0 >= 2.6.18], , [
	AC_MSG_WARN([libxml2 < 2.6.18])
])
AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LIBS)

AC_DEFINE_UNQUOTED(STATIC_PROTO_INIT,
	$extern_init static void static_proto_init(void) { $load_proto },
	[Loads static protocol plugin module initialization functions.]
)


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
