AC_INIT([libmpotr], [0.0.0])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AM_PROG_AR
LT_INIT

AC_PROG_CXX
AC_LANG([C++])

CXXFLAGS = "-std=c++11 -Wall -Wextra -Werror"

GTEST_BASE=contrib/gtest
GTEST_INCLUDE=${GTEST_BASE}/include
AC_SUBST(GTEST_BASE)
AC_SUBST(GTEST_INCLUDE)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
