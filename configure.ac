#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pidgin-libbnet], [1.0.0], [nmbook@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AM_PROG_AR
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/w3clan.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for Pidgin
PKG_CHECK_MODULES([PURPLE], purple, [AC_DEFINE(HAVE_PURPLE, 1, [Define if we have found libpurple.])])
AC_SUBST(PURPLE_CFLAGS)
AC_SUBST(PURPLE_LIBS)

# Checks for glib
AM_PATH_GLIB_2_0([2.14.0], [], AC_MSG_ERROR([
*** GLib >= 2.14.0 is required to build libbnet; please make sure you have
*** the GLib development headers installed. The latest version of GLib is
*** always available at http://www.gtk.org]), [gthread])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

# Checks for gmp
AC_CHECK_LIB([gmp], [__gmpz_init], [], [AC_MSG_ERROR([
*** libgmp, the GNU MP Bignum library, is required to build libbnet for
*** WarCraft III support; please make sure you have the gmp development
*** headers installed.])])
AC_SUBST(GMP_CFLAGS)
AC_SUBST(GMP_LIBS)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memmove memset strpbrk])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

