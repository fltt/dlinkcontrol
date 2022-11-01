dnl Process with 'autoreconf -i'.
AC_PREREQ([2.71])
AC_INIT([dlinkcontrol], [1.0.0], [franz.lattanzio@gmail.com])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CHECK_LIB([util], [pidfile_open], [],
             [AC_MSG_ERROR([libutil is required])])
LIBCURL_CHECK_CONFIG([yes], [7.17.0],
                     [AS_IF([test "x$libcurl_protocol_HTTP" = xyes],
                            [AC_DEFINE([HAVE_WORKING_LIBCURL], [1],
                                       [A libcurl supporting HTTP protocol was found.])
                             working_libcurl_found=yes],
                            [AC_MSG_WARN([libcurl found, but it does not support HTTP protocol])])])
AS_IF([test "x$working_libcurl_found" != xyes],
      [AC_CHECK_LIB([fetch], [fetchReqHTTP], [],
                    [AC_MSG_ERROR([libcurl nor libfetch could be found])])])
AM_CONDITIONAL([LINK_TO_LIBCURL], [test "x$working_libcurl_found" = xyes])
AC_CHECK_HEADERS([libutil.h strings.h syslog.h unistd.h sys/param.h sys/time.h])
AC_TYPE_PID_T
AC_TYPE_SIZE_T

dnl ??? keep?
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([memset stpcpy strcasecmp strchr strdup strerror strtol])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
AS_IF([test "x$ac_cv_header_libutil_h" != xyes],
      AC_MSG_WARN([libutil found but no corresponding header file found -- trying to compile nevertheless]))
