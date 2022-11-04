dnl Process with 'autoreconf -i'.
AC_PREREQ([2.71])
AC_INIT([dlinkcontrol],[1.0.0],[franz.lattanzio@gmail.com])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
gl_EARLY
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
AC_CHECK_HEADERS([libutil.h syslog.h sys/param.h])
gl_INIT
AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 src/Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
AS_IF([test "x$ac_cv_header_libutil_h" != xyes],
      AC_MSG_WARN([libutil found but no corresponding header file found -- trying to compile nevertheless]))
AS_IF([test "x$ac_cv_header_syslog_h" != xyes],
      AC_MSG_WARN([syslog.h not found -- logging to syslog won't be available]))
