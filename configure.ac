# Copyright (c) 2022, 2023 Francesco Lattanzio
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

AC_PREREQ([2.71])
AC_INIT([D-Link Control], [1.0.2], [franz.lattanzio@gmail.com],
        [dlinkcontrol], [https://github.com/fltt/dlinkcontrol])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
gl_EARLY
AC_SEARCH_LIBS([pidfile_open], [bsd util], [],
               [AC_MSG_ERROR([could not find pidfile_open function])])
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
