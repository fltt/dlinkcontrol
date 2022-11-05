# Copyright 2022 Francesco Lattanzio
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

bin_PROGRAMS = dlinkcontrol

if LINK_TO_LIBCURL
LIBCURL_PREPROCESSOR_OPTIONS = $(LIBCURL_CPPFLAGS)
LIBCURL_LINKER_OPTIONS = $(LIBCURL)
else
LIBCURL_PREPROCESSOR_OPTIONS =
LIBCURL_LINKER_OPTIONS =
endif

dlinkcontrol_SOURCES = dlinkcontrol.c cJSON.h cJSON.c
dlinkcontrol_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib $(LIBCURL_PREPROCESSOR_OPTIONS)
dlinkcontrol_LDFLAGS = $(LIBCURL_LINKER_OPTIONS)
dlinkcontrol_LDADD = $(top_builddir)/lib/libgnu.a
