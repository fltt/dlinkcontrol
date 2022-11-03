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
