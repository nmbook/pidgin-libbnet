## Process this file with automake to produce Makefile.in
plugindir = $(libdir)/purple-2
plugin_LTLIBRARIES = libbnet.la
libbnet_la_SOURCES = bnet.c bufferer.c keydecode.c sha1.c srp.c userdata.c w3clan.c
libbnet_la_CFLAGS = $(PURPLE_CFLAGS) $(GLIB_CFLAGS) $(GMP_CFLAGS) -DPURPLE_PLUGINS -Wall -Waggregate-return -Wcast-align -Wdeclaration-after-statement -Werror-implicit-function-declaration -Wextra -Wno-sign-compare -Wno-unused-parameter -Winit-self -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wundef -Wno-multichar
libbnet_la_LDFLAGS = -version-info 0:0:0 -module -Wall -Werror
libbnet_la_LIBADD = $(PURPLE_LIBS) $(GLIB_LIBS) $(GMP_LIBS)
EXTRA_DIST = \
    bnet.h \
    bufferer.h \
    keydecode.h \
    sha1.h \
    srp.h \
    userdata.h \
    w3clan.h

