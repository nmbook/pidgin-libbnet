# The new makefile for libbnet
# On Cygwin or Linux:
#  make
#  make install
# This should work on any of these systems:
#  Cygwin under 32-bit Windows
#  Cygwin under 32-bit Windows (using WOW64)
#  Linux x86
#  Linux x86_64
#  Tell me if there's a system you want libbnet.so to compile for!
#  I will add it if libpurple can be compiled there...

# modify this to use a different compiler
CC := gcc
# modify this to add/remove the -g flag for
CC_DEBUG := yes

# OS (operating system, currently either Cygwin or Linux/Other) and OS_64 (is OS 64-bit?)
UNAME = $(shell uname)
UNAMER = $(shell uname -r)
ifeq (,$(findstring CYGWIN,$(UNAME)))
OS = LinuxOther
ifeq (,$(findstring x86_64,$(UNAMER)))
$(info Operating System: Linux x86)
OS_64 = no
else
$(info Operating System: Linux x86_64)
OS_64 = yes
endif
else
OS = Cygwin
ifeq (,$(findstring WOW64,$(UNAME)))
$(info Operating System: Windows 32-bit)
OS_64 = no
else
$(info Operating System: Windows 32-bit WOW64)
OS_64 = yes
endif
endif

# tops for -I and -L
PIDGIN_TREE_TOP := ../../..
PURPLE_TOP := $(PIDGIN_TREE_TOP)/libpurple
W32_TOP := $(PIDGIN_TREE_TOP)/../win32-dev

# list of warnings, same as for official Pidgin protocols, except we add:
# -Wno-multichar
#   A lot of B.net depends on using constants such as 'WAR3' as "character" constants.
#   Rather than convert them to hex equivs (would have been error-prone, and left it harder
#   to look at later), I just added this flag to the compile
CC_WARNINGS = -Wall -Waggregate-return -Wcast-align -Wdeclaration-after-statement -Werror-implicit-function-declaration -Wextra -Wno-sign-compare -Wno-unused-parameter -Winit-self -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wundef -Wno-multichar

ifeq ($(CC_DEBUG),yes)
CC_DBG = -g
else
CC_DBG =
endif

ifeq ($(OS),Cygwin)
CC_COMPFLAGS = -mno-cygwin -mms-bitfields -DWIN32_LEAN_AND_MEAN
else
CC_COMPFLAGS = -fPIC
endif

ifeq ($(OS),Cygwin)
CC_LINKFLAGS = -Wl,--enable-auto-image-base
else
CC_LINKFLAGS = -Wl,-soname,$@
endif

# flags to compile a .c -> .o
CC_COMPILE = -O2 $(CC_WARNINGS) -pipe $(CC_COMPFLAGS) $(CC_DBG) $(INC_PATHS) -c $(@:%.o=%.c) -o $@
# flags to link .o's -> .dll or .so
CC_LINK = -shared $(OBJECTS) $(LIB_PATHS) $(LIBS) $(CC_LINKFLAGS) -o $@

# -I: self, purple, glib, gmp
ifeq ($(OS),Cygwin)
INC_PATHS = -I. -I$(PURPLE_TOP) -I$(PURPLE_TOP)/win32 -I$(W32_TOP)/gtk_2_0-2.16/include/glib-2.0 -I$(W32_TOP)/gmp-5.0.1/include
else
INC_PATHS = -I. -I$(PURPLE_TOP) -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I/usr/lib/glib-2.0/include -I/usr/include
endif
# -L: purple, glib, gmp
ifeq ($(OS),Cygwin)
LIB_PATHS = -L$(PURPLE_TOP) -L$(W32_TOP)/gtk_2_0-2.16/lib -L$(W32_TOP)/gmp-5.0.1/lib
else
LIB_PATHS = -L$(PURPLE_TOP) -L/usr/lib -L/usr/lib64
endif
# -l
ifeq ($(OS),Cygwin)
W32_LIBS = -lintl -lws2_32
else
W32_LIBS =
endif
LIBS = -lpurple -lglib-2.0 -lgmp $(W32_LIBS)

TARGET = libbnet
SOURCES = bnet.c packets.c srp.c keydecode.c bnet-sha1.c
OBJECTS = $(SOURCES:%.c=%.o)

#Standard stuff here
.PHONY: all clean install makedir-win32

ifeq ($(OS),Cygwin)
all: $(TARGET).dll
else
all: $(TARGET).so
endif

%.o: %.c
	$(CC) $(CC_COMPILE)

$(TARGET).so $(TARGET).dll: $(OBJECTS)
	$(CC) $(CC_LINK)

# stops implicit rule spam in make -d
Makefile: ;
# stops more implicit rule spam
%.c: ;

clean:
	rm *.o

ifeq ($(OS),Cygwin)
ifeq ($(OS_64),yes)
install: mkdir-win32
	cp $(TARGET).dll $$APPDATA/.purple/plugins/$(TARGET).dll
	cp pixmaps/pidgin/protocols/16/bnet.png /cygdrive/c/Program\ Files\ \(x86\)/Pidgin/pixmaps/pidgin/protocols/16/bnet.png
	cp pixmaps/pidgin/protocols/22/bnet.png /cygdrive/c/Program\ Files\ \(x86\)/Pidgin/pixmaps/pidgin/protocols/22/bnet.png
	cp pixmaps/pidgin/protocols/48/bnet.png /cygdrive/c/Program\ Files\ \(x86\)/Pidgin/pixmaps/pidgin/protocols/48/bnet.png
else
install: mkdir-win32
	cp $(TARGET).dll $$APPDATA/.purple/plugins/$(TARGET).dll
	cp pixmaps/pidgin/protocols/16/bnet.png /cygdrive/c/Program\ Files/Pidgin/pixmaps/pidgin/protocols/16/bnet.png
	cp pixmaps/pidgin/protocols/22/bnet.png /cygdrive/c/Program\ Files/Pidgin/pixmaps/pidgin/protocols/22/bnet.png
	cp pixmaps/pidgin/protocols/48/bnet.png /cygdrive/c/Program\ Files/Pidgin/pixmaps/pidgin/protocols/48/bnet.png
endif
else
ifeq ($(OS_64),yes)
install:
	cp $(TARGET).so /usr/lib64/purple-2/$(TARGET).so
	cp pixmaps/pidgin/protocols/16/bnet.png /usr/share/pixmaps/pidgin/protocols/16/bnet.png
	cp pixmaps/pidgin/protocols/22/bnet.png /usr/share/pixmaps/pidgin/protocols/22/bnet.png
	cp pixmaps/pidgin/protocols/48/bnet.png /usr/share/pixmaps/pidgin/protocols/48/bnet.png
else
install:
	cp $(TARGET).so /usr/lib/purple/$(TARGET).so
	cp pixmaps/pidgin/protocols/16/bnet.png /usr/share/pixmaps/pidgin/protocols/16/bnet.png
	cp pixmaps/pidgin/protocols/22/bnet.png /usr/share/pixmaps/pidgin/protocols/22/bnet.png
	cp pixmaps/pidgin/protocols/48/bnet.png /usr/share/pixmaps/pidgin/protocols/48/bnet.png
endif
endif

mkdir-win32:
	mkdir $$APPDATA/.purple/plugins

