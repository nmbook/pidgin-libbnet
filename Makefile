#Customisable stuff here
LINUX32_COMPILER = gcc
LINUX64_COMPILER = x86_64-pc-linux-gnu-gcc
WIN32_COMPILER = /usr/bin/i586-mingw32-gcc
WIN32_WINDRES = i586-mingw32-windres
WIN32_OBJCOPY = i586-mingw32-objcopy
#LINUX_ARM_COMPILER = arm-pc-linux-gnu-gcc
LINUX_ARM_COMPILER = arm-none-linux-gnueabi-gcc
LINUX_PPC_COMPILER = powerpc-unknown-linux-gnu-gcc
FREEBSD60_COMPILER = i686-pc-freebsd6.0-gcc
MACPORT_COMPILER = i686-apple-darwin10-gcc-4.0.1

LIBPURPLE_CFLAGS = -I/usr/include/libpurple -I/usr/local/include/libpurple -DPURPLE_PLUGINS -DENABLE_NLS -DHAVE_ZLIB
GLIB_CFLAGS = -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include -I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include -I/usr/local/include
WIN32_DEV_DIR = /root/pidgin/win32-dev
WIN32_PIDGIN_DIR = /root/pidgin/pidgin-2.3.0_win32
WIN32_CFLAGS = -I${WIN32_DEV_DIR}/gtk_2_0/include/glib-2.0 -I${WIN32_PIDGIN_DIR}/libpurple/win32 -I${WIN32_DEV_DIR}/gtk_2_0/include -I${WIN32_DEV_DIR}/gtk_2_0/include/glib-2.0 -I${WIN32_DEV_DIR}/gtk_2_0/lib/glib-2.0/include -I/usr/include/json-glib-1.0 -Wno-format
WIN32_LIBS = -L${WIN32_DEV_DIR}/gtk_2_0/lib -L${WIN32_PIDGIN_DIR}/libpurple -lglib-2.0 -lgobject-2.0 -lintl -lpurple -lws2_32 -L. -lzlib1
MACPORT_CFLAGS = -I/opt/local/include/libpurple -DPURPLE_PLUGINS -DENABLE_NLS -DHAVE_ZLIB -I/opt/local/include/glib-2.0 -I/opt/local/lib/glib-2.0/include -I/opt/local/include -I/opt/local/include/json-glib-1.0 -arch i386 -arch ppc -dynamiclib -L/opt/local/lib -lpurple -lglib-2.0 -lgobject-2.0 -lintl -lz -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4
PIDGIN_DIR = /root/pidgin/pidgin-2.7.0

DEB_PACKAGE_DIR = ./debdir

BNET_SOURCES = bnet.c

#Standard stuff here
.PHONY: all clean install sourcepackage

all:    libbnet.so libbnet.dll libbnet64.so libbnetarm.so libbnetppc.so installers sourcepackage

install:
	cp libbnet.so /usr/lib/purple-2/
	cp libbnet64.so /usr/lib64/purple-2/
	cp libbnetarm.so /usr/lib/pidgin/
	cp libbnetppc.so /usr/lib/purple-2/
	cp bnet-16.png /usr/share/pixmaps/pidgin/protocols/16/bnet.png
	cp bnet-22.png /usr/share/pixmaps/pidgin/protocols/22/bnet.png
	cp bnet-48.png /usr/share/pixmaps/pidgin/protocols/48/bnet.png

installers:     pidgin-libbnet-0.7.0.exe pidgin-libbnet.rpm pidgin-libbnet.tar.bz2

clean:
	rm -f libbnet.so libbnet.dll libbnet64.so libbnetarm.so libbnetppc.so pidgin-libbnet-0.7.0.exe pidgin-libbnet.rpm pidgin-libbnet.tar.bz2 pidgin-libbnet-source.tar.bz2
	rm -rf pidgin-libbnet

libbnet.macport.so: ${BNET_SOURCES}
	${MACPORT_COMPILER} ${MACPORT_CFLAGS} -Wall -I. -g -O2 -pipe ${BNET_SOURCES} -o libbnet.macport.so -shared

libbnet.so: ${BNET_SOURCES}
	${LINUX32_COMPILER} ${LIBPURPLE_CFLAGS} -Wall ${GLIB_CFLAGS} -I. -g -O2 -pipe ${BNET_SOURCES} -o libbnet.so -shared -fPIC -DPIC

libbnetarm.so:      ${BNET_SOURCES}
	${LINUX_ARM_COMPILER} ${LIBPURPLE_CFLAGS} -Wall ${GLIB_CFLAGS} -I. -g -O2 -pipe ${BNET_SOURCES} -o libbnetarm.so -shared -fPIC -DPIC

libbnet64.so:       ${BNET_SOURCES}
	${LINUX64_COMPILER} ${LIBPURPLE_CFLAGS} -Wall ${GLIB_CFLAGS} -I. -g -m64 -O2 -pipe ${BNET_SOURCES} -o libbnet64.so -shared -fPIC -DPIC

libbnetppc.so:      ${BNET_SOURCES}
	${LINUX_PPC_COMPILER} ${LIBPURPLE_CFLAGS} -Wall ${GLIB_CFLAGS} -I. -g -O2 -pipe ${BNET_SOURCES} -o libbnetppc.so -shared -fPIC -DPIC

libbnetmacport.so: ${BNET_SOURCES}
	${MACPORT_COMPILER} ${MACPORT_CFLAGS} -Wall -I. -g -O2 -pipe ${BNET_SOURCES} -o libbnetmacport.so -shared

#pidgin-libbnet.res:	pidgin-libbnet.rc
#	${WIN32_WINDRES} $< -O coff -o $@

libbnet.dll:	${BNET_SOURCES} 
	${WIN32_COMPILER} ${LIBPURPLE_CFLAGS} -Wall -I. -g -O2 -pipe ${BNET_SOURCES}  -o $@ -shared -mno-cygwin ${WIN32_CFLAGS} ${WIN32_LIBS}
	${WIN32_OBJCOPY} --only-keep-debug $@ $@.dbg
	${WIN32_OBJCOPY} --strip-debug $@
	${WIN32_OBJCOPY} --add-gnu-debuglink=$@.dbg $@
	upx libbnet.dll
	#pidgin-facebookchat.res
	#pidgin-facebookchat.res

libbnet-debug.dll:  ${BNET_SOURCES}
	${WIN32_COMPILER} ${LIBPURPLE_CFLAGS} -Wall -I. -g -O2 -pipe ${BNET_SOURCES}  -o $@ -shared -mno-cygwin ${WIN32_CFLAGS} ${WIN32_LIBS}
	#pidgin-facebookchat.res
	#pidgin-facebookchat.res

libbnetbsd60.so:    ${BNET_SOURCES}
	${FREEBSD60_COMPILER} ${LIBPURPLE_CFLAGS} -Wall ${GLIB_CFLAGS} -I. -g -O2 -pipe ${BNET_SOURCES} -o libbnet.so -shared -fPIC -DPIC


#pidgin-facebookchat.exe:	libfacebook.dll
#	echo "Dont forget to update version number"
#	makensis facebook.nsi > /dev/null
	
#pidgin-facebookchat.deb:	libfacebook.so libfacebookarm.so libfacebook64.so libfacebookppc.so
#	echo "Dont forget to update version number"
#	cp libfacebook.so ${DEB_PACKAGE_DIR}/usr/lib/purple-2/
#	cp libfacebookppc.so ${DEB_PACKAGE_DIR}/usr/lib/purple-2/
#	cp libfacebook64.so ${DEB_PACKAGE_DIR}/usr/lib64/purple-2/
#	cp libfacebookarm.so ${DEB_PACKAGE_DIR}/usr/lib/pidgin/
#	cp facebook16.png ${DEB_PACKAGE_DIR}/usr/share/pixmaps/pidgin/protocols/16/facebook.png
#	cp facebook22.png ${DEB_PACKAGE_DIR}/usr/share/pixmaps/pidgin/protocols/22/facebook.png
#	cp facebook48.png ${DEB_PACKAGE_DIR}/usr/share/pixmaps/pidgin/protocols/48/facebook.png
#	chown -R root:root ${DEB_PACKAGE_DIR}
#	chmod -R 755 ${DEB_PACKAGE_DIR}
#	dpkg-deb --build ${DEB_PACKAGE_DIR} $@ > /dev/null

#pidgin-facebookchat.tar.bz2:    pidgin-facebookchat.deb
#	tar --bzip2 --directory ${DEB_PACKAGE_DIR} -cf $@ usr/

#sourcepackage:  ${FACEBOOK_SOURCES} Makefile facebook16.png facebook22.png facebook48.png COPYING facebook.nsi
#	tar -cf tmp.tar $^
#	mkdir pidgin-facebookchat
#	mv tmp.tar pidgin-facebookchat
#	tar xvf pidgin-facebookchat/tmp.tar -C pidgin-facebookchat
#	rm pidgin-facebookchat/tmp.tar
#	tar --bzip2 -cf pidgin-facebookchat-source.tar.bz2 pidgin-facebookchat
#	rm -rf pidgin-facebookchat

