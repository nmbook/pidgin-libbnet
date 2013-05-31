# Compiling this plugin on various systems.

Introduction
============

To compile this plugin, you basically need libpurple development headers, GMP development headers, and glib development headers, and the source.

Linux
-----

Here's a sequence of commands that will compile it for you.

1. Get necessary packages.
    Make sure you have the following packages:
    Fedora/RPM-based
    * libpurple-devel
    * glib-devel
    * gmp-devel
    Ubuntu/DEB-based
    * libpurple-dev
    * libglib-dev
    * libgmp-dev
2. Clone git:
      git clone http://github.com/nmbook/pidgin-libbnet/
3. Run make:
      make
4. If no errors, install the libbnet.so file produced in your `~/.purple/plugins` directory.
5. This is automatically done if you type (as root):
      make install


Windows
-------

This is not easy on Windows. To do this on Windows, you need to set up a Pidgin development environment as detailed here: http://developer.pidgin.im/wiki/BuildingWinPidgin

Then after building it, I placed the source of my plugin in `<path to pidgin source>`/libpurple/protocols/bnet/. If you follow the directions above and attempt to build it you'll get lots of errors. Once you have enough of it built that libpurple.dll is created, you can stop, since this plugin does not rely on pidgin or finch at all.

Then I compiled GMP using MinGW (not Cygwin) (this was not easy).

Then I used the command in bnet/:

 make

Then to install you can either do:

    make install

Or place the DLL in `%appdata%/.purple/plugins` yourself.
It will try to move the pixmaps to C:\Program Files\Pidgin (where ever it's installed)\pixmaps\pidgin\protocols\##\bnet.png for each ##=16,22,48 so that Pidgin can read them.

UPDATE: My makefile was using an outdated switch (`-mno-cygwin`) to use MinGW instead of linking against `cygwin1.dll` when I wrote the above. Now that I've updated to the newest Cygwin, I had to make sure that it was using the MinGW gcc and not Cygwin's (using a little bit of PATH hacking). Remember how I made the DLL and the installer so you don't have to compile this yourself?

