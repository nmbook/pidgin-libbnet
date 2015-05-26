# Classic Battle.net Plugin for Pidgin

Introduction
------------

This plugin allows you to connect to Battle.net with Pidgin in order to chat.

Battle.net is the Blizzard Entertainment gaming service that connects WarCraft II, StarCraft, Diablo II, WarCraft III (and other) games on a single chatting, stats-saving, and matchmaking system.

This plugin provides chat features only and will not under any circumstance join games or alter the in-game experience for any of the above games. It requires that you own the game you are chatting as (by requiring a CD key for that game).

This plugin requires that you specify an external 3rd-party "Logon Server" (otherwise known as BNLS for Battle.net Logon Server) that emulates the version checking process, and does not require any additional local files. The default BNLS, "bnls.net", should be trusted to do this.

Setup
=====

How to set up an account and join a channel on Battle.net using Pidgin.

For those of you who commonly use "bots" or any of the official clients (StarCraft, Diablo, Diablo II, WarCraft II, or WarCraft III), this page explains how to use Pidgin with this plugin installed as an alternative chat-only client.

Install on Windows
------------------

To install the plugin on Windows, just run the [installer for version 1.1.0] [3]. It will ask for your pidgin folder, by default this is C:\Program Files\Pidgin. On 64-bit systems this will be C:\Program Files (x86)\Pidgin. It will check if pidgin.exe is there to determine if this is actually your Pidgin folder. If so it'll install the required DLLs for you.

Since Pidgin is 32-bit only on Windows, so is my plugin. This makes Windows the easiest for the user to install on.

Install on Linux
----------------

To install on Linux, compile the .so file and place in  `~/.purple/plugins/libbnet.so`. See the SVN source repository for it.

From version 0.8.0 and on, you will need to download the libgmp package (gmp on Fedora).

To get the protocol icons, do the following copies from Github to your system:
/home/lio/pidgin-libbnet/dist/pixmaps/pidgin/protocols/16
```
wget -O /usr/share/pixmaps/pidgin/protocols/16/bnet.png -- https://github.com/nmbook/pidgin-libbnet/dist/pixmaps/pidgin/protocols/16/bnet.png
wget -O /usr/share/pixmaps/pidgin/protocols/22/bnet.png -- https://github.com/nmbook/pidgin-libbnet/dist/pixmaps/pidgin/protocols/22/bnet.png
wget -O /usr/share/pixmaps/pidgin/protocols/48/bnet.png -- https://github.com/nmbook/pidgin-libbnet/dist/pixmaps/pidgin/protocols/48/bnet.png
```

Soon I plan to make a DEB and RPM that will automate this process.

From Source on Linux
--------------------

You can download and compile the source yourself. Linux users might want to do this as the .so library files I made are specifically for a certain ABI of GMP which may not be the same as the one provided by your distribution.

To compile this plugin, you need libpurple development headers, GMP development headers, and glib development headers, and the source.

Here's a sequence of commands that will compile it for you from the git repository.

1. Get necessary packages.
    Make sure you have the following packages to compile and link against:

    Fedora/RPM-based
    * libpurple-devel
    * glib-devel
    * gmp-devel
    
    Ubuntu/DEB-based
    * libpurple-dev
    * libglib-dev
    * libgmp-dev
    
    Make sure you have the following packages to run the commands:
    * git
    * gcc
    * autoconf
    * libtool
    * make

2. Get the code with this command:

      ```
      git clone http://github.com/nmbook/pidgin-libbnet/
      ```

3. Run these commands:

      ```
      ./autogen.sh
      ./configure
      make
      ```

4. Automatically move the binary to your purple plugins folder (this part requires root or sudo):

      ```
      make install
      ```


From Source on Windows
----------------------

This is not easy on Windows. To do this on Windows, you need to set up a [Pidgin development environment as detailed here (click)] [2]. 

Then after building it, I placed the source of my plugin in ```<path to pidgin source>/libpurple/protocols/bnet/```. If you follow the directions above and attempt to build it you'll get lots of errors. Once you have enough of it built that libpurple.dll is created, you can stop, since this plugin does not rely on pidgin or finch at all.

Then I compiled GMP using MinGW (not Cygwin) (this was not easy).

Then I used the command in bnet/src/:

    make -f Makefile.mingw

Then to install you can either do:

    make -f Makefile.mingw install

Or place the DLL in ```%appdata%/.purple/plugins``` yourself.
It will try to move the pixmaps to ```<pidgin install directory>\pixmaps\pidgin\protocols\##\bnet.png``` for each ##=16,22,48 so that Pidgin can read them.

UPDATE: My makefile was using an outdated switch (```-mno-cygwin```) to use MinGW instead of linking against ```cygwin1.dll``` when I wrote the above. Now that I've updated to the newest Cygwin, I had to make sure that it was using the MinGW gcc and not Cygwin's (using a little bit of PATH hacking). Remember how I made the DLL and the installer so you don't have to compile this yourself?

Create an Account
=================

Once you have the plugin in the right place, you should be able to just create a Classic Battle.net account. Enter your username and password, then enter the game to emulate in the Advanced tab, then enter your CD-Key(s). Then you should be able to just connect.

Joining a Channel
=================

Use Pidgin's Buddies > Join a chat menu item and join a channel on the  Battle.net account you made.

If you have used Battle.net before, you know that for some clients you go to a default channel immediately upon log on. To simplify things, this channel is not reported to Pidgin. Instead the first channel you attempt to join is. So you can easily set a channel to "Auto-Join" and "Persistent" in your buddy list (add the chat from the conversation, then right click the channel in your buddy list) and that'll be the only channel you join.

Do not set more than one channel to Auto-Join since Battle.net's protocol only allows you to physically be in one channel at a time. Doing this would cause you to join the selected channels in succession, activating Battle.net's spam detection which will kick you from Battle.net for five to ten minutes.

Questions
=========

Q: I get "The provided CD-key could not be decoded."
A: This error means that the key you provided was not valid enough to be decoded, or was completely empty. Maybe you forgot to fill it in?

Q: I want to use this plugin with another libpurple program, such as Finch, Adium, Empathy, Instantbird, Meebo, Myfavoritelibpurpleprogram, ...!
A: I have actually investigated many different programs that utilize libpurple, here's what I've found:

* Pidgin: The .so can be used as-is for Pidgin. The Windows installer is for Pidgin.
* Finch (Linux only): do the same you do for Pidgin on Linux! You don't need the protocol icons since Finch can't use them.
* Empathy (Linux only): do the same, but put the protocol icons somewhere else. Empathy does not support chats/channels, so Empathy is an awful UI for this plugin (most Battle.net users use channels).
* Adium (Mac OS X only): if someone tries it, tell me!
* Others: none that I know of at this time that will work.

[1]: https://github.com/nmbook/pidgin-libbnet/blob/master/COMPILE.md "Compiling from Source"
[2]: http://developer.pidgin.im/wiki/BuildingWinPidgin               "Pidgin Development Environment on Windows"
[3]: https://github.com/nmbook/pidgin-libbnet/blob/master/dist/win32/out/pidgin-libbnet-1.1.0.exe "Current Windows Installer (v1.1.0)"
