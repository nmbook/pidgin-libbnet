# Install, Setup, Connect
How to set up an account and join a channel on Pidgin

Introduction
============

For those of you who commonly use "bots" or any of the official clients (StarCraft, Diablo, Diablo II, WarCraft II, or WarCraft III), this page explains how to use Pidgin with this plugin installed as an alternative chat-only client.

Install the Plugin
==================

Windows
-------

To install the plugin on Windows, just run the featured installer. It will ask for your pidgin folder, by default this is C:\Program Files\Pidgin. On 64-bit systems this will be C:\Program Files (x86)\Pidgin. It will check if pidgin.exe is there to determine if this is actually your Pidgin folder. If so it'll install the required DLLs for you.

(screenshot here)

Since Pidgin is 32-bit only on Windows, so is my plugin. This makes Windows the easiest for the user to install on.

Linux
-----

To install on Linux, I will provide an .so file to download and place in  `~/.purple/plugins/libbnet.so`. See the SVN source repository for it.

From version 0.8.0 and on, you will need to download the libgmp package (gmp on Fedora).

To get the protocol icons, do the following copies from Github to your system:

```
wget -O /usr/share/pixmaps/pidgin/protocols/16/bnet.png -- https://github.com/nmbook/pidgin-libbnet/pixmaps/pidgin/protocols/16/bnet.png
wget -O /usr/share/pixmaps/pidgin/protocols/22/bnet.png -- https://github.com/nmbook/pidgin-libbnet/pixmaps/pidgin/protocols/22/bnet.png
wget -O /usr/share/pixmaps/pidgin/protocols/48/bnet.png -- https://github.com/nmbook/pidgin-libbnet/pixmaps/pidgin/protocols/48/bnet.png
```

Eventually I plan to make a DEB and RPM that will automate this process.

Source
------

You can download and compile the source yourself. Linux users might want to do this as the .so library files I made are specifically for a certain ABI of GMP which may not be the same as the one provided by your distribution.

See: [CompileFromSource] [1]

Create an Account
=================

Once you have the plugin in the right place, you should be able to just create a Classic Battle.net account. Enter your username and password, then enter the game to emulate in the Advanced tab, then enter your CD-Key(s). Then you should be able to just connect.

(screenshot here)

Joining a Channel
=================

Use Pidgin's Buddies > Join a chat menu item and join a channel on the  Battle.net account you made.

(screenshot here)

If you have used Battle.net before, you know that for some clients you go to a default channel immediately upon log on. To simplify things, this channel is not reported to Pidgin. Instead the first channel you attempt to join is. So you can easily set a channel to "Auto-Join" and "Persistent" in your buddy list (add the chat from the conversation, then right click the channel in your buddy list) and that'll be the only channel you join.

(screenshot here)

Do not set more than one channel to Auto-Join since Battle.net's protocol only allows you to physically be in one channel at a time. Doing this would cause you to join the selected channels in succession, activating Battle.net's spam detection which will kick you from Battle.net for five to ten minutes.

Questions
=========

Connection Problems
-------------------

Q: I get "The provided CD-key could not be decoded."

A: This error means that the key you provided was not valid enough to be decoded, or was completely empty. Maybe you forgot to fill it in?

Other Problems
--------------

Q: I want to use this plugin with another libpurple program, such as Finch, Adium, Empathy, Instantbird, Meebo, Myfavoritelibpurpleprogram, ...!

A: I have actually investigated many different programs that utilize libpurple, here's what I've found:

* Pidgin: The .so can be used as-is for Pidgin. The Windows installer is for Pidgin.
* Finch (Linux only): do the same you do for Pidgin on Linux! You don't need the protocol icons since Finch can't use them.
* Empathy (Linux only): do the same, but put the protocol icons somewhere else. Empathy does not support chats/channels, so Empathy is an awful UI for this plugin (most Battle.net users use channels).
* Adium (Mac OS X only): if someone tries it, tell me!
* Others: none that I know of at this time that will work.

    [1] https://github.com/nmbook/pidgin-libbnet/blob/master/COMPILE.md "Compiling from Source"
