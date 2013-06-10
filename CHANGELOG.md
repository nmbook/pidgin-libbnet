# Current functionality and changelog

#summary Changes made to this plugin since version 0.6.0.

Current functionality (0.9.0)
=============================
This lists the functions that are working. If you find an issue with anything, use the Issues section!

* Log in (STAR, SEXP, D2DV, D2XP, W2BN, WAR3, W3XP, SSHR, JSTR, DRTL, DSHR)
* Chat in Battle.net channels (appears as Chats)
* Whisper from and to anyone logged in to Battle.net on the current [gateway] (appears as IMs)
* Friend list support (uses buddy list)
* Away/DND states
* WarCraft III Clans
* User info and statistics (getting whois and getting profile and record, setting profile)
* Windows installer
* Hide automated friend messages (similar to "Your friend X has entered Battle.net" and "Your friend X entered a Diablo II game called Y"). This is a setting.

v0.9.0 "Clan Support, News Support, Legacy Support"
===================================================

* Added: Legacy Client Support (SSHR, JSTR, DRTL, DSHR). Restricted to public channels on official servers.
* Added: Ability to view Battle.net News & MOTD
* Added: WarCraft III Clan Support: accepting/declining clan invites and viewing/changing Clan MOTD (allowed to change only as Shaman/Chieftain of course)
* Fixed: 26-character invalid key bug on Linux (for real this time).
* Changed: Some code structure changes.

v0.8.0: "SRP Version & Bug Fixes"
=================================

* Added: Warcraft III local SRP support. Requires libgmp (included in installer). You won't send your passwords to BNLS ever again!
* Fixed: Non UTF-8 messages will not crash you.
* Fixed: A crash that occurs when connection was lost or you were unable to connect to BNLS.
* Fixed: CD-Key decoding issues.
* Fixed crash on friend remove/buddy remove
* Fixed: more issues than I can remember. Come on! Half of them were made months ago...
* Changed: Use bnls.net as default BNLS server.
* Updated the build system. I got around to actually writing my own Makefile that does everything you need for this small project... doesn't really affect users of the Windows installer though.

v0.7.2: "Unnamed Release"
=========================
* It should now be compilable without modification on Linux.
* Fixed a bug where the "hide mutual friend status-change messages" option didn't hide messages on other gateways.
* Updated CD-Key error code and added an informative message for ghosting. If you get "CD-key in use" with your own username, you will get a different error and Pidgin will automatically reconnect you as if you had a network connection error.
* Updated Windows installer.

v0.7.1: "Small Bugfix Release"
==============================
* Fixed: A couple possible crashes during logon if BNLS connection fails or you are IPBanned from Battle.net.
* Fixed: Now correctly reports NLS revision to BNLS servers. This fixes "incorrect password" when using a JBLS server for WarCraft III logon.

v0.7.0: "Installer and WarCraft III Release"
============================================
* Added: Warcraft III support.
* Added: Do not disturb mode is now correctly updated by your Pidgin status.
* Added: "User is away" warning and "User is unavailable" error on IM (whisper) are now correctly shown in the IM and not in the channel.
* Added: EID_ERRORs in channels now appear red instead of black.
* Added: "X is away (away message)" is now displayed as an auto-response! "X < AUTO-RESPONSE >: Away (away message)".
* Added: Warcraft III and Diablo channel user stats are now parsed.
* Fixed: From the room list window, if you click "Join Channel" you will crash.
* Fixed: Jailout's RBNETD (uswest.bnet.cc) will give you a blank username on logon.
* Fixed: 26-character keys will no longer IPBan you.
* Fixed: Certain new StarCraft keys will no longer IPBan you.
* Fixed: If you have a channel "persisted" or you are in it and Pidgin doesn't know and you reopen/"rejoin" it, the channel user list is emptied.
* Fixed: If you are in channel A with user X and you move to channel B then do Buddies > Get User Info... on that user X, their user information and stats will be shown as if they are in the current channel.
* Fixed: User ban, kick, and unban messages will now always appear in the channel and never in an IM.
* Fixed: Whisper commands open a new IM and show your sent whisper.

v0.6.0: "Public Release 1"
==========================
* This is the first release, so nothing "changed" since the last one.

I'm using the following lists to record what must be done, what should be done, and what might be done with this plugin. This is not a bug list, use the Issues section for that...

Definite To Do
==============
* Using message blocking (client side) and/or squelching (Battle.net feature) to do per-user filtering.
* WarCraft III Clan listing in buddy list
* WarCraft III User and clan game statistics
* Account creation and password changing
* Testing on Mac (Adium)
* Packages for Pidgin and Finch for Linux

Possible To Do
==============
* Chat queue
* Empathy
* icons.bni and MPQ reading (so that we can show users' icons)
* Local version checking (so that we do not need BNLS for version checking)
* Diablo II MCP (character logon)
* Game list reading
* Ladder reading (list of players currently high on the ladder, applies to Diablo II only at this time, used to apply to StarCraft)
