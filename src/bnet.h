/**
 * pidgin-libbnet
 * A Protocol Plugin for Pidgin, allowing emulation of a chat-only client
 * connected to the Battle.net Service.
 * Copyright (C) 2011-2012 Nate Book
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// PURPLE_PLUGINS
#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#ifndef _BNET_H_
#define _BNET_H_
 
// libraries
#include <glib.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// libpurple includes
#ifdef _WIN32
// Win/Mingw doesn't compile without this
#include "internal.h"
#else
// needed for getpeername call on non-Windows
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "circbuffer.h"
#include "connection.h"
#include "cmds.h"
#include "debug.h"
#include "network.h"
#include "notify.h"
#include "plugin.h"
#include "prpl.h"
#include "roomlist.h"
#include "request.h"
#include "version.h"

// includes
#include "bufferer.h"
#include "keydecode.h"
#include "sha1.h"
#include "srp.h"
#include "userdata.h"

// prpl data
#define PROTOCOL_NAME      "bnet"
#define PLUGIN_ID          "prpl-ribose-bnet"
#define PLUGIN_NAME        "Classic Battle.net"
#define PLUGIN_MAJOR_VER    1
#define PLUGIN_MINOR_VER    1
#define PLUGIN_MICRO_VER    0
#define PLUGIN_SHORT_DESCR "Classic Battle.net Protocol Plugin"
#define PLUGIN_DESCR       "Classic Battle.net Chat Server Protocol. Allows you to connect to classic Battle.net to chat with users on StarCraft, Diablo/II, and WarCraft II/III and their expansions."
#define PLUGIN_AUTHOR      "Nate Book <nmbook@gmail.com>"
#define PLUGIN_WEBSITE     "http://natembook.com/prpl/bnet"
#define QUOTE_(x)           #x
#define QUOTE(x)            QUOTE_(x)
#define PLUGIN_STR_VER      QUOTE(PLUGIN_MAJOR_VER.PLUGIN_MINOR_VER.PLUGIN_MICRO_VER)

// default setting values
#define BNET_DEFAULT_SERVER        "uswest.battle.net"
#define BNET_DEFAULT_PORT           6112
#define BNET_DEFAULT_BNLSSERVER    "bnls.net"
#define BNET_DEFAULT_BNLSPORT       9367
#define BNET_DEFAULT_GROUP_FRIENDS "Friends"
#define BNET_DEFAULT_GROUP_CLAN    "Clan %T members"

#define BNET_FILE_CACHE  "bnet-cache.xml"

// logon steps
#define BNET_STEP_COUNT      5
#define BNET_STEP_BNLS       0
#define BNET_STEP_CONNECTING 1
#define BNET_STEP_CREV       2
#define BNET_STEP_LOGON      3
#define BNET_STEP_FINAL      4

// chat message maximum size
#define BNET_MSG_MAXSIZE 225
#define BNET_EBADCHARS 0x0100

// status types
#define BNET_STATUS_ONLINE  "Online"
#define BNET_STATUS_AWAY    "Away"
#define BNET_STATUS_DND     "Do not disturb"
#define BNET_STATUS_OFFLINE "Offline"

// buffer size
#define BNET_INITIAL_BUFSIZE 2048

// protocol bytes
#define BNET_PROTOCOL_BNCS  0x01
#define BNET_PROTOCOL_MCP   0x01
#define BNET_PROTOCOL_BNFTP 0x02
#define BNET_PROTOCOL_CHAT  0x03

// bncs packet ids
typedef enum {
    BNET_SID_NULL                    = 0x00,
    BNET_SID_CLIENTID                = 0x05,
    BNET_SID_STARTVERSIONING         = 0x06,
    BNET_SID_REPORTVERSION           = 0x07,
    BNET_SID_ENTERCHAT               = 0x0A,
    BNET_SID_GETCHANNELLIST          = 0x0B,
    BNET_SID_JOINCHANNEL             = 0x0C,
    BNET_SID_CHATCOMMAND             = 0x0E,
    BNET_SID_CHATEVENT               = 0x0F,
    BNET_SID_LEAVECHAT               = 0x10,
    BNET_SID_LOCALEINFO              = 0x12,
    BNET_SID_FLOODDETECTED           = 0x13,
    BNET_SID_UDPPINGRESPONSE         = 0x14,
    BNET_SID_MESSAGEBOX              = 0x19,
    BNET_SID_LOGONCHALLENGEEX        = 0x1D,
    BNET_SID_CLIENTID2               = 0x1E,
    BNET_SID_PING                    = 0x25,
    BNET_SID_READUSERDATA            = 0x26,
    BNET_SID_WRITEUSERDATA           = 0x27,
    BNET_SID_LOGONCHALLENGE          = 0x28,
    BNET_SID_SYSTEMINFO              = 0x2B,
    BNET_SID_CDKEY                   = 0x30,
    BNET_SID_W3PROFILE               = 0x35,
    BNET_SID_CDKEY2                  = 0x36,
    BNET_SID_LOGONRESPONSE2          = 0x3A,
    BNET_SID_CREATEACCOUNT2          = 0x3D,
    BNET_SID_LOGONREALMEX            = 0x3E,
    BNET_SID_QUERYREALMS2            = 0x40,
    BNET_SID_W3GENERAL               = 0x44,
    BNET_SID_NETGAMEPORT             = 0x45,
    BNET_SID_NEWS_INFO               = 0x46,
    BNET_SID_OPTIONALWORK            = 0x4A,
    BNET_SID_REQUIREDWORK            = 0x4C,
    BNET_SID_AUTH_INFO               = 0x50,
    BNET_SID_AUTH_CHECK              = 0x51,
    BNET_SID_AUTH_ACCOUNTCREATE      = 0x52,
    BNET_SID_AUTH_ACCOUNTLOGON       = 0x53,
    BNET_SID_AUTH_ACCOUNTLOGONPROOF  = 0x54,
    BNET_SID_AUTH_ACCOUNTCHANGE      = 0x55,
    BNET_SID_AUTH_ACCOUNTCHANGEPROOF = 0x56,
    BNET_SID_SETEMAIL                = 0x59,
    BNET_SID_FRIENDSLIST             = 0x65,
    BNET_SID_FRIENDSUPDATE           = 0x66,
    BNET_SID_FRIENDSADD              = 0x67,
    BNET_SID_FRIENDSREMOVE           = 0x68,
    BNET_SID_FRIENDSPOSITION         = 0x69,
    BNET_SID_CLANFINDCANDIDATES      = 0x70,
    BNET_SID_CLANINVITEMULTIPLE      = 0x71,
    BNET_SID_CLANCREATIONINVITATION  = 0x72,
    BNET_SID_CLANDISBAND             = 0x73,
    BNET_SID_CLANMAKECHIEFTAIN       = 0x74,
    BNET_SID_CLANINFO                = 0x75,
    BNET_SID_CLANQUITNOTIFY          = 0x76,
    BNET_SID_CLANINVITATION          = 0x77,
    BNET_SID_CLANREMOVEMEMBER        = 0x78,
    BNET_SID_CLANINVITATIONRESPONSE  = 0x79,
    BNET_SID_CLANRANKCHANGE          = 0x7A,
    BNET_SID_CLANSETMOTD             = 0x7B,
    BNET_SID_CLANMOTD                = 0x7C,
    BNET_SID_CLANMEMBERLIST          = 0x7D,
    BNET_SID_CLANMEMBERREMOVED       = 0x7E,
    BNET_SID_CLANMEMBERSTATUSCHANGE  = 0x7F,
    BNET_SID_CLANMEMBERRANKCHANGE    = 0x81,
    BNET_SID_CLANMEMBERINFO          = 0x82,
} BnetPacketID;

// AUTH_INFO protocol id
#define BNET_PROTOCOL_ID 0

// architecture
typedef enum {
    BNET_PLATFORM_IX86 = 0x49583836,
    BNET_PLATFORM_PMAC = 0x504d4143,
    BNET_PLATFORM_XMAC = 0x584d4143,
} BnetPlatformID;

// language
typedef enum {
    BNET_PRODLANG_ENUS = 0x656e5553,
} BnetProductLanguage;

// udp
//'bnet'
#define BNET_UDP_SIG 0x626e6574

// game product id
typedef enum {
    BNET_PRODUCT_STAR = 0x53544152,
    BNET_PRODUCT_SEXP = 0x53455850,
    BNET_PRODUCT_W2BN = 0x5732424e,
    BNET_PRODUCT_D2DV = 0x44324456,
    BNET_PRODUCT_D2XP = 0x44325850,
    BNET_PRODUCT_JSTR = 0x4a535452,
    BNET_PRODUCT_WAR3 = 0x57415233,
    BNET_PRODUCT_W3XP = 0x57335850,
    BNET_PRODUCT_DRTL = 0x4452544c,
    BNET_PRODUCT_DSHR = 0x44534852,
    BNET_PRODUCT_SSHR = 0x53534852,
    BNET_PRODUCT_CHAT = 0x43484152,
    BNET_PRODUCT_W3DM = 0x5733444d,
} BnetProductID;

/* This is the DWORD-string tag type, as a 32-bit unsigned integer
 * Use bnet_tag_to_string and bnet_string_to_tag to convert between a string version */
typedef guint32 BnetDwordTag;

// versioning system to use
typedef enum {
    // SSHR, JSTR: SID_CLIENTID, SID_LOCALEINFO, SID_SYSTEMINFO, SID_STARTVERSIONING; SID_CDKEY
    BNET_VERSIONING_LEGACY  = 0x00,
    // DRTL, DSHR, W2BN: SID_CLIENTID2, SID_LOCALEINFO, SID_STARTVERSIONING; SID_CDKEY2
    BNET_VERSIONING_LEGACY2 = 0x01,
    // STAR, SEXP, D2DV, D2XP, W3DM, WAR3, W3XP: SID_AUTH_INFO; SID_AUTH_CHECK
    BNET_VERSIONING_AUTH    = 0x02,
} BnetVersioningSystem;

// account logon system to use
typedef enum {
// DRTL, DSHR, STAR, SEXP, SSHR, JSTR, W2BN, D2DV, D2XP: X-SHA-1 SID_LOGONRESPONSE/SID_LOGONRESPONSE2
    BNET_LOGON_XSHA1  = 0x00,
    // W3DM: SRP (NLS version 1)
    BNET_LOGON_SRPOLD = 0x01,
    // WAR3, W3XP: SRP (NLS version 2)
    BNET_LOGON_SRP    = 0x02,
} BnetLogonSystem;

// possible event numbers for telnet
// 10xx => CHATEVENT EIDs
#define BNET_TELNET_EID 1000
// 20xx => packet SIDs
#define BNET_TELNET_SID 2000
// 30xx
#define BNET_TELNET_XID 3000

// result codes
#define BNET_SUCCESS 0x0000

// AUTH_CHECK result codes
// matches any verbyte errors
#define BNET_AUTH_CHECK_VERCODEERROR_MASK   0x00FF
// matches any version check errors
#define BNET_AUTH_CHECK_VERERROR_MASK       0x0100
// matches any key check errors
#define BNET_AUTH_CHECK_KEYERROR_MASK       0x0200
// matches the specific error code for a error
#define BNET_AUTH_CHECK_ERROR_MASK          0x000F
// matches the key index in the error code
#define BNET_AUTH_CHECK_KEYNUMBER_MASK      0x00F0
// version check error: invalid version
#define BNET_AUTH_CHECK_VERERROR_INVALID    0x0001
// version check error: outdated version
#define BNET_AUTH_CHECK_VERERROR_OLD        0x0000
// version check error: downgrade
#define BNET_AUTH_CHECK_VERERROR_NEW        0x0002
// key check error: invalid key
#define BNET_AUTH_CHECK_KEYERROR_INVALID    0x0000
// key check error: key in use
#define BNET_AUTH_CHECK_KEYERROR_INUSE      0x0001
// key check error: banned key
#define BNET_AUTH_CHECK_KEYERROR_BANNED     0x0002
// key check error: key for different product
#define BNET_AUTH_CHECK_KEYERROR_BADPRODUCT 0x0003

// REPORTVERSION result codes
#define BNET_REPORTVERS_FAILED           0x00
#define BNET_REPORTVERS_OLD              0x01
#define BNET_REPORTVERS_SUCCESS          0x02
#define BNET_REPORTVERS_INVALID          0x03

// CDKEY result codes
#define BNET_CDKEY_SUCCESS               0x01
#define BNET_CDKEY_INVALID               0x02
#define BNET_CDKEY_BADPRODUCT            0x03
#define BNET_CDKEY_BANNED                0x04
#define BNET_CDKEY_INUSE                 0x05

// account result codes for SID_AUTH_ACCOUNT* packets)
#define BNET_AUTH_ACCOUNT_DNE            0x01
#define BNET_AUTH_ACCOUNT_BADPW          0x02
#define BNET_AUTH_ACCOUNT_EXISTS         0x04
#define BNET_AUTH_ACCOUNT_REQUPGRADE     0x05
#define BNET_AUTH_ACCOUNT_CLOSED         0x06
#define BNET_AUTH_ACCOUNT_SHORT          0x07
#define BNET_AUTH_ACCOUNT_BADCHAR        0x08
#define BNET_AUTH_ACCOUNT_BADWORD        0x09
#define BNET_AUTH_ACCOUNT_NOTENOUGHALPHA 0x0A
#define BNET_AUTH_ACCOUNT_ADJPUNCT       0x0B
#define BNET_AUTH_ACCOUNT_TOOMANYPUNCT   0x0C
#define BNET_AUTH_ACCOUNT_REQEMAIL       0x0E
#define BNET_AUTH_ACCOUNT_ERROR          0x0F

// account logon result codes for LOGONRESPONSE2 (match SID_AUTH_ACCOUNT* error codes)
#define BNET_LOGONRESP2_DNE              BNET_AUTH_ACCOUNT_DNE
#define BNET_LOGONRESP2_BADPW            BNET_AUTH_ACCOUNT_BADPW
#define BNET_LOGONRESP2_CLOSED           BNET_AUTH_ACCOUNT_CLOSED

// account create result codes for CREATEACCOUNT2
#define BNET_CREATEACC2_BADCHAR          0x02
#define BNET_CREATEACC2_BADWORD          0x03
#define BNET_CREATEACC2_EXISTS           0x04
#define BNET_CREATEACC2_NOTENOUGHALPHA   0x06

// this enum specifies choosable game types (for BNLS)
typedef enum {
    BNET_GAME_TYPE_STAR = 0x01,
    BNET_GAME_TYPE_SEXP = 0x02,
    BNET_GAME_TYPE_W2BN = 0x03,
    BNET_GAME_TYPE_D2DV = 0x04,
    BNET_GAME_TYPE_D2XP = 0x05,
    BNET_GAME_TYPE_JSTR = 0x06,
    BNET_GAME_TYPE_WAR3 = 0x07,
    BNET_GAME_TYPE_W3XP = 0x08,
    BNET_GAME_TYPE_DRTL = 0x09,
    BNET_GAME_TYPE_DSHR = 0x0A,
    BNET_GAME_TYPE_SSHR = 0x0B,
} BnetGameType;

// bnls packet ids
typedef enum {
    BNET_BNLS_REQUESTVERSIONBYTE = 0x10,
    BNET_BNLS_VERSIONCHECKEX2    = 0x1A,
    BNET_BNLS_LOGONCHALLENGE     = 0x02,
    BNET_BNLS_LOGONPROOF         = 0x03,
    BNET_BNLS_CHOOSENLSREVISION  = 0x0D,
    BNET_BNLS_MESSAGE            = 0xFF
} BnetBnlsPacketID;

// flags for SID_JOINCHANNEL
typedef enum {
    BNET_CHANNELJOIN_NOCREATE   = 0x00000000,
    BNET_CHANNELJOIN_FIRSTJOIN  = 0x00000001,
    BNET_CHANNELJOIN_FORCEDJOIN = 0x00000002,
    BNET_CHANNELJOIN_D2FIRST    = 0x00000004,
} BnetChannelJoinFlags;

// event types (SID_CHATEVENT or telnet lines)
typedef enum {
    BNET_EID_SHOWUSER            = 0x00000001,
    BNET_EID_JOIN                = 0x00000002,
    BNET_EID_LEAVE               = 0x00000003,
    BNET_EID_WHISPER             = 0x00000004,
    BNET_EID_TALK                = 0x00000005,
    BNET_EID_BROADCAST           = 0x00000006,
    BNET_EID_CHANNEL             = 0x00000007,
    BNET_EID_USERFLAGS           = 0x00000009,
    BNET_EID_WHISPERSENT         = 0x0000000A,
    BNET_EID_CHANNELFULL         = 0x0000000D,
    BNET_EID_CHANNELDOESNOTEXIST = 0x0000000E,
    BNET_EID_CHANNELRESTRICTED   = 0x0000000F,
    BNET_EID_INFO                = 0x00000012,
    BNET_EID_ERROR               = 0x00000013,
    BNET_EID_INFO_PARSED         = 0x00000014,
    BNET_EID_ERROR_PARSED        = 0x00000015,
    BNET_EID_EMOTE               = 0x00000017
} BnetChatEventID;

// user flags & channel flags (SID_CHATEVENT or telnet lines)
typedef enum {
    BNET_USER_FLAG_NONE      = 0x00000000,
    BNET_USER_FLAG_BLIZZREP  = 0x00000001,
    BNET_USER_FLAG_OP        = 0x00000002,
    BNET_USER_FLAG_VOICE     = 0x00000004,
    BNET_USER_FLAG_BNETADMIN = 0x00000008,
    BNET_USER_FLAG_NOUDP     = 0x00000010,
    BNET_USER_FLAG_SQUELCH   = 0x00000020,
    BNET_USER_FLAG_GUEST     = 0x00000040,
    BNET_USER_FLAG_BEEP      = 0x00000100,
    
    BNET_CHAN_FLAG_NONE      = 0x00000000,
    BNET_CHAN_FLAG_PUBLIC    = 0x00000001,
    BNET_CHAN_FLAG_MODERATED = 0x00000002,
    BNET_CHAN_FLAG_RESTRICT  = 0x00000004,
    BNET_CHAN_FLAG_SILENT    = 0x00000008,
    BNET_CHAN_FLAG_SYSTEM    = 0x00000010,
    BNET_CHAN_FLAG_PRODUCT   = 0x00000020,
    BNET_CHAN_FLAG_GLOBAL    = 0x00001000,
    BNET_CHAN_FLAG_REDIRECT  = 0x00004000,
    BNET_CHAN_FLAG_CHAT      = 0x00008000,
    BNET_CHAN_FLAG_TECHSPPT  = 0x00010000
} BnetChatEventFlags;

typedef struct {
    guint64 timestamp;
    guint32 id;
    guint32 flags;
    guint32 ping;
    gchar *name;
    gchar *text;
} BnetDelayedEvent;

/* How to show an EID_INFO message */
typedef enum {
    /* hide this EID_INFO */
    SHOW_NEVER        = 0,
    /* try to show in current context as the response to a command */
    SHOW_AS_RESPONSE  = 1,
    /* always show in the current channel (kick, ban, and other non-commnd response messages) */
    SHOW_IN_CHAT_ONLY = 2,
} BnetEventShowMode;

typedef enum {
    BNET_USER_TYPE_CHANNELUSER = 0x01,
    BNET_USER_TYPE_FRIEND      = 0x02,
    BNET_USER_TYPE_CLANMEMBER  = 0x04,
} BnetUserType;

typedef struct {
    gchar *key;
    gchar *value;
    gchar *short_value;
    gboolean full_view;
} BnetStatsDataItem;


// the "abstract" Battle.net user type
// All possible buddy list entries are one of
// the three types of this:
// BnetChannelUser: users in the current channel
// BnetFriendInfo: users in your Battle.net friend list
// BnetClanMember: users in your WarCraft III clan
typedef struct {
    BnetUserType type;
    gchar *username;
    gchar data[48];
} BnetUser;

typedef struct {
    BnetUserType type;
    char *username;
    char *stats_data;
    BnetChatEventFlags flags;
    gint32 ping;
    gboolean hidden;
    
    char *stats_message;

    gboolean filter_wait_callback;
    gboolean left_channel;
} BnetChannelUser;

// friend status flags
typedef enum {
    BNET_FRIEND_STATUS_ONLINE = 0x00,
    BNET_FRIEND_STATUS_MUTUAL = 0x01,
    BNET_FRIEND_STATUS_DND    = 0x02,
    BNET_FRIEND_STATUS_AWAY   = 0x04
} BnetFriendStatus;

// friend location types
typedef enum {
    BNET_FRIEND_LOCATION_OFFLINE        = 0x00,
    BNET_FRIEND_LOCATION_ONLINE         = 0x01,
    BNET_FRIEND_LOCATION_CHANNEL        = 0x02,
    BNET_FRIEND_LOCATION_GAME_PUBLIC    = 0x03,
    BNET_FRIEND_LOCATION_GAME_PRIVATE   = 0x04,
    BNET_FRIEND_LOCATION_GAME_PROTECTED = 0x05
} BnetFriendLocation;



typedef struct {
    BnetUserType type;
    // account name from friend list
    char *account;
    // information directly from friend list
    BnetFriendStatus status;
    BnetFriendLocation location;
    BnetProductID product;
    char *location_name;

    // whether we are waiting for a /whois on this user
    // for the friend list
    BnetFriendStatus automated_lookup;
    // from /whois (if available)
    // when a whois returns "away" or "dnd" message
    gchar *dnd_stored_status;
    gchar *away_stored_status;
    // whether this account is on the Battle.net friend list
    gboolean on_list;
    
    // prpl buddy object
    PurpleBuddy *buddy;
} BnetFriendInfo;

/*
typedef struct {
    PurpleConversation *conv;
    BnetCommandID cmd;
    BnetPacketID pkt_id;
    BnetPacket *pkt;
    BnetPacketID pkt_response;
    int cookie;
    BnetQueueFunc cb;
    gboolean responded;
    int delay;
} BnetQueueElement;
*/

typedef enum {
    BNET_CLAN_RANK_INITIATE  = 0,
    BNET_CLAN_RANK_PEON      = 1,
    BNET_CLAN_RANK_GRUNT     = 2,
    BNET_CLAN_RANK_SHAMAN    = 3,
    BNET_CLAN_RANK_CHIEFTAIN = 4,
} BnetClanMemberRank;

typedef enum {
    BNET_CLAN_STATUS_OFFLINE = 0,
    BNET_CLAN_STATUS_ONLINE  = 1,
} BnetClanMemberStatus;

typedef struct {
    // type = 
    BnetUserType type;
    gchar *name;
    BnetClanMemberRank rank;
    BnetClanMemberStatus status;
    gchar *location;

    guint64 join_date;
} BnetClanMember;

typedef BnetDwordTag BnetClanTag;

typedef enum {
    BNET_CLAN_RESPONSE_SUCCESS          = 0x00,
    BNET_CLAN_RESPONSE_NAMEINUSE        = 0x01,
    BNET_CLAN_RESPONSE_TOOSOON          = 0x02,
    BNET_CLAN_RESPONSE_NOTENOUGHMEMBERS = 0x03,
    BNET_CLAN_RESPONSE_DECLINE          = 0x04,
    BNET_CLAN_RESPONSE_UNAVAILABLE      = 0x05,
    BNET_CLAN_RESPONSE_ACCEPT           = 0x06,
    BNET_CLAN_RESPONSE_NOTAUTHORIZED    = 0x07,
    BNET_CLAN_RESPONSE_NOTALLOWED       = 0x08,
    BNET_CLAN_RESPONSE_FULL             = 0x09,
    BNET_CLAN_RESPONSE_BADTAG           = 0x0a,
    BNET_CLAN_RESPONSE_BADNAME          = 0x0b,
    BNET_CLAN_RESPONSE_USERNOTFOUND     = 0x0c,
} BnetClanResponseCode;

typedef enum {
    BNET_REALM_SUCCESS           = 0x00,
    
    BNET_REALM_LOGON_UNAVAIL     = 0x80000001,
    BNET_REALM_LOGON_BADPW       = 0x80000002,
    
    // game available
    BNET_REALM_GLIST_AVAIL       = 0x04,
    // game server down
    BNET_REALM_GLIST_UNAVAIL     = 0xFFFFFFFF,
    
    // create failed: already exists
    BNET_REALM_CHAR_EXISTS       = 0x14,
    // create failed: bad character name
    BNET_REALM_CHAR_BADNAME      = 0x15,
    // logon failed: player does not exist
    BNET_REALM_CHAR_PDNE         = 0x46,
    // delete failed: char does not exist
    BNET_REALM_CHARDEL_DNE       = 0x49,
    // logon failed/upgrade failed
    BNET_REALM_CHAR_FAILED       = 0x7A,
    // logon failed/upgrade failed: char expired
    BNET_REALM_CHAR_EXPIRED      = 0x7B,
    // upgrade failed: already expansion
    BNET_REALM_CHARUP_ALREADY    = 0x7C,
    
    // create failed: bad name
    BNET_REALM_GAME_BADNAME      = 0x1E,
    // create failed: exists
    BNET_REALM_GAME_EXISTS       = 0x1F,
    // game server down
    BNET_REALM_GAME_UNAVAIL      = 0x20,
    // join failed: bad pw
    BNET_REALM_GAME_BADPW        = 0x29,
    // join failed: does not exist
    BNET_REALM_GAME_DNE          = 0x2A,
    // join failed: game full
    BNET_REALM_GAME_FULL         = 0x2B,
    // join failed: failed level reqs
    BNET_REALM_GAME_LEVEL        = 0x2C,
    // join failed: your hc char is dead
    BNET_REALM_GAME_DEADHC       = 0x6E,
    // join failed: a non-hardcare char cannot join a hardcore game
    BNET_REALM_GAME_NOTHC        = 0x71,
    // join failed: nightmare not available
    BNET_REALM_GAME_NOTNM        = 0x73,
    // join failed: hell not available
    BNET_REALM_GAME_NOTHELL      = 0x74,
    // join failed: a non-exp char cannot join a exp game
    BNET_REALM_GAME_NOTXP        = 0x78,
    // join failed: a exp char cannot join a non-exp game
    BNET_REALM_GAME_NOTDV        = 0x79,
    // join failed: a non-ladder char cannot join a ladder game
    BNET_REALM_GAME_NOTL         = 0x7D,
    
    // no bncs connection detected (2)
    BNET_REALM_CONNECT_NOBNCS2   = 0x02,
    // no bncs connection detected (10)
    BNET_REALM_CONNECT_NOBNCS10  = 0x0A,
    // no bncs connection detected (11)
    BNET_REALM_CONNECT_NOBNCS11  = 0x0B,
    // no bncs connection detected (12)
    BNET_REALM_CONNECT_NOBNCS12  = 0x0C,
    // no bncs connection detected (13)
    BNET_REALM_CONNECT_NOBNCS13  = 0x0D,
    // key is banned
    BNET_REALM_CONNECT_KEYBAN    = 0x7E,
    // temporarily banned
    BNET_REALM_CONNECT_TEMPBAN   = 0x7F,
} BnetRealmStatus;

// bnls packet ids
typedef enum {
    BNET_D2MCP_STARTUP = 0x01,
    BNET_D2MCP_CHARLOGON = 0x07,
    BNET_D2MCP_MOTD = 0x12,
    BNET_D2MCP_CHARLIST2 = 0x19,
} BnetD2RealmPacketID;

typedef struct {
    guint32 up;
    gchar *name;
    gchar *descr;
} BnetD2RealmServer;

typedef struct {
    guint32 expires;
    gchar *name;
    gchar *stats;
} BnetD2RealmCharacter;

typedef enum {
    BNET_WID_USERRECORD = 0x04,
    BNET_WID_CLANRECORD = 0x08,
} BnetW3GeneralSubcommand;

typedef enum {
    BNET_W3RECORD_USER_SOLO = 0x534f4c4f,
    BNET_W3RECORD_USER_TEAM = 0x5445414d,
    BNET_W3RECORD_USER_FFA  = 0x46464120,
    BNET_W3RECORD_RACE_ORC  = 0x00000001,
    BNET_W3RECORD_RACE_HUMA = 0x00000002,
    BNET_W3RECORD_RACE_SCOU = 0x00000003,
    BNET_W3RECORD_RACE_NELF = 0x00000004,
    BNET_W3RECORD_RACE_RAND = 0x00000000,
    BNET_W3RECORD_RACE_TRNA = 0x00000005,
    BNET_W3RECORD_TEAM_2VS2 = 0x32565332,
    BNET_W3RECORD_TEAM_3VS3 = 0x33565333,
    BNET_W3RECORD_TEAM_4VS4 = 0x34565534,
    BNET_W3RECORD_CLAN_SOLO = 0x434c4e53,
    BNET_W3RECORD_CLAN_2VS2 = 0x434c4e32,
    BNET_W3RECORD_CLAN_3VS3 = 0x434c4e33,
    BNET_W3RECORD_CLAN_4VS4 = 0x434c4e34,
} BnetW3RecordType;

typedef enum {
    // not waiting for anything
    BNET_LOOKUP_INFO_NONE                      = 0x00000000,
    // the user closed the lookup dialog: don't notify anymore
    BNET_LOOKUP_INFO_CANCELLED                 = 0x00000001,
    // waiting for channel list (NOT USED -- this is already stored)
    //BNET_LOOKUP_INFO_AWAIT_CHANNEL_LIST        = 0x00000010,
    // waiting for friends list (NOT USED -- this is already stored)
    //BNET_LOOKUP_INFO_AWAIT_FRIENDS_LIST        = 0x00000020,
    // waiting for WarCraft III clan list (NOT USED -- this is already stored)
    //BNET_LOOKUP_INFO_AWAIT_W3_CLAN_LIST        = 0x00000040,
    // waiting for possible /whois statuses responses (away and dnd)
    BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES_AWAY = 0x00000100,
    BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES_DND  = 0x00000200,
    // both of the above
    BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES      = 0x00000300,
    // waiting for /whois request (returns EID_INFO)
    BNET_LOOKUP_INFO_AWAIT_WHOIS               = 0x00000400,
    // waiting for SID_READUSERDATA request
    BNET_LOOKUP_INFO_AWAIT_USER_DATA           = 0x00000800,
    // waiting for SID_W3PROFILE request
    BNET_LOOKUP_INFO_AWAIT_W3_USER_PROFILE     = 0x00001000,
    // waiting for SID_WARCRAFTGENERAL.WID_USERRECORD request
    BNET_LOOKUP_INFO_AWAIT_W3_USER_STATS       = 0x00002000,
    // waiting for SID_WARCRAFTGENERAL.WID_CLANRECORD request
    BNET_LOOKUP_INFO_AWAIT_W3_CLAN_STATS       = 0x00004000,
    // waiting for SID_CLANMEMBERINFO request
    BNET_LOOKUP_INFO_AWAIT_W3_CLAN_MI          = 0x00008000,
    // matches all BNET_LOOKUP_INFO_AWAIT_* flags
    BNET_LOOKUP_INFO_AWAIT_MASK                = 0x0000fff0,
    // 1=we have not shown the first section, 0=it has been shown, put a line break
    BNET_LOOKUP_INFO_FIRST_SECTION             = 0x00010000,
    // whether we have found a suitable location/product pair from the channel, friends, or clan list
    BNET_LOOKUP_INFO_FOUND_LOCPROD             = 0x00100000,
    // whether we have found a suitable clan tag (or proof they aren't in a clan) from the channel, friends, or clan list
    BNET_LOOKUP_INFO_FOUND_W3_TAG              = 0x00200000,
} BnetLookupInfoFlags;

typedef struct {
    guint32 timestamp;
    gchar *message;
} BnetNewsItem;

typedef struct {
    gchar *name;
    gchar *subname;
    gchar *message;
} BnetMotdItem;

struct BnetPacketCookieKey {
    guint8 packet_id;
    guint32 cookie;
};

// these are used in the "Get News Info" dialog to classify BnetNewsItems.
// motd sent by the BNCS in response to SID_NEWS_INFO, with timestamp 0 (name = gateway)
#define BNET_MOTD_TYPE_BNCS     0
// any messages sent in BNLS_MESSAGE (aka BNLS_IPBAN) (name = address)
#define BNET_MOTD_TYPE_BNLS     1
// motd set by D2MCP_GETMOTD (name = realm name)
#define BNET_MOTD_TYPE_D2MCP    2
// motd set by SID_CLANMOTD (name = "Clan tag: name")
#define BNET_MOTD_TYPE_CLAN     3
// information of upcoming tournament, sent by SID_TOURNAMENT (not implemented) (name = tournament name)
#define BNET_MOTD_TYPE_WCG_T    4
// information of upcoming tournament, sent by SID_W3GENERAL.WID_TOURNAMENT (name = tournament name)
#define BNET_MOTD_TYPE_W3_T     5
#define BNET_MOTD_TYPES         6

// userdata request
#define BNET_USERDATA_PROFILE_REQUEST "profile\\sex\nprofile\\age\nprofile\\location\nprofile\\description"
#define BNET_USERDATA_RECORD_REQUEST(prod, num) "Record\\%s\\%d\\wins\nRecord\\%s\\%d\\losses\nRecord\\%s\\%d\\disconnects\nRecord\\%s\\%d\\last game\nRecord\\%s\\%d\\last game result", (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num)
#define BNET_USERDATA_RECORD_LADDER_REQUEST(prod, num) "Record\\%s\\%d\\wins\nRecord\\%s\\%d\\losses\nRecord\\%s\\%d\\disconnects\nRecord\\%s\\%d\\last game\nRecord\\%s\\%d\\last game result\nRecord\\%s\\%d\\rating\nRecord\\%s\\%d\\high rating\nDynKey\\%s\\%d\\rank\nRecord\\%s\\%d\\high rank", (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num)
#define BNET_USERDATA_SYSTEM_REQUEST "System\\Account Created\nSystem\\Last Logoff\nSystem\\Last Logon\nSystem\\Time Logged\nSystem\\Account Expires\n"
#define BNET_USERDATA_RECORD_NORMAL  0
#define BNET_USERDATA_RECORD_LADDER  1
#define BNET_USERDATA_RECORD_IRONMAN 3
#define BNET_RECORD_NONE    0
#define BNET_RECORD_NORMAL  1
#define BNET_RECORD_LADDER  2
#define BNET_RECORD_IRONMAN 8

typedef enum {
    BNET_READUSERDATA_REQUEST_NONE    = 0x0,
    BNET_READUSERDATA_REQUEST_PROFILE = 0x1,
    BNET_READUSERDATA_REQUEST_RECORD  = 0x2,
    BNET_READUSERDATA_REQUEST_SYSTEM  = 0x4
} BnetUserDataRequestType;

typedef struct _BnetUserDataRequest BnetUserDataRequest;

// stores socket connection data for a specific socket
struct SocketData {
    // file descriptor
    int fd;
    // input watcher
    int prpl_input_watcher;
    // inbound buffer
	gchar *inbuf;
    // inbound buffer length
    guint16 inbuf_length;
    // inbound buffer used
    guint16 inbuf_used;
    // the connection data for this connect
    PurpleProxyConnectData *prpl_conn_data;
    // the server address (host name)
    gchar *server;
    // the server port
    guint16 port;
};

// this struct stores extra info for a battle.net connection
typedef struct {
    int magic;
    /* The libpurple account */
    PurpleAccount *account;

    /* BNCS (Battle.net Chat Server) state */
    struct {
        /* Generic connection data */
        struct SocketData conn;

        /* Versioning/product state */
        struct {
            BnetVersioningSystem type;
            gboolean complete;
            BnetProductID product;
            guint32 version_code;
            BnetGameType game_type;
            gchar *key_owner;
        } versioning;
        
        /* Account logon state */
        struct {
            BnetLogonSystem type;
            gboolean create_account;
            guint32 client_cookie;
            guint32 server_cookie;
            guint32 session_cookie;
            gchar *username;
            srp_t *auth_ctx;
            srp_t *auth_ctx_pending;
            guint lockout_timer_handle;
            PurpleRequestFields *prpl_setemail_fields_handle;
        } logon;
        
        /* Chat environment state */
        struct {
            gboolean is_online;
            gboolean sent_enter_channel;
            gboolean first_join;
            gchar *unique_name;
            gchar *stats;
            const gchar *d2_star;
            guint updatelist_timer_tick;
            guint updatelist_timer_handle;
            //BnetQueeu *queue
            GList *channel_list;
            PurpleRoomlist *prpl_room_list_handle;
            PurpleConversation *prpl_last_cmd_conv_handle;
            GHashTable *packet_cookie_table;
        } chat_env;

        /* MOTDs */
        BnetMotdItem motds[BNET_MOTD_TYPES];

        /* Battle.net news */
        struct {
            guint32 latest;
            guint32 item_count;
            GList *item_list;
        } news;

        /* Current channel state */
        struct {
            gboolean seen_self;
            gboolean got_motd;
            gchar *name_pending;
            gchar *name;
            BnetChatEventFlags flags;
            GList *user_list;
            GQueue *delayed_event_queue;
            int prpl_chat_id;
            guint join_timer_handle;
        } channel;

        /* Whisper state */
        struct {
            gchar *last_sent_to;
            gboolean awaiting_confirm;
        } whisper;

        /* Friends list state */
        struct {
            GList *list;
        } friends;

        /* My status state */
        struct {
            BnetFriendStatus status;
            BnetFriendStatus status_pending;
            gchar *away_msg;
            gchar *dnd_msg;
        } status;

        /* User lookup ("Get User Info") state */
        struct {
            gchar *name;
            BnetLookupInfoFlags flags;
            BnetClanTag w3_tag;
            PurpleNotifyUserInfo *prpl_notify_handle;
        } lookup_info;

        /* SID_GETUSERDATA state */
        struct {
            gboolean writing_profile;
            GList *requests;
            PurpleRequestFields *prpl_profile_fields_handle;
        } user_data;
        
        /* Warcraft III clan state */
        struct {
            gboolean in_clan;
            gboolean clan_members_in_blist;
            BnetClanTag my_clantag;
            gchar *my_clanname;
            GList *my_clanmembers;
            BnetClanMemberRank my_rank;
            PurpleRequestFields *prpl_setmotd_fields_handle;
        } w3_clan;
    } bncs;

    /* BNLS (Battle.net Logon Server) state */
    struct {
        /* Generic connection data */
        struct SocketData conn;
    } bnls;

    /* D2MCP (Battle.net D2 Character Realm/Master Control Protocol) state */
    struct {
        /* Generic connection data */
        struct SocketData conn;
        
        /* Data to log on to realm server */
        guint32 logon_data[16];

        /* Currently connected realm */
        BnetD2RealmServer realm;

        /* Currently logged on character */
        BnetD2RealmCharacter character;

        /* Whether we are logged on to a character */
        gboolean on_character;

        /* Handle for D2 realm list */
        PurpleRequestFields *prpl_realmlist_fields_handle;
        /* Handle for D2 character list */
        PurpleRequestFields *prpl_charlist_fields_handle;
    } d2mcp;
} BnetConnectionData;

typedef struct {
    BnetConnectionData *bnet;
    BnetPacketID packet_id;
    gint32 cookie;
    BnetClanTag clan_tag;
    gchar *inviter;
    gchar *clan_name;
} BnetClanInvitationCallbackData;

typedef struct {
    BnetConnectionData *bnet;
    BnetChannelUser *bcu;
} BnetFilterJoinDelayCallback;

typedef enum {
    BNET_CMD_NONE = 0,
    BNET_CMD_AWAY,
    BNET_CMD_BAN,
    BNET_CMD_BEEP,
    BNET_CMD_CLAN,
    BNET_CMD_DESIGNATE,
    BNET_CMD_DND,
    BNET_CMD_EMOTE,
    BNET_CMD_FRIENDS,
    BNET_CMD_HELP,
    BNET_CMD_JOIN,
    BNET_CMD_KICK,
    BNET_CMD_MAIL,
    BNET_CMD_NOBEEP,
    BNET_CMD_OPTIONS,
    BNET_CMD_REJOIN,
    BNET_CMD_SQUELCH,
    BNET_CMD_STATS,
    BNET_CMD_TIME,
    BNET_CMD_UNBAN,
    BNET_CMD_UNSQUELCH,
    BNET_CMD_USERS,
    BNET_CMD_WHISPER,
    BNET_CMD_WHO,
    BNET_CMD_WHOIS,
    BNET_CMD_WHOAMI,
} BnetCommandID;

typedef enum {
    // this command will fall through to libpurple's command
    BNET_CMD_FLAG_PRPLCONTINUE = 0x1,
    // this command only works on a channel
    // in a whisper, it will be sent to the user instead
    BNET_CMD_FLAG_WHISPERPRPLCONTINUE = 0x2,
    // this command is of the format /cmd user[ other args]
    // and should become /cmd *user[ other args] on D2.
    BNET_CMD_FLAG_STAROND2 = 0x4,
    // this command has an EID_INFO response
    BNET_CMD_FLAG_INFORESPONSE = 0x8,
    // this command is not forwarded to Battle.net
    BNET_CMD_FLAG_PRPL = 0x10,
} BnetCommandFlag;

struct BnetCommand {
    BnetCommandID id;
    BnetCommandFlag bnetflags;
    char *name;
    char *args;
    char *helptext;
} bnet_cmds[] = {
    { BNET_CMD_HELP, BNET_CMD_FLAG_PRPLCONTINUE | BNET_CMD_FLAG_INFORESPONSE, "help", "s",
            "help [topic]:  Request help from Battle.net on the specified topic." },
    { BNET_CMD_HELP, BNET_CMD_FLAG_INFORESPONSE, "?", "s",
            "? [topic]:  Request help from Battle.net on the specified topic." },
    { BNET_CMD_AWAY, BNET_CMD_FLAG_INFORESPONSE, "away", "s",
            "away [message]:  Set your away status to message (clear your away status by providing no message)." },
    { BNET_CMD_DND, BNET_CMD_FLAG_INFORESPONSE, "dnd", "s",
            "dnd [message]:  Set your do-not-disturb status to message (clear your do-not-disturb status by providing no message). You cannot recieve messages in this state." },
    { BNET_CMD_JOIN, 0, "channel", "s", 
            "channel &lt;channel&gt;:  Join the specified channel." },
    { BNET_CMD_JOIN, 0, "join", "s",
            "join &lt;channel&gt;:  Join the specified channel." },
    { BNET_CMD_JOIN, 0, "j", "s",
            "j &lt;channel&gt;:  Join the specified channel." },
    { BNET_CMD_EMOTE, BNET_CMD_FLAG_WHISPERPRPLCONTINUE, "emote", "s",
            "emote &lt;action&gt;:  Send an IRC style action to a chat." },
    { BNET_CMD_EMOTE, BNET_CMD_FLAG_WHISPERPRPLCONTINUE, "me", "s",
            "me &lt;action&gt;:  Send an IRC style action to a chat." },
    { BNET_CMD_FRIENDS, BNET_CMD_FLAG_INFORESPONSE, "friends", "ws",
            "friends &lt;action&gt; [options]:  Perform a friends-list action (list, add &lt;user&gt;, remove &lt;user&gt;, msg &lt;message&gt;, promote &lt;user&gt;, demote &lt;user&gt;)." },
    { BNET_CMD_FRIENDS, BNET_CMD_FLAG_INFORESPONSE, "f", "ws",
            "f &lt;action&gt; [options]:  Perform a friends-list action (list, add &lt;user&gt;, remove &lt;user&gt;, msg &lt;message&gt;, promote &lt;user&gt;, demote &lt;user&gt;)." },
    { BNET_CMD_OPTIONS, BNET_CMD_FLAG_INFORESPONSE, "options", "w",
            "options &lt;option&gt;:  Change a messaging setting." },
    { BNET_CMD_OPTIONS, BNET_CMD_FLAG_INFORESPONSE, "o", "w",
            "o &lt;option&gt;:  Change a messaging setting." },
    { BNET_CMD_SQUELCH, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "squelch", "w",
            "squelch &lt;user&gt;:  Block messages from the specified user." },
    { BNET_CMD_SQUELCH, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "ignore", "w",
            "ignore &lt;user&gt;:  Block messages from the specified user." },
    { BNET_CMD_UNSQUELCH, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "unsquelch", "w",
            "unsquelch &lt;user&gt;:  Unblock messages from the specified user." },
    { BNET_CMD_UNSQUELCH, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "unignore", "w",
            "unignore &lt;user&gt;:  Unblock messages from the specified user." },
    { BNET_CMD_WHISPER, BNET_CMD_FLAG_STAROND2, "whisper", "ws",
            "whisper &lt;user&gt; &lt;message&gt;:  Send a private message, aka a whisper." },
    { BNET_CMD_WHISPER, BNET_CMD_FLAG_STAROND2, "w", "ws",
            "w &lt;user&gt; &lt;message&gt;:  Send a private message, aka a whisper." },
    { BNET_CMD_WHISPER, BNET_CMD_FLAG_STAROND2, "msg", "ws",
            "msg &lt;user&gt; &lt;message&gt;:  Send a private message, aka a whisper." },
    { BNET_CMD_WHISPER, BNET_CMD_FLAG_STAROND2, "m", "ws",
            "m &lt;user&gt; &lt;message&gt;:  Send a private message, aka a whisper." },
    { BNET_CMD_WHO, BNET_CMD_FLAG_INFORESPONSE, "who", "s",
            "who &lt;channel&gt;:  Display the list of users in a channel." },
    { BNET_CMD_WHOIS, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "whois", "w",
            "whois &lt;user&gt;:  Display where a user is on Battle.net." },
    { BNET_CMD_WHOIS, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "whereis", "w",
            "whereis &lt;user&gt;:  Display where a user is on Battle.net." },
    { BNET_CMD_WHOIS, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "where", "w",
            "where &lt;user&gt;:  Display where a user is on Battle.net." },
    { BNET_CMD_WHOAMI, BNET_CMD_FLAG_INFORESPONSE, "whoami", "",
            "whoami:  Displays where you are on Battle.net." },
    { BNET_CMD_BAN, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "ban", "ws", 
            "ban &lt;user&gt; &lt;message&gt;: Remove a user from the channel, and prevent him/her from returning." },
    { BNET_CMD_UNBAN, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "unban", "w", 
            "unban &lt;user&gt;: Allow a banned user to return." },
    { BNET_CMD_KICK, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "kick", "ws", 
            "kick &lt;user&gt; &lt;message&gt;: Remove a user from the channel." },
    { BNET_CMD_DESIGNATE, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "designate", "w", 
            "designate &lt;user&gt;:  Select the specified user to be your \"heir\", where when you lose operator status, he/she will get it automatically." },
    { BNET_CMD_REJOIN, 0, "rejoin", "", 
            "rejoin:  Resign your operator status (Warcraft III clan officers will regain it immediately after)." },
    { BNET_CMD_REJOIN, 0, "resign", "", 
            "resign:  Resign your operator status (Warcraft III clan officers will regain it immediately after)." },
    { BNET_CMD_CLAN, BNET_CMD_FLAG_INFORESPONSE, "clan", "ws",
            "clan &lt;action&gt; [options]:  Perform a Warcraft III clan action (public, private, mail <message>, motd <message>)." },
    { BNET_CMD_CLAN, BNET_CMD_FLAG_INFORESPONSE, "c", "ws",
            "c &lt;action&gt; [options]:  Perform a Warcraft III clan action (public, private, mail <message>, motd <message>)." },
    { BNET_CMD_TIME, BNET_CMD_FLAG_INFORESPONSE, "time", "", 
            "time:  Display the Battle.net and local time." },
    { BNET_CMD_USERS, BNET_CMD_FLAG_PRPLCONTINUE | BNET_CMD_FLAG_INFORESPONSE, "users", "", 
            "users:  Display the number of users on Battle.net." },
    { BNET_CMD_STATS, BNET_CMD_FLAG_INFORESPONSE, "stats", "ww",
            "stats &lt;user&gt; [product]:  Display a user's game statistics, with an optionally specified product code." },
    { BNET_CMD_STATS, BNET_CMD_FLAG_INFORESPONSE, "astat", "ww",
            "astat &lt;user&gt; [product]:  Display a user's game statistics, with an optionally specified product code." },
    { BNET_CMD_MAIL, BNET_CMD_FLAG_STAROND2 | BNET_CMD_FLAG_INFORESPONSE, "mail", "ws",
            "mail &lt;user&gt; &lt;message&gt;:  Send a message to the specified user's e-mail. They will not receive it unless they want to." },
    { BNET_CMD_BEEP, BNET_CMD_FLAG_INFORESPONSE, "beep", "", 
            "beep:  (no text-bots exist anymore) Enable beep characters for text bots." },
    { BNET_CMD_NOBEEP, BNET_CMD_FLAG_INFORESPONSE, "nobeep", "", 
            "nobeep:  (no text-bots exist anymore) Disable beep characters for text bots." },
    { 0, 0, NULL, NULL, NULL }
};

static void bnet_channel_user_free(BnetChannelUser *bcu);
static void bnet_friend_info_free(BnetFriendInfo *bfi);
static void bnet_user_free(BnetUser *bu);
static void bnet_buddy_free(PurpleBuddy *buddy);
static void bnet_news_item_free(BnetNewsItem *item);
static void bnet_connect(PurpleAccount *account, const gboolean do_register);
static void bnet_login(PurpleAccount *account);
static void bnet_bnls_login_cb(gpointer data, gint source, const gchar *error_message);
static int  bnet_bnls_send_LOGONCHALLENGE(const BnetConnectionData *bnet);
static int  bnet_bnls_send_VERSIONCHECKEX2(const BnetConnectionData *bnet,
            guint32 login_type, guint32 server_cookie, guint32 session_cookie,
            guint64 mpq_ft, char *mpq_fn, char *checksum_formula);
static int  bnet_bnls_send_REQUESTVERSIONBYTE(BnetConnectionData *bnet);
static void bnet_bnls_input_cb(gpointer data, gint source, PurpleInputCondition cond);
static void bnet_bnls_read_input(BnetConnectionData *bnet, int len);
static void bnet_bnls_recv_CHOOSENLSREVISION(const BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_bnls_recv_LOGONCHALLENGE(const BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_bnls_recv_LOGONPROOF(const BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_bnls_recv_REQUESTVERSIONBYTE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_bnls_recv_VERSIONCHECKEX2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_bnls_parse_packet(BnetConnectionData *bnet, const guint8 packet_id,
            const gchar *packet_start, const guint16 packet_len);
static void bnet_realm_login_cb(gpointer data, gint source, const gchar *error_message);
static gboolean bnet_realm_protocol_begin(const BnetConnectionData *bnet);
static int  bnet_realm_send_STARTUP(const BnetConnectionData *bnet);
static void bnet_realm_input_cb(gpointer data, gint source, PurpleInputCondition cond);
static void bnet_realm_read_input(BnetConnectionData *bnet, int len);
static void bnet_realm_parse_packet(BnetConnectionData *bnet, const guint8 packet_id,
            const gchar *packet_start, const guint16 packet_len);
static void bnet_login_cb(gpointer data, gint source, const gchar *error_message);
static gboolean bnet_protocol_telnet_begin(const BnetConnectionData *bnet);
static gboolean bnet_protocol_begin(const BnetConnectionData *bnet);
static int  bnet_send_telnet_line(const BnetConnectionData *bnet, const char *line);
static int  bnet_send_protocol_byte(int byte, int fd);
static int  bnet_send_NULL(const BnetConnectionData *bnet);
static int  bnet_send_STARTVERSIONING(const BnetConnectionData *bnet);
static int  bnet_send_REPORTVERSION(const BnetConnectionData *bnet,
            guint32 exe_version, guint32 exe_checksum, char *exe_info);
static int  bnet_send_ENTERCHAT(const BnetConnectionData *bnet, const gchar *stats);
static int  bnet_send_GETCHANNELLIST(const const BnetConnectionData *bnet);
static int  bnet_send_JOINCHANNEL(const BnetConnectionData *bnet,
            BnetChannelJoinFlags channel_flags, char *channel);
static int  bnet_send_CHATCOMMAND(const BnetConnectionData *bnet, const char *command);
static int  bnet_send_CDKEY(const BnetConnectionData *bnet);
static int  bnet_send_CDKEY2(const BnetConnectionData *bnet);
static int  bnet_send_LOGONRESPONSE2(const BnetConnectionData *bnet);
static int  bnet_send_CREATEACCOUNT2(const BnetConnectionData *bnet);
static int  bnet_send_LOCALEINFO(const BnetConnectionData *bnet);
static int  bnet_send_CLIENTID2(const BnetConnectionData *bnet);
static int  bnet_send_CLIENTID(const BnetConnectionData *bnet);
static int  bnet_send_SYSTEMINFO(const BnetConnectionData *bnet);
static int  bnet_send_PING(const BnetConnectionData *bnet, guint32 cookie);
static int  bnet_send_READUSERDATA(const BnetConnectionData *bnet,
            int request_cookie, const char *username, char **keys);
static int  bnet_send_WRITEUSERDATA(const BnetConnectionData *bnet,
            const char *sex, const char *age, const char *location, const char *description);
static int  bnet_send_NEWS_INFO(const BnetConnectionData *bnet, guint32 timestamp);
static int  bnet_send_AUTH_INFO(const BnetConnectionData *bnet);
static int  bnet_send_AUTH_CHECK(const BnetConnectionData *bnet,
            guint32 exe_version, guint32 exe_checksum, char *exe_info);
static int  bnet_send_AUTH_ACCOUNTCREATE(const BnetConnectionData *bnet, char *salt_and_v);
static int  bnet_send_AUTH_ACCOUNTLOGON(const BnetConnectionData *bnet, char *A);
static int  bnet_send_AUTH_ACCOUNTLOGONPROOF(const BnetConnectionData *bnet, char *M1);
static int  bnet_send_SETEMAIL(const BnetConnectionData *bnet, const char *email);
static int  bnet_send_FRIENDSLIST(const BnetConnectionData *bnet);
static int  bnet_send_CLANCREATIONINVITATION(const BnetConnectionData *bnet, const int cookie,
            const BnetClanTag clan_tag, const gchar *inviter_name, gboolean accept);
static int  bnet_send_CLANINVITATIONRESPONSE(const BnetConnectionData *bnet, const int cookie,
            const BnetClanTag clan_tag, const gchar *inviter_name, gboolean accept);
static int  bnet_send_CLANSETMOTD(const BnetConnectionData *bnet, const int cookie, const gchar *motd);
static int  bnet_send_CLANMOTD(const BnetConnectionData *bnet, const int cookie);
static int  bnet_send_CLANMEMBERLIST(const BnetConnectionData *bnet, const int cookie);
static void bnet_input_cb(gpointer data, gint source, PurpleInputCondition cond);
static void bnet_read_telnet_input(BnetConnectionData *bnet, int len);
static void bnet_read_input(BnetConnectionData *bnet, int len);
static void bnet_recv_STARTVERSIONING(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_REPORTVERSION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_ENTERCHAT(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_GETCHANNELLIST(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CHATEVENT(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_MESSAGEBOX(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_LOGONCHALLENGEEX(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_PING(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_READUSERDATA(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_LOGONCHALLENGE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CDKEY(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CDKEY2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_NEWS_INFO(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_INFO(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_CHECK(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_ACCOUNTCREATE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_ACCOUNTLOGON(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_ACCOUNTLOGONPROOF(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_SETEMAIL(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_LOGONRESPONSE2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CREATEACCOUNT2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSLIST(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSUPDATE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSADD(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSREMOVE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSPOSITION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANFINDCANDIDATES(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANINVITEMULTIPLE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANCREATIONINVITATION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANDISBAND(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMAKECHIEFTAIN(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANINFO(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANQUITNOTIFY(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANINVITATION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANREMOVEMEMBER(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANINVITATIONRESPONSE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANRANKCHANGE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMOTD(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMEMBERLIST(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMEMBERREMOVED(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMEMBERSTATUSCHANGE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMEMBERRANKCHANGE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CLANMEMBERINFO(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_event_SHOWUSER(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_JOIN(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_LEAVE(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_WHISPER(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_TALK(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_BROADCAST(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_CHANNEL(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_USERFLAGS(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_WHISPERSENT(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_CHANNELFULL(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_CHANNELDOESNOTEXIST(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_CHANNELRESTRICTED(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_whois(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_away_response(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_dnd_response(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_away_state(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_dnd_state(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_dnd_error(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_ban(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_kick(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static BnetEventShowMode bnet_recv_event_INFO_unban(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static void bnet_recv_event_INFO(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_ERROR(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_EMOTE(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_INFO_PARSED(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event_ERROR_PARSED(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static void bnet_recv_event(BnetConnectionData *bnet, PurpleConvChat *chat, BnetChatEventID event_id,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping, guint64 timestamp);
static BnetEventShowMode bnet_parse_telnet_line_event(BnetConnectionData *bnet, GRegex *regex,
            const gchar *text, GMatchInfo *mi, guint64 timestamp);
static void bnet_parse_telnet_line(BnetConnectionData *bnet, const gchar *line);
static void bnet_parse_packet(BnetConnectionData *bnet, const guint8 packet_id,
            const gchar *packet_start, const guint16 packet_len);
static void bnet_account_register(PurpleAccount *account);
static void bnet_account_chpw(PurpleConnection *gc, const char *oldpass, const char *newpass);
static void bnet_account_logon(BnetConnectionData *bnet);
static void bnet_enter_channel(const BnetConnectionData *bnet);
static void bnet_realm_logon_cb(BnetConnectionData *bnet);
static void bnet_enter_chat(BnetConnectionData *bnet);
static int  bnet_realm_logon(const BnetConnectionData *bnet, const guint32 client_cookie,
            const gchar *realm_name, const gchar *realm_pass);
static void bnet_entered_chat(BnetConnectionData *bnet);
static void bnet_realm_character_list(BnetConnectionData *bnet, GList *char_list);
static void bnet_realm_server_list(BnetConnectionData *bnet, GList *server_list);
static gboolean bnet_updatelist_timer(BnetConnectionData *bnet);
static void bnet_account_lockout_set(BnetConnectionData *bnet);
static void bnet_account_lockout_cancel(BnetConnectionData *bnet);
static gboolean bnet_account_lockout_timer(BnetConnectionData *bnet);
static void bnet_request_set_email_cb(gpointer data);
static void bnet_request_set_email(BnetConnectionData *bnet, gboolean nomatch_error);
static void bnet_clan_invite_accept_cb(void *data, int act_index);
static void bnet_clan_invite_decline_cb(void *data, int act_index);
static gint bnet_channel_user_compare(gconstpointer a, gconstpointer b);
static PurpleCmdRet bnet_handle_cmd(PurpleConversation *conv, const gchar *cmdword,
            gchar **args, gchar **error, void *data);
static double bnet_get_tz_bias(void);
static char *bnet_format_time(guint64 unixtime);
static char *bnet_format_filetime_string(char *ftime_str);
static char *bnet_format_filetime(guint64 filetime);
static guint64 bnet_get_filetime(time_t time);
static char *bnet_format_strsec(char *secs_str);
static char *bnet_to_utf8_crlf(const char *input);
static char *bnet_utf8_to_iso88591(const char *input);
static gchar *bnet_escape_text(const gchar *text, int length, gboolean replace_linebreaks);
static void bnet_find_detached_buddies(BnetConnectionData *bnet);
static void bnet_do_whois(const BnetConnectionData *bnet, const char *who);
static void bnet_friend_update(const BnetConnectionData *bnet, int index,
            BnetFriendInfo *bfi, BnetFriendStatus status,
            BnetFriendLocation location, BnetProductID product_id,
            const gchar *location_name);
static void bnet_close(PurpleConnection *gc);
static int  bnet_send_raw(PurpleConnection *gc, const char *buf, int len);
static int  bnet_send_whisper(PurpleConnection *gc, const char *who,
            const char *message, PurpleMessageFlags flags);
static void bnet_lookup_info(PurpleConnection *gc, const char *who);
static void bnet_lookup_info_close(gpointer user_data);
static gboolean bnet_lookup_info_cached_channel(BnetConnectionData *bnet);
static gboolean bnet_lookup_info_cached_friends(BnetConnectionData *bnet);
static gboolean bnet_lookup_info_cached_clan(BnetConnectionData *bnet);
static void bnet_lookup_info_whois(BnetConnectionData *bnet);
static void bnet_lookup_info_user_data(BnetConnectionData *bnet);
static void bnet_lookup_info_w3_user_profile(BnetConnectionData *bnet);
static void bnet_lookup_info_w3_user_stats(BnetConnectionData *bnet);
static void bnet_lookup_info_w3_clan_stats(BnetConnectionData *bnet);
static void bnet_lookup_info_w3_clan_mi(BnetConnectionData *bnet);
static void bnet_action_set_motd_cb(gpointer data);
static gint bnet_news_item_sort(gconstpointer a, gconstpointer b);
static void bnet_news_save(BnetConnectionData *bnet);
static void bnet_news_load(BnetConnectionData *bnet);
static void bnet_action_show_news(PurplePluginAction *action);
static void bnet_action_set_motd(PurplePluginAction *action);
static void bnet_action_set_user_data(PurplePluginAction *action);
static void bnet_profile_get_for_edit(BnetConnectionData *bnet);
static void bnet_profile_show_write_dialog(BnetConnectionData *bnet,
            const char *psex, const char *page, const char *ploc, const char *pdescr);
static void bnet_profile_write_cb(gpointer data);
static void bnet_userdata_request_free(BnetUserDataRequest *req);
static BnetUserDataRequest *bnet_userdata_request_new(int cookie, BnetUserDataRequestType type,
            const gchar *username, gchar **userdata_keys,
            BnetProductID product);
static int bnet_userdata_request_get_cookie(const BnetUserDataRequest *req);
static gchar *bnet_userdata_request_get_key_by_index(const BnetUserDataRequest *req, int i);
static BnetUserDataRequestType bnet_userdata_request_get_type(const BnetUserDataRequest *req);
static BnetProductID bnet_userdata_request_get_product(const BnetUserDataRequest *req);
static GHashTable *bnet_chat_info_defaults(PurpleConnection *gc, const char *chat_name);
static GList *bnet_chat_info(PurpleConnection *gc);
static char *bnet_channel_message_parse(char *stats_data, BnetChatEventFlags flags, int ping);
static PurpleConvChatBuddyFlags bnet_channel_flags_to_prpl_flags(BnetChatEventFlags flags);
static void bnet_join_chat(PurpleConnection *gc, GHashTable *components);
static int bnet_chat_im(PurpleConnection *gc, int chat_id, const char *message, PurpleMessageFlags flags);
static const char *bnet_list_icon(PurpleAccount *a, PurpleBuddy *b);
static const char *bnet_list_emblem(PurpleBuddy *b);
static char *bnet_status_text(PurpleBuddy *b);
static void bnet_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *info,
            gboolean full);
static char *bnet_get_location_text(BnetFriendLocation location, char *location_name);
static const gchar *bnet_get_product_name(BnetProductID product);
static gchar *bnet_get_product_info(const gchar *user_stats);
static gchar *bnet_parse_user_flags(BnetChatEventFlags flags);
static GList *bnet_parse_user_stats(BnetProductID product, const gchar *stats);
static gchar *bnet_get_product_id_str(BnetProductID product);
static GList *bnet_status_types(PurpleAccount *account);
static void bnet_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
static void bnet_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
static PurpleRoomlist *bnet_roomlist_get_list(PurpleConnection *gc);
static void bnet_roomlist_cancel(PurpleRoomlist *list);
static void bnet_set_status(PurpleAccount *account, PurpleStatus *status);
static void bnet_set_away(BnetConnectionData *bnet, gboolean new_state, const gchar *message);
static void bnet_set_dnd(BnetConnectionData *bnet, gboolean new_state, const gchar *message);
static const char *bnet_normalize(const PurpleAccount *account, const char *in);
static const char *bnet_d2_normalize(const PurpleAccount *account, const char *in);
static const char *bnet_d2_get_character(const PurpleAccount *account, const char *in);
static const char *bnet_d2_get_realm(const PurpleAccount *account, const char *in);
static const char *bnet_account_normalize(const PurpleAccount *account, const char *in);
static const char *bnet_gateway_normalize(const PurpleAccount *account, const char *in);
static gboolean bnet_is_d2(const BnetConnectionData *bnet);
static gboolean bnet_is_w3(const BnetConnectionData *bnet);
static BnetVersioningSystem bnet_get_versioningsystem(const BnetConnectionData *bnet);
static int bnet_get_key_count(const BnetConnectionData *bnet);
static GList *bnet_actions(PurplePlugin *plugin, gpointer context);
static void init_plugin(PurplePlugin *plugin);


typedef void (*BnetChatEventFunction)(BnetConnectionData *, PurpleConvChat *, const gchar *,
        const gchar *, BnetChatEventFlags, gint32, guint64);

struct BnetChatEvent {
    BnetChatEventID id;
    BnetChatEventFunction fn;
    gboolean text_is_statstring;
} bnet_events[] = {
    { 0, NULL, FALSE },
    { BNET_EID_SHOWUSER, bnet_recv_event_SHOWUSER, TRUE },
    { BNET_EID_JOIN, bnet_recv_event_JOIN, TRUE },
    { BNET_EID_LEAVE, bnet_recv_event_LEAVE, TRUE },
    { BNET_EID_WHISPER, bnet_recv_event_WHISPER, FALSE },
    { BNET_EID_TALK, bnet_recv_event_TALK, FALSE },
    { BNET_EID_BROADCAST, bnet_recv_event_BROADCAST, FALSE },
    { BNET_EID_CHANNEL, bnet_recv_event_CHANNEL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_USERFLAGS, bnet_recv_event_USERFLAGS, TRUE },
    { BNET_EID_WHISPERSENT, bnet_recv_event_WHISPERSENT, FALSE },
    { 0, NULL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_CHANNELFULL, bnet_recv_event_CHANNELFULL, FALSE },
    { BNET_EID_CHANNELDOESNOTEXIST, bnet_recv_event_CHANNELDOESNOTEXIST, FALSE },
    { BNET_EID_CHANNELRESTRICTED, bnet_recv_event_CHANNELRESTRICTED, FALSE },
    { 0, NULL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_INFO, bnet_recv_event_INFO, FALSE },
    { BNET_EID_ERROR, bnet_recv_event_ERROR, FALSE },
    { BNET_EID_INFO_PARSED, bnet_recv_event_INFO_PARSED, FALSE }, /* defunct by Battle.net, used in delayed event handling */
    { BNET_EID_ERROR_PARSED, bnet_recv_event_ERROR_PARSED, FALSE }, /* defunct by Battle.net, used in delayed event handling */
    { 0, NULL, FALSE },
    { BNET_EID_EMOTE, bnet_recv_event_EMOTE, FALSE },

    /* NULL TERMINATION */
    { 0, NULL, FALSE }
};

typedef BnetEventShowMode (*BnetRegexMatchFunction)(BnetConnectionData *, GRegex *, const gchar *, GMatchInfo *, guint64);

struct BnetRegexStore {
    GRegex *regex;
    gchar *regex_str;
    BnetChatEventID event_id;
    BnetRegexMatchFunction fn;
    gchar *arg_format;
} bnet_regex_store[] = {
    // TELNET LINE
    { NULL, "(\\d{4}) \\S+(?:\\s(.+)|)", 0, bnet_parse_telnet_line_event, NULL },
    
    // TELNET EID EVENT
    { NULL, "(\\S+) (\\d+) \\[(\\S+)\\]", BNET_TELNET_EID, NULL, "nfp" },
    { NULL, "(\\S+) (\\d+)", BNET_TELNET_EID, NULL, "nf" },
    { NULL, "(\\S+) (\\d+) \"(.*)\"", BNET_TELNET_EID, NULL, "nft" },
    { NULL, "\"(.*)\"", BNET_TELNET_EID, NULL, "t" },

    // WHOIS RESPONSE
    { NULL, "(?:You are |)(\\S+(?:| \\(\\*\\S+\\)))(?:,| is) using (.+) in (.+)\\.", BNET_EID_INFO, bnet_recv_event_INFO_whois, NULL },
    // WHOIS AWAY RESPONSE
    // WHISPER AWAY RESPONSE
    { NULL, "(?:You are|(\\S+(?:| \\(\\*\\S+\\))) is) away \\((.+)\\)", BNET_EID_INFO, bnet_recv_event_INFO_away_response, NULL },
    // WHOIS DND RESPONSE
    { NULL, "(?:You are|(\\S+(?:| \\(\\*\\S+\\))) is) refusing messages \\((.+)\\)", BNET_EID_INFO, bnet_recv_event_INFO_dnd_response, NULL },
    // AWAY RESPONSE
    // STILL AWAY RESPONSE
    { NULL, "You are (still|now|no longer) marked as (?:being |)away\\.", BNET_EID_INFO, bnet_recv_event_INFO_away_state, NULL },
    // DND RESPONSE
    { NULL, "Do Not Disturb mode (engaged|cancelled)\\.", BNET_EID_INFO, bnet_recv_event_INFO_dnd_state, NULL },
    // WHISPER DND ERROR
    { NULL, "(\\S+(?:| \\(\\*\\S+\\))) is unavailable \\((.+)\\)", BNET_EID_INFO, bnet_recv_event_INFO_dnd_error, NULL },
    // BAN MESSAGE
    { NULL, "(\\S+(?:| \\(\\*\\S+\\))) was banned by (\\S+(?:| \\(\\*\\S+\\)))(?: \\((.+)\\)|)\\.", BNET_EID_INFO, bnet_recv_event_INFO_ban, NULL },
    // KICK MESSAGE
    { NULL, "(\\S+(?:| \\(\\*\\S+\\))) was kicked out of the channel by (\\S+(?:| \\(\\*\\S+\\)))(?: \\((.+)\\)|)\\.", BNET_EID_INFO, bnet_recv_event_INFO_kick, NULL },
    // UNBAN MESSAGE
    { NULL, "(\\S+(?:| \\(\\*\\S+\\))) was unbanned by (\\S+(?:| \\(\\*\\S+\\)))\\.", BNET_EID_INFO, bnet_recv_event_INFO_unban, NULL },

    // NULL TERMINATOR
    { NULL, NULL, 0, NULL, NULL }
};

#endif

