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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// libpurple includes
#ifdef _WIN32 // Win/Mingw doesn't compile without this
#include "internal.h"
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
#include "w3clan.h"
#include "userdata.h"

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
    BNET_SID_PROFILE                 = 0x35,
    BNET_SID_CDKEY2                  = 0x36,
    BNET_SID_LOGONRESPONSE2          = 0x3A,
    BNET_SID_CREATEACCOUNT2          = 0x3D,
    BNET_SID_WARCRAFTGENERAL         = 0x44,
    BNET_SID_NETGAMEPORT             = 0x45,
    BNET_SID_NEWS_INFO               = 0x46,
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
    BNET_SID_CLANMEMBERINFORMATION   = 0x82,
} BnetPacketID;

// bnls packet ids
#define BNET_BNLS_REQUESTVERSIONBYTE 0x10
#define BNET_BNLS_VERSIONCHECKEX2 0x1A
#define BNET_BNLS_LOGONCHALLENGE 0x02
#define BNET_BNLS_LOGONPROOF 0x03
#define BNET_BNLS_CHOOSENLSREVISION 0x0D

// AUTH_INFO protocol id
#define BNET_PROTOCOL_ID 0

// architecture
#define BNET_PLATFORM_IX86 'IX86'
#define BNET_PLATFORM_PMAC 'PMAC'
#define BNET_PLATFORM_XMAC 'XMAC'

// udp
//'bnet'
#define BNET_UDP_SIG 'bnet'

// game product id
#define BNET_PRODUCT_STAR 'STAR'
#define BNET_PRODUCT_SEXP 'SEXP'
#define BNET_PRODUCT_W2BN 'W2BN'
#define BNET_PRODUCT_D2DV 'D2DV'
#define BNET_PRODUCT_D2XP 'D2XP'
#define BNET_PRODUCT_JSTR 'JSTR'
#define BNET_PRODUCT_WAR3 'WAR3'
#define BNET_PRODUCT_W3XP 'W3XP'
#define BNET_PRODUCT_DRTL 'DRTL'
#define BNET_PRODUCT_DSHR 'DSHR'
#define BNET_PRODUCT_SSHR 'SSHR'
#define BNET_PRODUCT_CHAT 'CHAT'

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

// prpl data
#define PROTOCOL_NAME      "bnet"
#define PLUGIN_ID          "prpl-ribose-bnet"
#define PLUGIN_NAME        "Classic Battle.net"
#define PLUGIN_MAJOR_VER    0
#define PLUGIN_MINOR_VER    9
#define PLUGIN_MICRO_VER    0
#define PLUGIN_SHORT_DESCR "Classic Battle.net Protocol Plugin"
#define PLUGIN_DESCR       "Classic Battle.net Chat Server Protocol. Allows you to connect to classic Battle.net to chat with users on StarCraft, Diablo/II, and WarCraft II/III and their expansions."
#define PLUGIN_AUTHOR      "Nate Book <nmbook@gmail.com>"
#define PLUGIN_WEBSITE     "http://www.ribose.me"
#define QUOTE_(x)           #x
#define QUOTE(x)            QUOTE_(x)
#define PLUGIN_STR_VER      QUOTE(PLUGIN_MAJOR_VER.PLUGIN_MINOR_VER.PLUGIN_MICRO_VER)

// default setting values
#define BNET_DEFAULT_SERVER     "uswest.battle.net"
#define BNET_DEFAULT_PORT        6112
#define BNET_DEFAULT_BNLSSERVER "bnls.net"
#define BNET_DEFAULT_BNLSPORT    9367

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

// this enum specifies choosable game types
// this is the order BNLS uses too
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
    BNET_GAME_TYPE_SSHR = 0x0B
} BnetGameType;

// this type specifies values that can come from BNET_PRODUCT_*
// #define'd in packet.h
typedef guint32 BnetProductID;

// buffer size
#define BNET_INITIAL_BUFSIZE 512

typedef enum {
    BNET_CHANNELJOIN_NOCREATE   = 0x00000000,
    BNET_CHANNELJOIN_FIRSTJOIN  = 0x00000001,
    BNET_CHANNELJOIN_FORCEDJOIN = 0x00000002,
    BNET_CHANNELJOIN_D2FIRST    = 0x00000004
} BnetChannelJoinFlags;

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
    BNET_EID_EMOTE               = 0x00000017
} BnetChatEventID;

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

#define BNET_USER_TYPE_CHANNELUSER  0x01
#define BNET_USER_TYPE_FRIEND       0x02

typedef enum {
    BNET_USER_TAG_ONFRIENDLIST = 1
} BnetUserTag;

typedef struct {
    gint32 type;
    gchar *username;
    // tag: used currently for friend list diff right now
    BnetUserTag tag;
    gchar data[48];
} BnetUser;

typedef struct {
    guint32 type;
    char *username;
    // tag: used currently for friend list diff right now
    BnetUserTag tag;
    char *stats_data;
    BnetChatEventFlags flags;
    gint32 ping;
    gboolean hidden;
    
    char *stats_message;
} BnetChannelUser;

typedef enum {
    BNET_FRIEND_STATUS_ONLINE = 0x00,
    BNET_FRIEND_STATUS_MUTUAL = 0x01,
    BNET_FRIEND_STATUS_DND    = 0x02,
    BNET_FRIEND_STATUS_AWAY   = 0x04
} BnetFriendStatus;

typedef enum {
    BNET_FRIEND_LOCATION_OFFLINE        = 0x00,
    BNET_FRIEND_LOCATION_ONLINE         = 0x01,
    BNET_FRIEND_LOCATION_CHANNEL        = 0x02,
    BNET_FRIEND_LOCATION_GAME_PUBLIC    = 0x03,
    BNET_FRIEND_LOCATION_GAME_PRIVATE   = 0x04,
    BNET_FRIEND_LOCATION_GAME_PROTECTED = 0x05
} BnetFriendLocation;

typedef struct {
    guint32 type;
    // account name from friend list
    char *account;
    // tag: used currently for friend list diff right now
    BnetUserTag tag;
    // information directly from friend list
    BnetFriendStatus status;
    BnetFriendLocation location;
    BnetProductID product;
    char *location_name;

    // whether we are waiting for a /whois on this user
    BnetFriendStatus automated_lookup;
    // from /whois (if available)
    // when a whois returns "away" or "dnd" message
    gchar *dnd_stored_status;
    gchar *away_stored_status;
    
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

// protocol bytes
#define BNET_PROTOCOL_BNCS  0x01
#define BNET_PROTOCOL_MCP   0x01
#define BNET_PROTOCOL_BNFTP 0x02
#define BNET_PROTOCOL_CHAT  0x03

// versioning system to use
typedef gint32 BnetVersioningSystem;
// SSHR, JSTR: SID_CLIENTID, SID_LOCALEINFO, SID_SYSTEMINFO, SID_STARTVERSIONING; SID_CDKEY
#define BNET_VERSIONING_LEGACY  0x00
// DRTL, DSHR, W2BN: SID_CLIENTID2, SID_LOCALEINFO, SID_STARTVERSIONING; SID_CDKEY2
#define BNET_VERSIONING_LEGACY2 0x01
// STAR, SEXP, D2DV, D2XP, W3DM, WAR3, W3XP: SID_AUTH_INFO; SID_AUTH_CHECK
#define BNET_VERSIONING_AUTH    0x02

// account logon system to use
typedef gint32 BnetLogonSystem;
// DRTL, DSHR, STAR, SEXP, SSHR, JSTR, W2BN, D2DV, D2XP: X-SHA-1 SID_LOGONRESPONSE/SID_LOGONRESPONSE2
#define BNET_LOGON_XSHA1        0x00
// W3DM: SRP (NLS version 1)
#define BNET_LOGON_SRPOLD       0x01
// WAR3, W3XP: SRP (NLS version 2)
#define BNET_LOGON_SRP          0x02

// possible event numbers for telnet
// 10xx => CHATEVENT EIDs
#define BNET_TELNET_EID 1000
// 20xx => packet SIDs
#define BNET_TELNET_SID 2000
// 30xx
#define BNET_TELNET_XID 3000

// stores socket connection data for a specific socket
struct SocketData {
    // file descriptor
    int fd;
    // inbound buffer length
    guint16 inbuflen;
    // inbound buffer used
    guint16 inbufused;
    // inbound buffer
	gchar *inbuf;
    // input watcher
    int inpa;
    // the connection data for this connect
    PurpleProxyConnectData *conn_data;
};

// this struct stores extra info for a battle.net connection
typedef struct {
    // = 'bnet'
    int magic;
    
    // assocated PurpleAccount
    PurpleAccount *account;
    
    // socket data:
    // BNET
    struct SocketData sbnet;
    // BNLS
    struct SocketData sbnls;
    
    // current connection info:
    // current username
    gchar *username;
    // current server
    gchar *server;
    // current port
    guint16 port;
    // current BNLS server
    gchar *bnls_server;
    // current BNLS port
    guint16 bnls_port;
    
    // authentication data:
    gboolean emulate_telnet;
    // the game product to emulate (BNLS style)
    BnetGameType game;
    // the game product ID (BNET style)
    BnetProductID product_id;
    // the version code (verbyte)
    guint32 version_code;
    // the client cookie (client token)
    guint32 client_cookie;
    // the server cookie (server token)
    guint32 server_cookie;
    // the UDP cookie (UDP token)
    guint32 udp_cookie;
    // versioning system
    BnetVersioningSystem versioning_system;
    // logon type
    BnetLogonSystem logon_system;
    // whether we have completed version checking yet
    gboolean versioning_complete;
    // for logging in
    srp_t *account_data;
    // for changing password or creating an account, the "new" srp_t
    srp_t *account_change_data;
    
    // account data:
    // whether we should create the account if DNE during this logon
    gboolean account_create; 
    // whether we should change passwords during this logon
    gboolean change_pw;
    // what to change password from
    char *change_pw_from;
    // what to change password to
    char *change_pw_to;
    
    // online data:
    // when completely connected (in a channel), this is set to TRUE
    gboolean is_online;
    // contains "*" or "" depending on whether we are on D2
    gchar *d2_star;
    // send first-join
    gboolean sent_enter_channel;
    // account name after enter chat
    gchar *my_accountname;
    // statstring after enter chat
    gchar *my_statstring;
    // the unique username Battle.net assigned
    gchar *unique_username;
    // a counter, increases every 30 seconds that is_online is true
    // used for "keep alive"-like functions
    guint32 ka_tick;
    // handle for keep alive timer
    guint ka_handle;
    // welcome messages, stored for later
    //GList *welcome_msgs;
    // number of news messages
    guint32 news_count;
    // news messages
    GList *news;
    // email fields for dialog
    PurpleRequestFields *set_email_fields;
    
    // roomlist data:
    // a GList<char *> - a copy of the roomlist
    GList *channel_list;
    // libpurple Roomlist
    PurpleRoomlist *room_list;
    
    // channel data:
    // when this channel is the "first join" channel and should not be told to libpurple
    gboolean channel_first_join;
    // we are waiting for "ourself" in the current channel, to pass the whole list to libpurple
    gboolean channel_seen_self;
    // hash table containing join attempt
    GHashTable *join_attempt;
    // hash of current channel name
    int channel_id;
    // current channel name
    char *channel_name;
    // current channel flags
    BnetChatEventFlags channel_flags;
    // current channel members
    GList *channel_users;
    
    // whois data:
    // the username of the user we are currently looking up
    gchar *lookup_user;
    // libpurple's data for the current look-up
    PurpleNotifyUserInfo *lookup_info;
    
    // a GList<BnetUserDataRequest> - each userdata request
    GList *userdata_requests;
    
    // whether we are requesting profile data to write to your profile
    gboolean writing_profile;
    // fields in write dialog
    PurpleRequestFields *profile_write_fields;
    
    // whisper data:
    // last user we sent a message to
    gchar *last_sent_to;
    gboolean awaiting_whisper_confirm;

    // friend data:
    // a GList<BnetFriendInfo> - our current Battle.net friends list
    GList *friends_list;
    
    // W3 clan data:
    BnetClanInfo *clan_info;
    // W3 clan set motd fields in dialog
    PurpleRequestFields *set_motd_fields;
    
    // status data:
    // away: are we currently away?
    gboolean is_away;
    // what message?
    gchar *away_msg;
    // are we trying to change our status?
    gboolean setting_away_status;
    // dnd: are we currently dnd?
    gboolean is_dnd;
    // what message?
    gchar *dnd_msg;
    // are we trying to change our dnd state?
    gboolean setting_dnd_status;
    
    PurpleConversation *last_command_conv;
    
    // priority queue
    //BnetQueue *mqueue;
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
    guint32 timestamp;
    gchar *message;
} BnetNewsItem;

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
            "friends &lt;action&gt; [options]:  Perform a friends-list action (list, add &lt;user&gt;, remove &lt;user&gt;, msg &lt;user&gt; &lt;message&gt;, promote &lt;user&gt;, demote &lt;user&gt;)." },
    { BNET_CMD_FRIENDS, BNET_CMD_FLAG_INFORESPONSE, "f", "ws",
            "f &lt;action&gt; [options]:  Perform a friends-list action (list, add &lt;user&gt;, remove &lt;user&gt;, msg &lt;user&gt; &lt;message&gt;, promote &lt;user&gt;, demote &lt;user&gt;)." },
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

typedef void (*BnetChatEventFunction)(BnetConnectionData *, PurpleConvChat *, const gchar *,
        const gchar *, BnetChatEventFlags, gint32);

struct BnetChatEvent {
    BnetChatEventID id;
    BnetChatEventFunction fn;
    gboolean text_is_statstring;
} bnet_events[] = {
    { 0, NULL, FALSE },
    { BNET_EID_SHOWUSER, NULL, TRUE },
    { BNET_EID_JOIN, NULL, TRUE },
    { BNET_EID_LEAVE, NULL, TRUE },
    { BNET_EID_WHISPER, NULL, FALSE },
    { BNET_EID_TALK, NULL, FALSE },
    { BNET_EID_BROADCAST, NULL, FALSE },
    { BNET_EID_CHANNEL, NULL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_USERFLAGS, NULL, TRUE },
    { BNET_EID_WHISPERSENT, NULL, FALSE },
    { 0, NULL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_CHANNELFULL, NULL, FALSE },
    { BNET_EID_CHANNELDOESNOTEXIST, NULL, FALSE },
    { BNET_EID_CHANNELRESTRICTED, NULL, FALSE },
    { 0, NULL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_INFO, NULL, FALSE },
    { BNET_EID_ERROR, NULL, FALSE },
    { 0, NULL, FALSE },
    { 0, NULL, FALSE },
    { 0, NULL, FALSE },
    { BNET_EID_EMOTE, NULL, FALSE },
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
            guint32 login_type, guint32 server_cookie, guint32 udp_cookie,
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
static void bnet_login_cb(gpointer data, gint source, const gchar *error_message);
static gboolean bnet_protocol_telnet_begin(const BnetConnectionData *bnet);
static gboolean bnet_protocol_begin(const BnetConnectionData *bnet);
static int  bnet_send_telnet_line(const BnetConnectionData *bnet, const char *line);
static int  bnet_send_protocol_byte(const BnetConnectionData *bnet, int byte);
static int  bnet_send_NULL(const BnetConnectionData *bnet);
static int  bnet_send_STARTVERSIONING(const BnetConnectionData *bnet);
static int  bnet_send_REPORTVERSION(const BnetConnectionData *bnet,
            guint32 exe_version, guint32 exe_checksum, char *exe_info);
static int  bnet_send_ENTERCHAT(const BnetConnectionData *bnet);
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
static int  bnet_send_WRITEUSERDATA_2(const BnetConnectionData *bnet,
            const char *key, const char *val);
static int  bnet_send_NEWS_INFO(const BnetConnectionData *bnet);
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
static void bnet_recv_CLANMEMBERINFORMATION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_event_SHOWUSER(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_JOIN(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_LEAVE(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_WHISPER(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_TALK(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_BROADCAST(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_CHANNEL(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_USERFLAGS(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_WHISPERSENT(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_CHANNELFULL(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_CHANNELDOESNOTEXIST(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_CHANNELRESTRICTED(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_INFO(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_ERROR(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_recv_event_EMOTE(BnetConnectionData *bnet, PurpleConvChat *chat,
            const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping);
static void bnet_parse_telnet_line(BnetConnectionData *bnet, const gchar *line);
static void bnet_parse_packet(BnetConnectionData *bnet, const guint8 packet_id,
            const gchar *packet_start, const guint16 packet_len);
static void bnet_account_register(PurpleAccount *account);
static void bnet_account_chpw(PurpleConnection *gc, const char *oldpass, const char *newpass);
static void bnet_account_logon(BnetConnectionData *bnet);
static void bnet_enter_channel(const BnetConnectionData *bnet);
static void bnet_enter_chat(BnetConnectionData *bnet);
static void bnet_entered_chat(BnetConnectionData *bnet);
static gboolean bnet_keepalive_timer(BnetConnectionData *bnet);
static void bnet_request_set_email_cb(gpointer data);
static void bnet_request_set_email(BnetConnectionData *bnet);
static void bnet_clan_invite_accept_cb(void *data, int act_index);
static void bnet_clan_invite_decline_cb(void *data, int act_index);
static gint bnet_channel_user_compare(gconstpointer a, gconstpointer b);
static PurpleCmdRet bnet_handle_cmd(PurpleConversation *conv, const gchar *cmdword,
            gchar **args, gchar **error, void *data);
static double bnet_get_tz_bias(void);
static char *bnet_format_time(guint64 unixtime);
static char *bnet_format_filetime(char *ftime_str);
static guint64 bnet_get_filetime(time_t time);
static char *bnet_format_strsec(char *secs_str);
static char *bnet_locale_to_utf8(const char *input);
static char *bnet_locale_from_utf8(const char *input);
static gchar *bnet_escape_text(const gchar *text, int length, gboolean replace_linebreaks);
static void bnet_find_detached_buddies(BnetConnectionData *bnet);
static void bnet_friend_update(const BnetConnectionData *bnet, int index,
            BnetFriendInfo *bfi, BnetFriendStatus status,
            BnetFriendLocation location, BnetProductID product_id,
            const gchar *location_name);
static void bnet_close(PurpleConnection *gc);
static int  bnet_send_raw(PurpleConnection *gc, const char *buf, int len);
static int  bnet_send_whisper(PurpleConnection *gc, const char *who,
            const char *message, PurpleMessageFlags flags);
static void bnet_get_info(PurpleConnection *gc, const char *who);
static void bnet_whois_complete(gpointer user_data);
static void bnet_whois_user(const BnetConnectionData *bnet, const char *who);
static void bnet_profiledata_user(BnetConnectionData *bnet, const char *who);
static void bnet_action_set_motd_cb(gpointer data);
static gint bnet_news_item_sort(gconstpointer a, gconstpointer b);
static void bnet_action_show_news(PurplePluginAction *action);
static void bnet_action_set_motd(PurplePluginAction *action);
static void bnet_action_set_user_data(PurplePluginAction *action);
static void bnet_profile_get_for_edit(BnetConnectionData *bnet);
static void bnet_profile_show_write_dialog(BnetConnectionData *bnet,
            const char *psex, const char *page, const char *ploc, const char *pdescr);
static void bnet_profile_write_cb(gpointer data);
static gboolean bnet_channeldata_user(BnetConnectionData *bnet, const char *who);
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
static char *bnet_get_product_name(BnetProductID product);
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
static const char *bnet_account_normalize(const PurpleAccount *account, const char *in);
static const char *bnet_gateway_normalize(const PurpleAccount *account, const char *in);
static gboolean bnet_is_d2(const BnetConnectionData *bnet);
static gboolean bnet_is_w3(const BnetConnectionData *bnet);
static BnetVersioningSystem bnet_get_versioningsystem(const BnetConnectionData *bnet);
static int bnet_get_key_count(const BnetConnectionData *bnet);
static GList *bnet_actions(PurplePlugin *plugin, gpointer context);
static void init_plugin(PurplePlugin *plugin);

#endif

