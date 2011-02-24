/** 
 * A Protocol Plugin for Pidgin, allowing emulation of a chat-only client
 * connected to the Battle.net Service.
 * Copyright (C) 2011 Nate Book
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

// libraries
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// libpurple includes
#include "internal.h"

#include "roomlist.h"
#include "blist.h"
#include "notify.h"
#include "plugin.h"
#include "version.h"
#include "prpl.h"
#include "account.h"
#include "accountopt.h"
#include "connection.h"
#include "debug.h"
#include "circbuffer.h"
#include "network.h"
#include "cmds.h"
#include "request.h"

// PURPLE_PLUGINS
#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

// prpl data
#define PROTOCOL_NAME      "bnet"
#define PLUGIN_ID          "prpl-ribose-bnet"
#define PLUGIN_NAME        "Classic Battle.net"
#define PLUGIN_MAJOR_VER    0
#define PLUGIN_MINOR_VER    8
#define PLUGIN_MICRO_VER    0
#define PLUGIN_SHORT_DESCR "Classic Battle.net Chat Server Protocol Plugin"
#define PLUGIN_DESCR       "Classic Battle.net Chat Server Protocol. Allows you to connect to classic Battle.net to chat with users on StarCraft, Diablo/II, and WarCraft II/III and their expansions."
#define PLUGIN_AUTHOR      "Nate Book <nmbook@gmail.com>"
#define PLUGIN_WEBSITE     "http://ribose.no-ip.org"
#define QUOTE_(x)           #x
#define QUOTE(x)            QUOTE_(x)
#define PLUGIN_STR_VER      QUOTE(PLUGIN_MAJOR_VER.PLUGIN_MINOR_VER.PLUGIN_MICRO_VER)

// default setting values
#define BNET_DEFAULT_SERVER     "uswest.battle.net"
#define BNET_DEFAULT_PORT        6112
#define BNET_DEFAULT_BNLSSERVER "ribose.no-ip.org"
#define BNET_DEFAULT_BNLSPORT    9367

// logon steps
#define BNET_STEP_COUNT      5
#define BNET_STEP_BNLS       0
#define BNET_STEP_CONNECTING 1
#define BNET_STEP_CREV       2
#define BNET_STEP_LOGON      3
#define BNET_STEP_FINAL      4

// message maximum size
#define BNET_MSG_MAXSIZE 225
#define BNET_EBADCHARS 0x0100

// status types
#define BNET_STATUS_ONLINE  "Online"
#define BNET_STATUS_AWAY    "Away"
#define BNET_STATUS_DND     "Do not disturb"
#define BNET_STATUS_OFFLINE "Offline"

// userdata request
#define BNET_USERDATA_PROFILE_REQUEST "profile\\sex\nprofile\\age\nprofile\\location\nprofile\\description"
#define BNET_USERDATA_RECORD_REQUEST "Record\\%s\\%d\\wins\nRecord\\%s\\%d\\losses\nRecord\\%s\\%d\\disconnects\nRecord\\%s\\%d\\last game\nRecord\\%s\\%d\\last game result"
#define BNET_USERDATA_RECORD_LADDER_REQUEST g_strdup_printf("%s\n%s", BNET_USERDATA_RECORD_REQUEST, "Record\\%s\\%d\\rating\nRecord\\%s\\%d\\high rating\nDynKey\\%s\\%d\\rank\nRecord\\%s\\%d\\high rank")
#define BNET_USERDATA_SYSTEM_REQUEST "System\\Account Created\nSystem\\Last Logoff\nSystem\\Last Logon\nSystem\\Username\n"
#define BNET_RECORD_NONE    0
#define BNET_RECORD_NORMAL  1
#define BNET_RECORD_LADDER  2
#define BNET_RECORD_IRONMAN 8

// includes
#include "packets.c"
#include "bnet-sha1.c"
#include "keydecode.c"
//#include "nls.c"

// this enum specifies choosable game types
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

// stores socket connection data for a specific socket
struct SocketData {
    // file descriptor
    int fd;
    // inbound buffer
	guint8 *inbuf;
    // inbound buffer amount to read
	guint16 inbuflen;
    // inbound buffer actual size
	guint16 inbufused;
    // input watcher
    int inpa;
    // the connection data for this connect
    PurpleProxyConnectData *conn_data;
};

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
// this struct stores extra info for a battle.net connection
typedef struct {
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
    // nls revision
    guint32 nls_revision;
    // whether we have completed version checking yet
    gboolean crev_complete;
    
    // account data:
    // whether we should create the account if DNE during this logon
    gboolean create_if_dne; 
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
    // the unique username Battle.net assigned
    gchar *unique_username;
    // a counter, increases every 30 seconds that is_online is true
    // used for "keep alive"-like functions
    guint32 ka_tick;
    // handle for keep alive timer
    guint ka_handle;
    // welcome messages, stored for later
    GList *welcome_msgs;
    
    // roomlist data:
    // a GList<char *> - a copy of the roomlist
    GList *channel_list;
    // libpurple Roomlist
    PurpleRoomlist *room_list;
    
    // channel data:
    // when this channel is the "first join" channel and should not be told to libpurple
    gboolean first_join;
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
    // action queue
    GQueue *action_q;
    // item being requested of B.net now.
    //BnetQueueElement *active_q_item;
} BnetConnectionData;

typedef struct {
    char *username;
    char *stats_data;
    BnetChatEventFlags flags;
    gint32 ping;
    gboolean hidden;
    
    char *stats_message;
} BnetChannelUser;

typedef enum {
    BNET_CHANNELJOIN_NOCREATE   = 0x00000000,
    BNET_CHANNELJOIN_FIRSTJOIN  = 0x00000001,
    BNET_CHANNELJOIN_FORCEDJOIN = 0x00000002,
    BNET_CHANNELJOIN_D2FIRST    = 0x00000004
} BnetChannelJoinFlags;

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
    // information directly from friend list
    char *account;
    BnetFriendStatus status;
    BnetFriendLocation location;
    BnetProductID product;
    char *location_name;

    // whether we are waiting for a /whois on this user
    gboolean automated_lookup;
    // from /whois (if available)
    // when a whois returns "away" or "dnd" message
    char *stored_status;
    
    // prpl buddy object
    PurpleBuddy *buddy;
} BnetFriendInfo;

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
    BNET_READUSERDATA_REQUEST_NONE    = 0x0,
    BNET_READUSERDATA_REQUEST_PROFILE = 0x1,
    BNET_READUSERDATA_REQUEST_RECORD  = 0x2,
    BNET_READUSERDATA_REQUEST_SYSTEM  = 0x4
} BnetUserDataRequestType;

typedef struct {
    // readuserdata data:
    // the cookie
    int cookie;
    // the type of request
    BnetUserDataRequestType request_type;
    // the user name
    gchar *username;
    // user data keys
    gchar **userdata_keys;
    // product for this request
    BnetProductID product;
} BnetUserDataRequest;

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
    { BNET_CMD_USERS, BNET_CMD_FLAG_INFORESPONSE, "users", "", 
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
    { 10231, BNET_CMD_FLAG_PRPL, "writekey", "ws",
            "writekey &lt;key&gt; &lt;value&gt;:  Writes a key to your Battle.net profile." },
    { 0, 0, NULL, NULL, NULL }
};

static void bnet_channel_user_free(BnetChannelUser *bcu);
static void bnet_friend_info_free(BnetFriendInfo *bfi);
static void bnet_buddy_free(PurpleBuddy *buddy);
static void bnet_connect(PurpleAccount *account, gboolean do_register);
static void bnet_login(PurpleAccount *account);
static void bnls_login_cb(gpointer data, gint source, const gchar *error_message);
static int bnls_send_CHOOSENLSREVISION(BnetConnectionData *bnet);
static int bnls_send_LOGONCHALLENGE(BnetConnectionData *bnet);
static int bnls_send_LOGONPROOF(BnetConnectionData *bnet, char *s_and_B);
static int bnls_send_VERSIONCHECKEX2(BnetConnectionData *bnet,
       guint32 login_type, guint32 server_cookie, guint32 udp_cookie,
       guint64 mpq_ft, char *mpq_fn, char *checksum_formula);
static int bnls_send_REQUESTVERSIONBYTE(BnetConnectionData *bnet);
static void bnls_input_cb(gpointer data, gint source, PurpleInputCondition cond);
static void bnls_read_input(BnetConnectionData *bnet, int len);
static void bnls_recv_CHOOSENLSREVISION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnls_recv_LOGONCHALLENGE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnls_recv_LOGONPROOF(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnls_recv_REQUESTVERSIONBYTE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnls_recv_VERSIONCHECKEX2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnls_parse_packet(BnetConnectionData *bnet, guint8 packet_id, guint8 *packet_start, guint16 packet_len);
static void bnet_login_cb(gpointer data, gint source, const gchar *error_message);
static gboolean bnet_protocol_begin(BnetConnectionData *bnet);
static int bnet_send_protocol_byte(BnetConnectionData *bnet, int byte);
static int bnet_send_NULL(BnetConnectionData *bnet);
static int bnet_send_ENTERCHAT(BnetConnectionData *bnet);
static int bnet_send_GETCHANNELLIST(BnetConnectionData *bnet);
static int bnet_send_JOINCHANNEL(BnetConnectionData *bnet,
           BnetChannelJoinFlags channel_flags, char *channel);
/*static int bnet_queue_CHATCOMMAND(BnetConnectionData *bnet, PurpleConversation *conv,
        BnetCommandID cmd, BnetQueueFunc cb, const char *command);*/
static int bnet_send_CHATCOMMAND(BnetConnectionData *bnet, const char *command);
static int bnet_send_LEAVECHAT(BnetConnectionData *bnet);
static int bnet_send_LOGONRESPONSE2(BnetConnectionData *bnet);
static int bnet_send_CREATEACCOUNT2(BnetConnectionData *bnet);
static int bnet_send_PING(BnetConnectionData *bnet, guint32 cookie);
static int bnet_send_READUSERDATA(BnetConnectionData *bnet,
    int request_cookie, const char *username, char **keys);
static int bnet_send_WRITEUSERDATA(BnetConnectionData *bnet,
    char *sex, char *age, char *location, char *description);
static int bnet_send_WRITEUSERDATA_2(BnetConnectionData *bnet,
    char *key, char *val);
static int bnet_send_AUTH_INFO(BnetConnectionData *bnet);
static int bnet_send_AUTH_CHECK(BnetConnectionData *bnet,
       guint32 exe_version, guint32 exe_checksum, char *exe_info);
static int bnet_send_AUTH_ACCOUNTLOGON(BnetConnectionData *bnet, char *A);
static int bnet_send_AUTH_ACCOUNTLOGONPROOF(BnetConnectionData *bnet, char *M1);
static int bnet_send_FRIENDSLIST(BnetConnectionData *bnet);
static void bnet_account_logon(BnetConnectionData *bnet);
static void bnet_enter_chat(BnetConnectionData *bnet);
static gboolean bnet_keepalive_timer(BnetConnectionData *bnet);
static void bnet_account_register(PurpleAccount *account);
static void bnet_account_chpw(PurpleConnection *gc, const char *oldpass, const char *newpass);
static void bnet_input_cb(gpointer data, gint source, PurpleInputCondition cond);
static void bnet_read_input(BnetConnectionData *bnet, int len);
static void bnet_recv_ENTERCHAT(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_GETCHANNELLIST(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CHATEVENT(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_MESSAGEBOX(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_PING(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_READUSERDATA(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_INFO(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_CHECK(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_ACCOUNTLOGON(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_AUTH_ACCOUNTLOGONPROOF(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_LOGONRESPONSE2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_CREATEACCOUNT2(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSLIST(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSUPDATE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSADD(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSREMOVE(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_recv_FRIENDSPOSITION(BnetConnectionData *bnet, BnetPacket *pkt);
static void bnet_parse_packet(BnetConnectionData *bnet, guint8 packet_id, guint8 *packet_start, guint16 packet_len);
/*static void bnet_queue(BnetConnectionData *bnet, BnetQueueElement *qel);
static void bnet_dequeue_tick(BnetConnectionData *bnet);
static int bnet_dequeue(BnetConnectionData *bnet);*/
static gint bnet_channel_user_compare(gconstpointer a, gconstpointer b);
static PurpleCmdRet bnet_handle_cmd(PurpleConversation *conv, const gchar *cmdword,
                                  gchar **args, gchar **error, void *data);
static double get_tz_bias(void);
char *bnet_format_strftime(char *ftime_str);
char *bnet_format_strsec(char *secs_str);
static void bnet_friend_update(BnetConnectionData *bnet, int index, BnetFriendInfo *bfi, gboolean replace);
static void bnet_close(PurpleConnection *gc);
static int bnet_send_raw(PurpleConnection *gc, const char *buf, int len);
static int bnet_send_whisper(PurpleConnection *gc, const char *who,
                             const char *message, PurpleMessageFlags flags);
static void bnet_get_info(PurpleConnection *gc, const char *who);
static void bnet_whois_complete(gpointer user_data);
static void bnet_whois_user(BnetConnectionData *bnet, const char *who);
static void bnet_profiledata_user(BnetConnectionData *bnet, const char *who);
static void bnet_action_set_user_data(PurplePluginAction *action);
static void bnet_profile_get_for_edit(BnetConnectionData *bnet);
static void bnet_profile_show_write_dialog(BnetConnectionData *bnet,
        char *psex, char *page, char *ploc, char *pdescr);
static void bnet_profile_write_cb(gpointer data);
static gboolean bnet_channeldata_user(BnetConnectionData *bnet, const char *who);
static GHashTable *bnet_chat_info_defaults(PurpleConnection *gc, const char *chat_name);
static GList *bnet_chat_info(PurpleConnection *gc);
static char *bnet_channel_message_parse(char *stats_data, BnetChatEventFlags flags, int ping);
static PurpleConvChatBuddyFlags bnet_channel_flags_to_prpl_flags(BnetChatEventFlags flags);
static void bnet_join_chat(PurpleConnection *gc, GHashTable *components);
static int bnet_chat_im(PurpleConnection *gc, int chat_id, const char *message, PurpleMessageFlags flags);
const char *bnet_list_icon(PurpleAccount *a, PurpleBuddy *b);
const char *bnet_list_emblem(PurpleBuddy *b);
char *bnet_status_text(PurpleBuddy *b);
void bnet_tooltip_text(PurpleBuddy *buddy,
                       PurpleNotifyUserInfo *info,
                       gboolean full);
char *get_location_text(BnetFriendLocation location, char *location_name);
char *get_product_name(BnetProductID product);
char *get_product_id_str(BnetProductID product);
static GList *bnet_status_types(PurpleAccount *account);
static void bnet_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
static void bnet_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
static PurpleRoomlist *bnet_roomlist_get_list(PurpleConnection *gc);
static void bnet_roomlist_cancel(PurpleRoomlist *list);
static void bnet_set_status(PurpleAccount *account, PurpleStatus *status);
void bnet_set_away(BnetConnectionData *bnet, gboolean new_state, const gchar *message);
void bnet_set_dnd(BnetConnectionData *bnet, gboolean new_state, const gchar *message);
static char *bnet_normalize(const PurpleAccount *account, const char *in);
static char *bnet_d2_normalize(PurpleAccount *account, char *in);
static char *bnet_account_normalize(PurpleAccount *account, char *in);
static gboolean bnet_is_d2(BnetConnectionData *bnet);
static gboolean bnet_is_w3(BnetConnectionData *bnet);
static GList *bnet_actions(PurplePlugin *plugin, gpointer context);
