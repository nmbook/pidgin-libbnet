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

#ifndef _BNET_C_
#define _BNET_C_

#include "bnet.h"

static void
_g_list_free_full(GList *list, GDestroyNotify free_fn)
{
    GList *el = g_list_first(list);
    while (el != NULL) {
        if (el->data != NULL) {
            free_fn(el->data);
        }
        el = g_list_next(el);
    }
    g_list_free(list);
}

static void
bnet_motd_free(BnetConnectionData *bnet, int type)
{
    if (bnet->motds[type].name != NULL) {
        purple_debug_info("bnet", "free motd[%d].name\n", type);
        g_free(bnet->motds[type].name);
        bnet->motds[type].name = NULL;
    }
    if (bnet->motds[type].subname != NULL) {
        purple_debug_info("bnet", "free motd[%d].subname\n", type);
        g_free(bnet->motds[type].subname);
        bnet->motds[type].subname = NULL;
    }
    if (bnet->motds[type].message != NULL) {
        purple_debug_info("bnet", "free motd[%d].message\n", type);
        g_free(bnet->motds[type].message);
        bnet->motds[type].message = NULL;
    }
}

static void
bnet_input_free(struct SocketData *s)
{
    purple_input_remove(s->inpa);
    close(s->fd);
    if (s->inbuf != NULL) {
        g_free(s->inbuf);
    }
    s->inbuf = NULL;
    s->inbuflen = 0;
    s->inbufused = 0;
    s->fd = 0;
}

static void
bnet_channel_user_free(BnetChannelUser *bcu)
{
    if (bcu != NULL) {
        if (bcu->username != NULL)
            g_free(bcu->username);
        if (bcu->stats_data != NULL)
            g_free(bcu->stats_data);
        g_free(bcu);
    }
}

static void
bnet_friend_info_free(BnetFriendInfo *bfi)
{
    if (bfi != NULL) {
        if (bfi->account != NULL)
            g_free(bfi->account);
        if (bfi->location_name != NULL)
            g_free(bfi->location_name);
        if (bfi->away_stored_status != NULL)
            g_free(bfi->away_stored_status);
        if (bfi->dnd_stored_status != NULL)
            g_free(bfi->dnd_stored_status);
        g_free(bfi);
    }
}

static void
bnet_user_free(BnetUser *bu)
{
    if (bu != NULL) {
        switch (bu->type) {
            case BNET_USER_TYPE_CHANNELUSER:
                bnet_channel_user_free((BnetChannelUser *)bu);
                break;
            case BNET_USER_TYPE_FRIEND:
                bnet_friend_info_free((BnetFriendInfo *)bu);
                break;
            case BNET_USER_TYPE_CLANMEMBER:
                bnet_clan_member_free((BnetClanMember *)bu);
                break;
            default:
                g_free(bu);
                break;
        }
    }
}

static void
bnet_buddy_free(PurpleBuddy *buddy)
{
    bnet_user_free(buddy->proto_data);
}

static void
bnet_news_item_free(BnetNewsItem *item)
{
    if (item != NULL) {
        if (item->message != NULL) {
            g_free(item->message);
            item->message = NULL;
        }
        g_free(item);
    }
}

static void
bnet_connect(PurpleAccount *account, const gboolean do_register)
{
    // local vars
    PurpleConnection *gc = NULL;
    BnetConnectionData *bnet = NULL;
    char **userparts = NULL;
    PurpleProxyConnectData *bnls_conn_data = NULL;
    PurpleProxyConnectData *conn_data = NULL;
    const char *username = purple_account_get_username(account);

    // set connection flags
    gc = purple_account_get_connection(account);
    gc->flags |= PURPLE_CONNECTION_NO_BGCOLOR;
    gc->flags |= PURPLE_CONNECTION_AUTO_RESP;
    gc->flags |= PURPLE_CONNECTION_NO_NEWLINES;
    gc->flags |= PURPLE_CONNECTION_NO_FONTSIZE;
    gc->flags |= PURPLE_CONNECTION_NO_URLDESC;
    gc->flags |= PURPLE_CONNECTION_NO_IMAGES;

    // check for invalid characters in name and server
    if (strpbrk(username, " \t\v\r\n") != NULL) {
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
                "Battle.net username or server may not contain whitespace");
        return;
    }

    // create and set up the bnet-specific connection data structure
    gc->proto_data = bnet = g_new0(BnetConnectionData, 1);
    bnet->magic = BNET_UDP_SIG; // for debugging
    bnet->account = account;
    bnet->port = purple_account_get_int(account, "port", BNET_DEFAULT_PORT);
    bnet->bnls_server = g_strdup(purple_account_get_string(account, "bnlsserver", BNET_DEFAULT_BNLSSERVER));
    bnet->bnls_port = BNET_DEFAULT_BNLSPORT;
    bnet->product_id = bnet_clan_string_to_tag(purple_account_get_string(bnet->account, "product", "RATS"));
    if (bnet_is_d2(bnet)) {
        bnet->d2_star = "*";
    } else {
        bnet->d2_star = "";
    }
    bnet->versioning_system = bnet_get_versioningsystem(bnet);
    bnet->versioning_complete = FALSE;
    bnet->logon_system = BNET_LOGON_XSHA1;
    bnet->is_online = FALSE;
    bnet->sent_enter_channel = FALSE;
    bnet->emulate_telnet = (bnet->product_id == BNET_PRODUCT_CHAT);

    bnet->account_create = do_register;

    //bnet->action_q = g_queue_new();

    // save username and server for this connection
    userparts = g_strsplit(username, "@", 2);
    bnet->username = g_strdup(userparts[0]);
    bnet->server = g_strdup(userparts[1]);
    g_strfreev(userparts);

    // set display name
    purple_connection_set_display_name(gc, bnet->username);

    if (bnet->emulate_telnet) {
        // connect to bnet
        purple_debug_info("bnet", "Connecting to (CHAT) %s:%d...\n", bnet->server, bnet->port);
        if (!bnet->account_create) {
            purple_connection_update_progress(gc, "Connecting to Battle.net", BNET_STEP_CONNECTING, BNET_STEP_COUNT);
        }
        conn_data = purple_proxy_connect(gc, account, bnet->server, bnet->port,
                bnet_login_cb, gc);
        if (conn_data == NULL) {
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                    "Unable to connect");
            return;
        }
        bnet->sbncs.conn_data = conn_data;
    } else {
        // begin connections
        purple_debug_info("bnet", "Connecting to BNLS %s:%d...\n", bnet->bnls_server, bnet->bnls_port);
        if (!bnet->account_create) {
            purple_connection_update_progress(gc, "Connecting to BNLS", BNET_STEP_BNLS, BNET_STEP_COUNT);
        }
        bnls_conn_data = purple_proxy_connect(gc, account, bnet->bnls_server, bnet->bnls_port,
                bnet_bnls_login_cb, gc);
        if (bnls_conn_data == NULL) {
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                    "Unable to connect to the BNLS server");
            return;
        }
        bnet->sbnls.conn_data = bnls_conn_data;
    }
}

static void
bnet_login(PurpleAccount *account)
{
    bnet_connect(account, FALSE);
}

static void
bnet_bnls_login_cb(gpointer data, gint source, const gchar *error_message)
{
    PurpleConnection *gc = data;
    BnetConnectionData *bnet = gc->proto_data;

    if (source < 0) {
        gchar *tmp = g_strdup_printf("Unable to connect to BNLS: %s",
                error_message);
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return; 
    }

    purple_debug_info("bnet", "BNLS connected!\n");

    bnet->sbnls.fd = source;

    if (bnet_bnls_send_REQUESTVERSIONBYTE(bnet)) {
        bnet->sbnls.inpa = purple_input_add(bnet->sbnls.fd, PURPLE_INPUT_READ, bnet_bnls_input_cb, gc);
    }
}

/* NO LONGER USED
   static int
   bnet_bnls_send_CHOOSENLSREVISION(const BnetConnectionData *bnet)
   {
   BnetPacket *pkt = NULL;
   int ret = -1;

   pkt = bnet_packet_create(BNET_PACKET_BNLS);
   bnet_packet_insert(pkt, &bnet->logon_system, BNET_SIZE_DWORD);

   ret = bnet_packet_send_bnls(pkt, BNET_BNLS_CHOOSENLSREVISION, bnet->sbnls.fd);

   return ret;
   }
   */

static int
bnet_bnls_send_LOGONCHALLENGE(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    const char *username = bnet->username;
    const char *password = purple_account_get_password(bnet->account);

    pkt = bnet_packet_create(BNET_PACKET_BNLS);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, password, BNET_SIZE_CSTRING);

    ret = bnet_packet_send_bnls(pkt, BNET_BNLS_LOGONCHALLENGE, bnet->sbnls.fd);

    return ret;
}

/* NO LONGER USED
   static int
   bnet_bnls_send_LOGONPROOF(const BnetConnectionData *bnet, const char *s_and_B)
   {
   BnetPacket *pkt = NULL;
   int ret = -1;

   pkt = bnet_packet_create(BNET_PACKET_BNLS);
   bnet_packet_insert(pkt, s_and_B, 64);

   ret = bnet_packet_send_bnls(pkt, BNET_BNLS_LOGONPROOF, bnet->sbnls.fd);

   return ret;
   }
   */

static int
bnet_bnls_send_VERSIONCHECKEX2(const BnetConnectionData *bnet,
        guint32 login_type, guint32 server_cookie, guint32 session_cookie,
        guint64 mpq_ft, char *mpq_fn, char *checksum_formula)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    guint32 bnls_flags = 0;

    pkt = bnet_packet_create(BNET_PACKET_BNLS);
    bnet_packet_insert(pkt, &bnet->game, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &bnls_flags, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &bnls_flags, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &mpq_ft, BNET_SIZE_FILETIME);
    bnet_packet_insert(pkt, mpq_fn, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, checksum_formula, BNET_SIZE_CSTRING);

    ret = bnet_packet_send_bnls(pkt, BNET_BNLS_VERSIONCHECKEX2, bnet->sbnls.fd);

    return ret;
}

static int
bnet_bnls_send_REQUESTVERSIONBYTE(BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    BnetGameType game = 0;

    const BnetProductID product_id = bnet->product_id;

    switch (product_id) {
        default:
        case BNET_PRODUCT_STAR: game = BNET_GAME_TYPE_STAR; break;
        case BNET_PRODUCT_SEXP: game = BNET_GAME_TYPE_SEXP; break;
        case BNET_PRODUCT_W2BN: game = BNET_GAME_TYPE_W2BN; break;
        case BNET_PRODUCT_D2DV: game = BNET_GAME_TYPE_D2DV; break;
        case BNET_PRODUCT_D2XP: game = BNET_GAME_TYPE_D2XP; break;
        case BNET_PRODUCT_JSTR: game = BNET_GAME_TYPE_JSTR; break;
        case BNET_PRODUCT_WAR3: game = BNET_GAME_TYPE_WAR3; break;
        case BNET_PRODUCT_W3XP: game = BNET_GAME_TYPE_W3XP; break;
        case BNET_PRODUCT_DRTL: game = BNET_GAME_TYPE_DRTL; break;
        case BNET_PRODUCT_DSHR: game = BNET_GAME_TYPE_DSHR; break;
        case BNET_PRODUCT_SSHR: game = BNET_GAME_TYPE_SSHR; break;
    }

    bnet->game = game;

    pkt = bnet_packet_create(BNET_PACKET_BNLS);
    bnet_packet_insert(pkt, &game, BNET_SIZE_DWORD);

    ret = bnet_packet_send_bnls(pkt, BNET_BNLS_REQUESTVERSIONBYTE, bnet->sbnls.fd);

    return ret;
}

static void
bnet_bnls_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    PurpleConnection *gc = data;
    BnetConnectionData *bnet = NULL;
    int len = 0;

    g_assert(gc != NULL);

    bnet = gc->proto_data;

    if (bnet->sbnls.inbuflen < bnet->sbnls.inbufused + BNET_INITIAL_BUFSIZE) {
        bnet->sbnls.inbuflen += BNET_INITIAL_BUFSIZE;
        bnet->sbnls.inbuf = g_realloc(bnet->sbnls.inbuf, bnet->sbnls.inbuflen);
    }

    len = read(bnet->sbnls.fd, bnet->sbnls.inbuf + bnet->sbnls.inbufused, bnet->sbnls.inbuflen - bnet->sbnls.inbufused);
    if (len < 0 && errno == EAGAIN) {
        return;
    } else if (len < 0) {
        gchar *tmp = NULL;
        tmp = g_strdup_printf("Lost connection with BNLS server: %s\n",
                g_strerror(errno));
        if (bnet->versioning_complete == FALSE) {
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
            if (bnet->sbncs.fd != 0) {
                bnet_input_free(&bnet->sbncs);
            }
        }
        purple_debug_info("bnet", tmp);
        g_free(tmp);
        if (bnet->sbnls.fd != 0) {
            bnet_input_free(&bnet->sbnls);
        }
        return;
    } else if (len == 0) {
        if (bnet->versioning_complete == FALSE) {
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                    "BNLS server closed the connection\n");
            if (bnet->sbncs.fd != 0) {
                bnet_input_free(&bnet->sbncs);
            }
        }
        purple_debug_info("bnet", "BNLS disconnected.\n");
        if (bnet->sbnls.fd != 0) {
            bnet_input_free(&bnet->sbnls);
        }
        return;
    }

    bnet_bnls_read_input(bnet, len);
}

static void
bnet_bnls_read_input(BnetConnectionData *bnet, int len)
{
    gchar *this_start = NULL;
    guint16 inbuftouse = 0;

    bnet->account->gc->last_received = time(NULL);
    bnet->sbnls.inbufused += len;

    this_start = bnet->sbnls.inbuf;

    while (this_start + 3 <= bnet->sbnls.inbuf + bnet->sbnls.inbufused)
    {
#pragma pack(push)
#pragma pack(1)
        struct {
            guint16 len;
            guint8 id;
        } *header = (void *)this_start;
#pragma pack(pop)
        inbuftouse += header->len;
        if (inbuftouse <= bnet->sbnls.inbufused) {
            bnet_bnls_parse_packet(bnet, header->id, this_start, header->len);
            if (bnet->sbnls.fd == 0) {
                /* the packet parser closed the connection! -- frees everything */
                return;
            }
            this_start += header->len;
        } else break;
    }

    if (this_start != bnet->sbnls.inbuf + bnet->sbnls.inbufused) {
        bnet->sbnls.inbufused -= (this_start - bnet->sbnls.inbuf);
        memmove(bnet->sbnls.inbuf, this_start, bnet->sbnls.inbufused);
    } else {
        bnet->sbnls.inbufused = 0;
    }
}

static void
bnet_bnls_recv_CHOOSENLSREVISION(const BnetConnectionData *bnet, BnetPacket *pkt)
{
    gboolean result = bnet_packet_read_dword(pkt);

    if (result) {
        bnet_bnls_send_LOGONCHALLENGE(bnet);
    }
}

static void
bnet_bnls_recv_LOGONCHALLENGE(const BnetConnectionData *bnet, BnetPacket *pkt)
{
    char *A = (char *)bnet_packet_read(pkt, 32);

    bnet_send_AUTH_ACCOUNTLOGON(bnet, A);

    g_free(A);
}

static void
bnet_bnls_recv_LOGONPROOF(const BnetConnectionData *bnet, BnetPacket *pkt)
{
    char *M1 = (char *)bnet_packet_read(pkt, SHA1_HASH_SIZE);

    bnet_send_AUTH_ACCOUNTLOGONPROOF(bnet, M1);

    g_free(M1);
}

static void
bnet_bnls_recv_REQUESTVERSIONBYTE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    // store version byte
    BnetProductID product_id = bnet_packet_read_dword(pkt);
    PurpleAccount *account = bnet->account;
    PurpleConnection *gc = account->gc;
    PurpleProxyConnectData *conn_data = NULL;

    if (product_id != 0) {
        guint32 version_code = bnet_packet_read_dword(pkt);
        bnet->version_code = version_code;
    }

    // connect to bnet
    purple_debug_info("bnet", "Connecting to Battle.net %s:%d...\n", bnet->server, bnet->port);
    if (!bnet->account_create) {
        purple_connection_update_progress(gc, "Connecting to Battle.net", BNET_STEP_CONNECTING, BNET_STEP_COUNT);
    }
    conn_data = purple_proxy_connect(gc, account, bnet->server, bnet->port,
            bnet_login_cb, gc);
    if (conn_data == NULL) {
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Unable to connect");
        return;
    }
    bnet->sbncs.conn_data = conn_data;
}

static void
bnet_bnls_recv_VERSIONCHECKEX2(BnetConnectionData *bnet, BnetPacket *pkt)
{
    //
    guint32 success = bnet_packet_read_dword(pkt);
    guint32 exe_version = 0;
    guint32 exe_checksum = 0;
    //guint32 cookie = 0; - assigned but not used
    guint32 version_code = 0;
    char *exe_info = NULL;

    bnet->versioning_complete = TRUE;

    if (success == TRUE) {
        exe_version = bnet_packet_read_dword(pkt);
        exe_checksum = bnet_packet_read_dword(pkt);
        exe_info = bnet_packet_read_cstring(pkt);
        /*cookie = */bnet_packet_read_dword(pkt);
        version_code = bnet_packet_read_dword(pkt);
        bnet->version_code = version_code;
        bnet->client_cookie = g_random_int();
        if (bnet->versioning_system == BNET_VERSIONING_AUTH) {
            bnet_send_AUTH_CHECK(bnet,
                    exe_version, exe_checksum, exe_info);
        } else {
            bnet_send_REPORTVERSION(bnet,
                    exe_version, exe_checksum, exe_info);
        }

        g_free(exe_info);
    } else {
        char *tmp = NULL;
        tmp = g_strdup("The BNLS server could says version check failure");
        purple_connection_error_reason(bnet->account->gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                tmp);
        g_free(tmp);
    }
}

static void
bnet_bnls_recv_MESSAGE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    gchar *message = bnet_packet_read_cstring(pkt);
    
    bnet_motd_free(bnet, BNET_MOTD_TYPE_BNLS);
    bnet->motds[BNET_MOTD_TYPE_BNLS].name = NULL;
    bnet->motds[BNET_MOTD_TYPE_BNLS].subname = NULL;
    bnet->motds[BNET_MOTD_TYPE_BNLS].message = message;
}

static void
bnet_bnls_parse_packet(BnetConnectionData *bnet, const guint8 packet_id, const gchar *packet_start, const guint16 packet_len)
{
    BnetPacket *pkt = NULL;

    purple_debug_misc("bnet", "BNLS S>C 0x%02x: length %d\n", packet_id, packet_len);

    pkt = bnet_packet_refer_bnls(packet_start, packet_len);

    switch (packet_id) {
        case BNET_BNLS_LOGONCHALLENGE:
            bnet_bnls_recv_LOGONCHALLENGE(bnet, pkt);
            break;
        case BNET_BNLS_LOGONPROOF:
            bnet_bnls_recv_LOGONPROOF(bnet, pkt);
            break;
        case BNET_BNLS_REQUESTVERSIONBYTE:
            bnet_bnls_recv_REQUESTVERSIONBYTE(bnet, pkt);
            break;
        case BNET_BNLS_VERSIONCHECKEX2:
            bnet_bnls_recv_VERSIONCHECKEX2(bnet, pkt);
            break;
        case BNET_BNLS_CHOOSENLSREVISION:
            bnet_bnls_recv_CHOOSENLSREVISION(bnet, pkt);
            break;
        case BNET_BNLS_MESSAGE:
            bnet_bnls_recv_MESSAGE(bnet, pkt);
            break;
        default:
            // unhandled
            purple_debug_warning("bnet", "Received unhandled BNLS packet 0x%02x, length %d\n", packet_id, packet_len);
            break;
    }

    bnet_packet_free(pkt);
}

static void
bnet_realm_login_cb(gpointer data, gint source, const gchar *error_message)
{
    PurpleConnection *gc = data;
    BnetConnectionData *bnet = gc->proto_data;

    if (source < 0) {
        gchar *tmp = g_strdup_printf("Unable to connect to the D2 realm: %s",
                error_message);
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return; 
    }

    purple_debug_info("bnet", "Realm connected!\n");

    bnet->sd2mcp.fd = source;

    if (bnet_realm_protocol_begin(bnet)) {
        bnet->sd2mcp.inpa = purple_input_add(bnet->sd2mcp.fd, PURPLE_INPUT_READ, bnet_realm_input_cb, gc);
    }
}

static gboolean
bnet_realm_protocol_begin(const BnetConnectionData *bnet)
{
    if (bnet_send_protocol_byte(BNET_PROTOCOL_MCP, bnet->sd2mcp.fd) < 0) {
        return FALSE;
    }

    if (bnet_realm_send_STARTUP(bnet) < 0) {
        return FALSE;
    }

    return TRUE;
}

static int
bnet_realm_send_STARTUP(const BnetConnectionData *bnet)
{
    BnetPacket *pkt;
    int ret = -1;

    int i;
    for (i = 0; i < 16; i++) {
        purple_debug_info("bnet", "MCP value %d = 0x%08x\n", i, bnet->mcp_data[i]);
    }
    pkt = bnet_packet_create(BNET_PACKET_D2MCP);
    for (i = 0; i < 16; i++) {
        bnet_packet_insert(pkt, &bnet->mcp_data[i], BNET_SIZE_DWORD);
    }
    bnet_packet_insert(pkt, bnet->unique_username, BNET_SIZE_CSTRING);
    
    ret = bnet_packet_send_d2mcp(pkt, BNET_D2MCP_STARTUP, bnet->sd2mcp.fd);
    
    return ret;
}

static int
bnet_realm_send_CHARLOGON(const BnetConnectionData *bnet, const gchar *char_name)
{
    BnetPacket *pkt;
    int ret = -1;
    
    pkt = bnet_packet_create(BNET_PACKET_D2MCP);
    bnet_packet_insert(pkt, char_name, BNET_SIZE_CSTRING);
    
    ret = bnet_packet_send_d2mcp(pkt, BNET_D2MCP_CHARLOGON, bnet->sd2mcp.fd);
    
    return ret;
}

static int
bnet_realm_send_MOTD(const BnetConnectionData *bnet)
{
    BnetPacket *pkt;
    int ret = -1;
    
    pkt = bnet_packet_create(BNET_PACKET_D2MCP);
    
    ret = bnet_packet_send_d2mcp(pkt, BNET_D2MCP_MOTD, bnet->sd2mcp.fd);
    
    return ret;
}

static int
bnet_realm_send_CHARLIST2(const BnetConnectionData *bnet, guint32 char_count)
{
    BnetPacket *pkt;
    int ret = -1;
    
    pkt = bnet_packet_create(BNET_PACKET_D2MCP);
    bnet_packet_insert(pkt, &char_count, BNET_SIZE_DWORD);
    
    ret = bnet_packet_send_d2mcp(pkt, BNET_D2MCP_CHARLIST2, bnet->sd2mcp.fd);
    
    return ret;
}

static void
bnet_realm_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    PurpleConnection *gc = data;
    BnetConnectionData *bnet = gc->proto_data;
    int len = 0;

    g_assert(bnet != NULL && bnet->magic == BNET_UDP_SIG);

    if (bnet->sd2mcp.inbuflen < bnet->sd2mcp.inbufused + BNET_INITIAL_BUFSIZE) {
        bnet->sd2mcp.inbuflen += BNET_INITIAL_BUFSIZE;
        bnet->sd2mcp.inbuf = g_realloc(bnet->sd2mcp.inbuf, bnet->sd2mcp.inbuflen);
    }

    len = read(bnet->sd2mcp.fd, bnet->sd2mcp.inbuf + bnet->sd2mcp.inbufused, bnet->sd2mcp.inbuflen - bnet->sd2mcp.inbufused);
    if (len < 0 && errno == EAGAIN) {
        return;
    } else if (len < 0) {
        gchar *tmp = NULL;
        tmp = g_strdup_printf("Lost connection with realm server: %s\n",
                g_strerror(errno));
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        purple_debug_info("bnet", tmp);
        g_free(tmp);
        if (bnet->sd2mcp.fd != 0) {
            bnet_input_free(&bnet->sd2mcp);
        }
        return;
    } else if (len == 0) {
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Server closed the realm connection\n");
        purple_debug_info("bnet", "D2 realm disconnected.\n");
        if (bnet->sd2mcp.fd != 0) {
            bnet_input_free(&bnet->sd2mcp);
        }
        return;
    }

    bnet_realm_read_input(bnet, len);
}

static void
bnet_realm_read_input(BnetConnectionData *bnet, int len)
{
    gchar *this_start = NULL;
    guint16 inbuftouse = 0;

    bnet->account->gc->last_received = time(NULL);
    bnet->sd2mcp.inbufused += len;

    this_start = bnet->sd2mcp.inbuf;

    while (this_start + 3 <= bnet->sd2mcp.inbuf + bnet->sd2mcp.inbufused)
    {
#pragma pack(push)
#pragma pack(1)
        struct {
            guint16 len;
            guint8 id;
        } *header = (void *)this_start;
#pragma pack(pop)
        inbuftouse += header->len;
        if (inbuftouse <= bnet->sd2mcp.inbufused) {
            bnet_realm_parse_packet(bnet, header->id, this_start, header->len);
            if (bnet->sd2mcp.fd == 0) {
                /* the packet parser closed the connection! -- frees everything */
                return;
            }
            this_start += header->len;
        } else break;
    }

    if (this_start != bnet->sd2mcp.inbuf + bnet->sd2mcp.inbufused) {
        bnet->sd2mcp.inbufused -= (this_start - bnet->sd2mcp.inbuf);
        memmove(bnet->sd2mcp.inbuf, this_start, bnet->sd2mcp.inbufused);
    } else {
        bnet->sd2mcp.inbufused = 0;
    }
}

static void
bnet_realm_recv_STARTUP(BnetConnectionData *bnet, BnetPacket *pkt)
{
    BnetRealmStatus status = bnet_packet_read_dword(pkt);
    switch (status) {
        case BNET_REALM_CONNECT_NOBNCS2:
        case BNET_REALM_CONNECT_NOBNCS10:
        case BNET_REALM_CONNECT_NOBNCS11:
        case BNET_REALM_CONNECT_NOBNCS12:
        case BNET_REALM_CONNECT_NOBNCS13:
            // TODO throw error
            // did not detect bncs conn
            purple_debug_warning("bnet", "MCP says you are not on a BNCS server 0x%02x.\n", status);
            break;
        case BNET_REALM_CONNECT_TEMPBAN:
            // TODO throw error
            // temporary ban
            purple_debug_warning("bnet", "MCP says you are temporarily banned from realm play.\n");
            break;
        case BNET_REALM_CONNECT_KEYBAN:
            // TODO throw error
            // key is banned
            purple_debug_warning("bnet", "MCP says your key is banned from realm play.\n");
            break;
        default: // TODO check error
            purple_debug_warning("bnet", "MCP says non-zero success 0x%02x.\n", status);
        case BNET_REALM_SUCCESS:
            // success
            bnet_realm_send_CHARLIST2(bnet, 8);
            break;
    }
}

static void
bnet_realm_recv_CHARLOGON(BnetConnectionData *bnet, BnetPacket *pkt)
{
    BnetRealmStatus status = bnet_packet_read_dword(pkt);
    switch (status) {
        case BNET_REALM_CHAR_PDNE:
            // TODO throw error
            // player does not exist
            purple_debug_warning("bnet", "MCP says player DNE.\n");
            break;
        case BNET_REALM_CHAR_FAILED:
            // TODO throw error
            // logon failed
            purple_debug_warning("bnet", "MCP says logon failed.\n");
            break;
        case BNET_REALM_CHAR_EXPIRED:
            // TODO throw error
            // char expired
            purple_debug_warning("bnet", "MCP says that character is expired.\n");
            break;
        default: // TODO check error
        case BNET_REALM_SUCCESS:
            // success
            bnet_realm_send_MOTD(bnet);
            bnet_send_GETCHANNELLIST(bnet);
            bnet_send_ENTERCHAT(bnet);
            break;
    }
}

static void
bnet_realm_recv_MOTD(BnetConnectionData *bnet, BnetPacket *pkt)
{
    gchar *message;
    
    bnet_packet_read_byte(pkt);
    message = bnet_packet_read_cstring(pkt);
    
    bnet_motd_free(bnet, BNET_MOTD_TYPE_D2MCP);
    bnet->motds[BNET_MOTD_TYPE_D2MCP].name = g_strdup(bnet->mcp_name);
    bnet->motds[BNET_MOTD_TYPE_D2MCP].subname = g_strdup(bnet->mcp_descr);
    bnet->motds[BNET_MOTD_TYPE_D2MCP].message = message;
}

static void
bnet_realm_recv_CHARLIST2(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint16 num_req;
    guint32 num_avail;
    guint16 num_ret;
    int i;
    gchar *auto_logon = g_strdup(purple_account_get_string(bnet->account, "d2realm_char", ""));
    GList *chars = NULL;
    gboolean do_auto_logon = FALSE;
    
    num_req = bnet_packet_read_word(pkt);
    num_avail = bnet_packet_read_dword(pkt);
    num_ret = bnet_packet_read_word(pkt);
    do_auto_logon = (num_ret == 1);
    
    for (i = 0; i < num_ret; i++) {
        guint32 exp_date = bnet_packet_read_dword(pkt);
        gchar *char_name = bnet_packet_read_cstring(pkt);
        gchar *char_stats = bnet_packet_read_cstring(pkt);
        
        // TODO if not auto logon populate dialog
        if (do_auto_logon && strlen(auto_logon) == 0) {
            auto_logon = g_strdup(char_name);
        }
        
        if (strcmp(auto_logon, char_name) == 0) {
            bnet->mcp_char_exp = exp_date;
            bnet->mcp_char = g_strdup(char_name);
            bnet->mcp_char_stats = g_strdup(char_stats);
        }
        
        g_free(char_name);
        g_free(char_stats);
    }
    
    if (do_auto_logon) {
        bnet_realm_send_CHARLOGON(bnet, auto_logon);
    }
    g_free(auto_logon);
}

static void
bnet_realm_parse_packet(BnetConnectionData *bnet, const guint8 packet_id,
            const gchar *packet_start, const guint16 packet_len)
{
    BnetPacket *pkt = NULL;

    purple_debug_misc("bnet", "Realm S>C 0x%02x: length %d\n", packet_id, packet_len);

    pkt = bnet_packet_refer_d2mcp(packet_start, packet_len);

    switch (packet_id) {
        case BNET_D2MCP_STARTUP:
            bnet_realm_recv_STARTUP(bnet, pkt);
            break;
        case BNET_D2MCP_CHARLOGON:
            bnet_realm_recv_CHARLOGON(bnet, pkt);
            break;
        case BNET_D2MCP_MOTD:
            bnet_realm_recv_MOTD(bnet, pkt);
            break;
        case BNET_D2MCP_CHARLIST2:
            bnet_realm_recv_CHARLIST2(bnet, pkt);
            break;
        default:
            // unhandled
            purple_debug_warning("bnet", "Received unhandled realm packet 0x%02x, length %d\n", packet_id, packet_len);
            break;
    }

    bnet_packet_free(pkt);
}

static void
bnet_login_cb(gpointer data, gint source, const gchar *error_message)
{
    PurpleConnection *gc = data;
    BnetConnectionData *bnet = gc->proto_data;

    if (source < 0) {
        gchar *tmp = g_strdup_printf("Unable to connect: %s",
                error_message);
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return; 
    }

    bnet->sbncs.fd = source;
    purple_debug_info("bnet", "BNCS connected!\n");

    if (bnet->emulate_telnet) {
        purple_connection_update_progress(gc, "Authenticating", BNET_STEP_LOGON, BNET_STEP_COUNT);
        if (bnet_protocol_telnet_begin(bnet)) {
            bnet->sbncs.inpa = gc->inpa = purple_input_add(bnet->sbncs.fd, PURPLE_INPUT_READ, bnet_input_cb, gc);
        }
    } else {
        if (!bnet->account_create) {
            purple_connection_update_progress(gc, "Checking product key and version", BNET_STEP_CREV, BNET_STEP_COUNT);
        }

        if (bnet_protocol_begin(bnet)) {
            bnet->sbncs.inpa = gc->inpa = purple_input_add(bnet->sbncs.fd, PURPLE_INPUT_READ, bnet_input_cb, gc);
        }
    }
}

static gboolean
bnet_protocol_telnet_begin(const BnetConnectionData *bnet)
{
    const char *username = bnet->username;
    const char *password = purple_account_get_password(bnet->account);

    if (bnet_send_protocol_byte(BNET_PROTOCOL_CHAT, bnet->sbncs.fd) < 0) {
        return FALSE;
    }

    if (bnet_send_telnet_line(bnet, username) < 0) {
        return FALSE;
    }

    if (bnet_send_telnet_line(bnet, password) < 0) {
        return FALSE;
    }

    return TRUE;
}

static gboolean
bnet_protocol_begin(const BnetConnectionData *bnet)
{
    if (bnet_send_protocol_byte(BNET_PROTOCOL_BNCS, bnet->sbncs.fd) < 0) {
        return FALSE;
    }

    switch (bnet->versioning_system) {
        default:
        case BNET_VERSIONING_AUTH:
            if (bnet_send_AUTH_INFO(bnet) < 0) {
                return FALSE;
            }
            break;
        case BNET_VERSIONING_LEGACY2:
            if (bnet_send_CLIENTID2(bnet) < 0) {
                return FALSE;
            }
            if (bnet_send_LOCALEINFO(bnet) < 0) {
                return FALSE;
            }
            if (bnet_send_STARTVERSIONING(bnet) < 0) {
                return FALSE;
            }
            break;
        case BNET_VERSIONING_LEGACY:
            if (bnet_send_CLIENTID(bnet) < 0) {
                return FALSE;
            }
            if (bnet_send_LOCALEINFO(bnet) < 0) {
                return FALSE;
            }
            if (bnet_send_SYSTEMINFO(bnet) < 0) {
                return FALSE;
            }
            if (bnet_send_STARTVERSIONING(bnet) < 0) {
                return FALSE;
            }
            break;
    }

    return TRUE;
}

static int
bnet_send_telnet_line(const BnetConnectionData *bnet, const char *line)
{
    gsize length = strlen(line);
    gchar tmp_buffer[length + 2];
    int ret = 0;

    g_memmove(tmp_buffer, line, length);
    tmp_buffer[length] = '\r';
    tmp_buffer[length + 1] = '\n';

    ret = write(bnet->sbncs.fd, tmp_buffer, length + 2);

    purple_debug_misc("bnet", "TELNET C>S: %s\n", line);

    return ret;
}

static int
bnet_send_protocol_byte(int byte, int fd)
{
    int ret = write(fd, &byte, 1);

    return ret;
}

static int
bnet_send_NULL(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);

    ret = bnet_packet_send(pkt, BNET_SID_NULL, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_STARTVERSIONING(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    guint32 platform_id = BNET_PLATFORM_IX86;
    BnetProductID product_id = bnet->product_id;
    guint32 version_code = bnet->version_code;
    guint32 zero = 0;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &platform_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &version_code, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_STARTVERSIONING, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_REPORTVERSION(const BnetConnectionData *bnet,
        guint32 exe_version, guint32 exe_checksum, char *exe_info)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    guint32 platform_id = BNET_PLATFORM_IX86;
    BnetProductID product_id = bnet->product_id;
    guint32 version_code = bnet->version_code;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &platform_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &version_code, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &exe_version, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &exe_checksum, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, exe_info, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_REPORTVERSION, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_ENTERCHAT(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    guint8 zero = 0;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, bnet->username, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, &zero, BNET_SIZE_BYTE);

    ret = bnet_packet_send(pkt, BNET_SID_ENTERCHAT, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_GETCHANNELLIST(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &bnet->product_id, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_GETCHANNELLIST, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_JOINCHANNEL(const BnetConnectionData *bnet,
        BnetChannelJoinFlags channel_flags, char *channel)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    guint32 chflags = (guint32)channel_flags;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &chflags, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, channel, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_JOINCHANNEL, bnet->sbncs.fd);

    return ret;
}

/*static int
  bnet_queue_CHATCOMMAND(const BnetConnectionData *bnet, PurpleConversation *conv,
  BnetCommandID cmd, BnetQueueFunc cb, const char *command)
  {
  BnetQueueElement *qel = g_new0(BnetQueueElement, 1);

  qel->conv = conv;
  qel->cmd = cmd;
  qel->pkt_id = BNET_SID_CHATCOMMAND;
  qel->pkt = bnet_packet_create(BNET_PACKET_BNCS);
  qel->pkt_response = BNET_SID_CHATEVENT;
  qel->cookie = 0;
  qel->cb = cb;

  bnet_packet_insert(qel->pkt, command, BNET_SIZE_CSTRING);

  bnet_queue(qel);
  }*/

static int
bnet_send_CHATCOMMAND(const BnetConnectionData *bnet, const char *command)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, command, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_CHATCOMMAND, bnet->sbncs.fd);

    return ret;
}

/* NO LONGER USED
   static int
   bnet_send_LEAVECHAT(const BnetConnectionData *bnet)
   {
   BnetPacket *pkt = NULL;
   int ret = -1;

   pkt = bnet_packet_create(BNET_PACKET_BNCS);

   ret = bnet_packet_send(pkt, BNET_SID_LEAVECHAT, bnet->sbncs.fd);

   return ret;
   }
   */

static int
bnet_send_CDKEY(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    guint32 key_spawn = 0;
    const char *key_owner = purple_account_get_string(bnet->account, "key_owner", "");
    BnetKey *keys = NULL;
    char key_normalized[14];
    gboolean keys_are_valid = FALSE;

    if (strlen(key_owner) == 0) {
        key_owner = bnet->username;
    }

    keys = g_new0(BnetKey, 1);

    keys_are_valid = bnet_key_decode_legacy_verify_only(key_normalized,
            bnet->client_cookie, bnet->server_cookie,
            purple_account_get_string(bnet->account, "key1", ""));

    if (!keys_are_valid) {
        char *tmp = NULL;
        tmp = g_strdup("The provided CD-key could not be decoded.");
        purple_connection_error_reason(bnet->account->gc,
                PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
                tmp);
        g_free(tmp);
        return -1;
    }

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &key_spawn, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, key_normalized, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, key_owner, BNET_SIZE_CSTRING);

    g_free(keys);

    ret = bnet_packet_send(pkt, BNET_SID_CDKEY, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_W3PROFILE(const BnetConnectionData *bnet, const guint32 cookie, const gchar *username)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_W3PROFILE, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CDKEY2(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    guint32 key_spawn = 0;
    const char *key_owner = purple_account_get_string(bnet->account, "key_owner", "");
    BnetKey *keys = NULL;
    gboolean keys_are_valid = FALSE;

    if (strlen(key_owner) == 0) {
        key_owner = bnet->username;
    }

    keys = g_new0(BnetKey, 1);

    keys_are_valid = bnet_key_decode_legacy(keys,
            bnet->client_cookie, bnet->server_cookie,
            purple_account_get_string(bnet->account, "key1", ""));

    if (!keys_are_valid) {
        char *tmp = NULL;
        tmp = g_strdup("The provided CD-key could not be decoded.");
        purple_connection_error_reason(bnet->account->gc,
                PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
                tmp);
        g_free(tmp);
        return -1;
    }

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &key_spawn, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &keys->length, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &keys->product_value, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &keys->public_value, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &bnet->server_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &bnet->client_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, keys->key_hash, SHA1_HASH_SIZE);
    bnet_packet_insert(pkt, key_owner, BNET_SIZE_CSTRING);

    g_free(keys);

    ret = bnet_packet_send(pkt, BNET_SID_CDKEY2, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_LOGONRESPONSE2(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    sha1_context sha;
    guint8 h1[SHA1_HASH_SIZE], h2[SHA1_HASH_SIZE];
    const char *username = bnet->username;
    const char *password = purple_account_get_password(bnet->account);

    sha.version = SHA1_TYPE_BROKEN;
    sha1_reset(&sha);
    sha1_input(&sha, (guint8 *)password, strlen(password));
    sha1_digest(&sha, h1);
    sha1_reset(&sha);
    sha1_input(&sha, (guint8 *)&bnet->client_cookie, BNET_SIZE_DWORD);
    sha1_input(&sha, (guint8 *)&bnet->server_cookie, BNET_SIZE_DWORD);
    sha1_input(&sha, h1, SHA1_HASH_SIZE);
    sha1_digest(&sha, h2);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &bnet->client_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &bnet->server_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, h2, SHA1_HASH_SIZE);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_LOGONRESPONSE2, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CREATEACCOUNT2(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    sha1_context sha;
    guint8 h1[SHA1_HASH_SIZE];
    const char *username = bnet->username;
    const char *password = purple_account_get_password(bnet->account);

    sha.version = SHA1_TYPE_BROKEN;
    sha1_reset(&sha);
    sha1_input(&sha, (const guint8 *)password, strlen(password));
    sha1_digest(&sha, h1);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, h1, SHA1_HASH_SIZE);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_CREATEACCOUNT2, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_LOCALEINFO(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    guint32 tz_bias = 0;
    guint32 system_lang = 1033;
    guint32 product_lang = 1033; // TODO: find pidgin's locale?!
    char *lang_abbr = "ENU";
    char *country_abbr = "USA";
    char *country = "United States";
    char *one = "1";
    time_t t_local, t_utc;
    struct tm *tm_utc = NULL;
    guint64 ft_local, ft_utc;

    t_local = time(NULL);
    tm_utc = gmtime(&t_local);
    t_utc = mktime(tm_utc);

    tz_bias = (guint32)(difftime(t_utc, t_local) / 60.0f);
    ft_utc = bnet_get_filetime(t_utc);
    ft_local = bnet_get_filetime(t_local);

    purple_debug_info("bnet", "tz bias %d\n", tz_bias);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &ft_utc, BNET_SIZE_FILETIME);
    bnet_packet_insert(pkt, &ft_local, BNET_SIZE_FILETIME);
    bnet_packet_insert(pkt, &tz_bias, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &system_lang, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product_lang, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product_lang, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, lang_abbr, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, one, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, country_abbr, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, country, BNET_SIZE_CSTRING);
    ret = bnet_packet_send(pkt, BNET_SID_LOCALEINFO, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLIENTID2(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    int zero = 0;
    const gchar *user = g_get_user_name();
    const gchar *host = g_get_host_name();

    purple_debug_info("bnet", "user %s @ host %s\n", user, host);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // server version 0 or 1
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // reg authority
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // reg version
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // account number
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // registration token
    bnet_packet_insert(pkt, host, BNET_SIZE_CSTRING); // LAN computer name
    bnet_packet_insert(pkt, user, BNET_SIZE_CSTRING); // LAN user name

    ret = bnet_packet_send(pkt, BNET_SID_CLIENTID2, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLIENTID(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    int zero = 0;
    const gchar *user = g_get_user_name();
    const gchar *host = g_get_host_name();

    purple_debug_info("bnet", "user %s @ host %s\n", user, host);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // reg version
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // reg authority
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // account number
    bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD); // registration token
    bnet_packet_insert(pkt, host, BNET_SIZE_CSTRING); // LAN computer name
    bnet_packet_insert(pkt, user, BNET_SIZE_CSTRING); // LAN user name

    ret = bnet_packet_send(pkt, BNET_SID_CLIENTID, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_SYSTEMINFO(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    int zero = 0;
    int i;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    for (i = 0; i < 7; i++) {
        bnet_packet_insert(pkt, &zero, BNET_SIZE_DWORD);
    }

    ret = bnet_packet_send(pkt, BNET_SID_SYSTEMINFO, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_PING(const BnetConnectionData *bnet, guint32 cookie)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_PING, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_READUSERDATA(const BnetConnectionData *bnet,
        int request_cookie, const char *username, char **keys)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    int account_count = 1;
    int key_count = g_strv_length(keys);
    int i = 0;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &account_count, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &key_count, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &request_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);
    for (i = 0; i < key_count; i++) {
        bnet_packet_insert(pkt, keys[i], BNET_SIZE_CSTRING);
    }

    ret = bnet_packet_send(pkt, BNET_SID_READUSERDATA, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_WRITEUSERDATA(const BnetConnectionData *bnet,
        const char *sex, const char *age, const char *location, const char *description)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    int account_count = 1;
    int key_count = 4;
    const char *k_sex = "profile\\sex";
    const char *k_age = "profile\\age";
    const char *k_location = "profile\\location";
    const char *k_description = "profile\\description";

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &account_count, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &key_count, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, bnet->username, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, k_sex, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, k_age, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, k_location, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, k_description, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, sex, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, age, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, location, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, description, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_WRITEUSERDATA, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_LOGONREALMEX(const BnetConnectionData *bnet, const guint32 client_cookie, const guint8 password_hash[SHA1_HASH_SIZE], const gchar *realm_name)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    
    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &client_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, password_hash, SHA1_HASH_SIZE);
    bnet_packet_insert(pkt, realm_name, BNET_SIZE_CSTRING);
    
    ret = bnet_packet_send(pkt, BNET_SID_LOGONREALMEX, bnet->sbncs.fd);
    
    return ret;
}

static int
bnet_send_QUERYREALMS2(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    
    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    
    ret = bnet_packet_send(pkt, BNET_SID_QUERYREALMS2, bnet->sbncs.fd);
    
    return ret;
}

static int
bnet_send_W3GENERAL_USERRECORD(const BnetConnectionData *bnet, guint32 cookie, const gchar *username, BnetProductID product)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    BnetW3GeneralSubcommand subcommand = BNET_WID_USERRECORD;
    
    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &subcommand, BNET_SIZE_BYTE);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, &product, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_W3GENERAL, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_W3GENERAL_CLANRECORD(const BnetConnectionData *bnet, guint32 cookie, BnetClanTag clan_tag, BnetProductID product)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    BnetW3GeneralSubcommand subcommand = BNET_WID_CLANRECORD;
    
    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &subcommand, BNET_SIZE_BYTE);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &clan_tag, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_W3GENERAL, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_NEWS_INFO(const BnetConnectionData *bnet, guint32 news_latest)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &news_latest, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_NEWS_INFO, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_AUTH_INFO(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    guint32 protocol_id = BNET_PROTOCOL_ID;
    guint32 platform_id = BNET_PLATFORM_IX86;
    BnetProductID product_id = bnet->product_id;
    guint32 version_code = bnet->version_code;
    guint32 product_lang = 1033; // TODO: find pidgin's locale?!
    union {
        guint32 as_int32;
        guchar as_arr[4];
    } local_ip;
    guint32 tz_bias = 0;
    guint32 mpq_lang = 1033;
    guint32 system_lang = 1033;
    char *country_abbr = "USA";
    char *country = "United States";

    const char *c_local_ip = purple_network_get_local_system_ip(bnet->sbncs.fd);
    g_memmove(local_ip.as_arr, purple_network_ip_atoi(c_local_ip), 4);

    tz_bias = (guint32)(bnet_get_tz_bias() / 60.0f);

    purple_debug_info("bnet", "local ip %s\n", c_local_ip);
    purple_debug_info("bnet", "tz bias %d\n", tz_bias);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &protocol_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &platform_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product_id, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &version_code, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &product_lang, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &local_ip.as_int32, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &tz_bias, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &mpq_lang, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &system_lang, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, country_abbr, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, country, BNET_SIZE_CSTRING);

    //purple_debug_info("bnet", "send: \n%s\n", bnet_packet_get_all_data(buf));

    ret = bnet_packet_send(pkt, BNET_SID_AUTH_INFO, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_AUTH_CHECK(const BnetConnectionData *bnet,
        guint32 exe_version, guint32 exe_checksum, char *exe_info)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    guint32 key_count = 0;
    guint32 key_spawn = 0;
    const char *key_owner = purple_account_get_string(bnet->account, "key_owner", "");
    BnetKey *keys = NULL;
    int i = 0;
    gboolean keys_are_valid = FALSE;

    if (strlen(key_owner) == 0) {
        key_owner = bnet->username;
    }

    purple_debug_info("bnet", "server cookie: %08x\n", bnet->server_cookie);
    purple_debug_info("bnet", "client cookie: %08x\n", bnet->client_cookie);

    key_count = bnet_get_key_count(bnet);

    keys = g_new0(BnetKey, 2);

    keys_are_valid = bnet_key_decode(keys, key_count,
            bnet->client_cookie, bnet->server_cookie,
            purple_account_get_string(bnet->account, "key1", ""),
            purple_account_get_string(bnet->account, "key2", ""));

    if (!keys_are_valid) {
        const char *exp = "";
        char *tmp = NULL;
        if (keys[0].length > 0) {
            // first key valid, second key must not be then
            exp = "expansion ";
        }
        tmp = g_strdup_printf("The provided %sCD-key could not be decoded.", exp);
        purple_connection_error_reason(bnet->account->gc,
                PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
                tmp);
        g_free(tmp);
        return -1;
    }

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &bnet->client_cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &exe_version, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &exe_checksum, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &key_count, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &key_spawn, BNET_SIZE_DWORD);
    for (; i < key_count; i++) {
        bnet_packet_insert(pkt, &keys[i], sizeof(BnetKey));
    }
    bnet_packet_insert(pkt, exe_info, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, key_owner, BNET_SIZE_CSTRING);

    g_free(keys);

    ret = bnet_packet_send(pkt, BNET_SID_AUTH_CHECK, bnet->sbncs.fd);

    return ret;
}


static int
bnet_send_AUTH_ACCOUNTCREATE(const BnetConnectionData *bnet, char *salt_and_v)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    char *username = bnet->username;

    g_return_val_if_fail(username != NULL, -1);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, salt_and_v, 64);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_AUTH_ACCOUNTCREATE, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_AUTH_ACCOUNTLOGON(const BnetConnectionData *bnet, char *A)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    char *username = bnet->username;

    g_return_val_if_fail(username != NULL, -1);

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, A, 32);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_AUTH_ACCOUNTLOGON, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_AUTH_ACCOUNTLOGONPROOF(const BnetConnectionData *bnet, char *M1)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, M1, SHA1_HASH_SIZE);

    ret = bnet_packet_send(pkt, BNET_SID_AUTH_ACCOUNTLOGONPROOF, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_SETEMAIL(const BnetConnectionData *bnet, const char *email)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, email, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_SETEMAIL, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_FRIENDSLIST(const BnetConnectionData *bnet)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);

    ret = bnet_packet_send(pkt, BNET_SID_FRIENDSLIST, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLANCREATIONINVITATION(const BnetConnectionData *bnet, const int cookie,
        const BnetClanTag clan_tag, const gchar *inviter_name, gboolean accept)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    BnetClanResponseCode response = BNET_CLAN_RESPONSE_DECLINE;
    if (accept) {
        response = BNET_CLAN_RESPONSE_ACCEPT;
    }

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &clan_tag, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, inviter_name, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, &response, BNET_SIZE_BYTE);

    ret = bnet_packet_send(pkt, BNET_SID_CLANCREATIONINVITATION, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLANINVITATIONRESPONSE(const BnetConnectionData *bnet, const int cookie,
        const BnetClanTag clan_tag, const gchar *inviter_name, gboolean accept)
{
    BnetPacket *pkt = NULL;
    int ret = -1;
    BnetClanResponseCode response = BNET_CLAN_RESPONSE_DECLINE;
    if (accept) {
        response = BNET_CLAN_RESPONSE_ACCEPT;
    }

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &clan_tag, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, inviter_name, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, &response, BNET_SIZE_BYTE);

    ret = bnet_packet_send(pkt, BNET_SID_CLANINVITATIONRESPONSE, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLANSETMOTD(const BnetConnectionData *bnet, const int cookie, const gchar *motd)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, motd, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_CLANSETMOTD, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLANMOTD(const BnetConnectionData *bnet, const int cookie)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_CLANMOTD, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLANMEMBERLIST(const BnetConnectionData *bnet, const int cookie)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);

    ret = bnet_packet_send(pkt, BNET_SID_CLANMEMBERLIST, bnet->sbncs.fd);

    return ret;
}

static int
bnet_send_CLANMEMBERINFO(const BnetConnectionData *bnet, const int cookie, const BnetClanTag tag, const gchar *username)
{
    BnetPacket *pkt = NULL;
    int ret = -1;

    pkt = bnet_packet_create(BNET_PACKET_BNCS);
    bnet_packet_insert(pkt, &cookie, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, &tag, BNET_SIZE_DWORD);
    bnet_packet_insert(pkt, username, BNET_SIZE_CSTRING);

    ret = bnet_packet_send(pkt, BNET_SID_CLANMEMBERINFO, bnet->sbncs.fd);

    return ret;
}

static void
bnet_account_logon(BnetConnectionData *bnet)
{
    if (bnet->logon_system == 0) {
        if (bnet->account_create) {
            bnet_send_CREATEACCOUNT2(bnet);
        } else {
            bnet->my_accountname = g_strdup(bnet->username);
            bnet_account_lockout_set(bnet);
            bnet_send_LOGONRESPONSE2(bnet);
        }
    } else {
        const char *username = bnet->username;
        const char *password = purple_account_get_password(bnet->account);
        bnet->account_data = srp_init(username, password);
        if (bnet->account_create) {
            gchar salt_and_v[64];
            srp_generate_salt_and_v(bnet->account_data, salt_and_v);
            bnet_send_AUTH_ACCOUNTCREATE(bnet, salt_and_v);
        } else {
            gchar A[32];
            srp_get_A(bnet->account_data, A);
            bnet->my_accountname = g_strdup(bnet->username);
            bnet_account_lockout_set(bnet);
            bnet_send_AUTH_ACCOUNTLOGON(bnet, A);
        }
    }
}

static void
bnet_enter_channel(const BnetConnectionData *bnet)
{
    bnet_send_JOINCHANNEL(bnet,
            (BnetChannelJoinFlags)
            (BNET_CHANNELJOIN_FIRSTJOIN |
             (bnet_is_d2(bnet) ? BNET_CHANNELJOIN_D2FIRST : 0)), "Lobby");
}

static void
bnet_enter_chat(BnetConnectionData *bnet)
{
    if (bnet_is_d2(bnet)) {
        if (purple_account_get_bool(bnet->account, "use_d2realm", FALSE)) {
            bnet_send_QUERYREALMS2(bnet);
        } else {
            bnet_send_GETCHANNELLIST(bnet);
            bnet_send_ENTERCHAT(bnet);
        }
    } else if (bnet_is_w3(bnet)) {
        bnet->clan_info = bnet_clan_info_new();
        // NETGAMEPORT
        bnet_send_GETCHANNELLIST(bnet);
        bnet_send_ENTERCHAT(bnet);
    } else {
        // UDPPINGRESPONSE
        bnet_send_ENTERCHAT(bnet);
        bnet_send_GETCHANNELLIST(bnet);
        bnet->sent_enter_channel = TRUE;
        bnet_enter_channel(bnet);
        bnet_news_load(bnet);
        bnet_send_NEWS_INFO(bnet, bnet->news_latest);
    }
    bnet_send_FRIENDSLIST(bnet);
}

static int
bnet_realm_logon(const BnetConnectionData *bnet, const guint32 client_cookie,
            const gchar *realm_name, const gchar *realm_pass)
{
    guint8 h1[SHA1_HASH_SIZE];
    guint8 h2[SHA1_HASH_SIZE];
    sha1_context sha;
    
    sha.version = SHA1_TYPE_BROKEN;
    sha1_reset(&sha);
    sha1_input(&sha, (guint8 *)realm_pass, strlen(realm_pass));
    sha1_digest(&sha, h1);
    sha1_reset(&sha);
    sha1_input(&sha, (guint8 *)&client_cookie, BNET_SIZE_DWORD);
    sha1_input(&sha, (guint8 *)&bnet->server_cookie, BNET_SIZE_DWORD);
    sha1_input(&sha, h1, SHA1_HASH_SIZE);
    sha1_digest(&sha, h2);
    
    purple_debug_info("bnet", "MCP Logging on to %s...\n", realm_name);
    
    return bnet_send_LOGONREALMEX(bnet, client_cookie, h2, realm_name);
}

static void
bnet_realm_connect(BnetConnectionData *bnet, struct sockaddr_in mcp_addr,
        const guint32 mcp_data[16], const gchar *bncs_unique_username)
{
    PurpleConnection *gc = bnet->account->gc;
    PurpleProxyConnectData *mcp_conn_data;
    char *addr_name = g_strdup(inet_ntoa(mcp_addr.sin_addr));
    int i;
    
    bnet->mcp_addr = addr_name;
    bnet->mcp_port = mcp_addr.sin_port;
    for (i = 0; i < 16; i++) {
        bnet->mcp_data[i] = mcp_data[i];
    }
    bnet->unique_username = g_strdup(bncs_unique_username);
    
    purple_debug_info("bnet", "Connecting to MCP %s:%d...\n", addr_name, mcp_addr.sin_port);
    mcp_conn_data = purple_proxy_connect(gc, bnet->account, addr_name, mcp_addr.sin_port,
            bnet_realm_login_cb, gc);
    if (mcp_conn_data == NULL) {
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Unable to connect to the MCP server");
        return;
    }
    bnet->sd2mcp.conn_data = mcp_conn_data;
}

static gboolean
bnet_keepalive_timer(BnetConnectionData *bnet)
{
    //purple_debug_info("bnet", "keepalive tick\n");
    // keep alive every 30 seconds
    bnet->ka_tick++;
    //purple_debug_info("bnet", "keepalive %d\n", bnet->ka_tick);

    if (bnet->emulate_telnet) {
        // blank line: every 8 minutes
        if ((bnet->ka_tick % 16) == 0) {
            bnet_send_telnet_line(bnet, "");
        }
    } else {
        // SID_NULL: every 8 minutes
        if ((bnet->ka_tick % 16) == 0) {
            bnet_send_NULL(bnet);
        }

        // SID_FRIENDSLIST: every 1 minute
        if ((bnet->ka_tick % 2) == 0) {
            bnet_send_FRIENDSLIST(bnet);
        }

        if (bnet->clan_info != NULL && bnet_clan_info_get_tag(bnet->clan_info) != 0) {
            // SID_CLANMEMBERLIST; every 2 minutes, alternating with FRIENDSLIST and CLANMOTD
            if ((bnet->ka_tick % 4) == 1) {
                int memblist_cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_CLANMEMBERLIST, NULL);
                bnet_send_CLANMEMBERLIST(bnet, memblist_cookie);
            }

            // SID_MOTD; every 2 minutes, alternating with FRIENDSLIST and CLANMEMBERLIST
            if ((bnet->ka_tick % 4) == 3) {
                int motd_cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_CLANMOTD, NULL);
                bnet_send_CLANMOTD(bnet, motd_cookie);
            }
        }
    }

    return TRUE;
}

static void
bnet_account_lockout_set(BnetConnectionData *bnet)
{
    bnet->alo_handle = purple_timeout_add_seconds(10, (GSourceFunc)bnet_account_lockout_timer, bnet);
}

static void
bnet_account_lockout_cancel(BnetConnectionData *bnet)
{
    if (bnet->alo_handle != 0) {
        purple_timeout_remove(bnet->alo_handle);
        bnet->alo_handle = 0;
    }
}

static gboolean
bnet_account_lockout_timer(BnetConnectionData *bnet)
{
    purple_connection_error_reason(bnet->account->gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
            "Logging on is taking too long. You are likely locked out of this account. Try again in 30 minutes.");

    purple_timeout_remove(bnet->alo_handle);
    bnet->alo_handle = 0;
    
    return FALSE;
}

static void
bnet_account_register(PurpleAccount *account)
{
    purple_debug_info("bnet", "REGISTER ACCOUNT REQUEST");
    bnet_connect(account, TRUE);
}

static void
bnet_account_chpw(PurpleConnection *gc, const char *oldpass, const char *newpass)
{
    BnetConnectionData *bnet = gc->proto_data;

    purple_debug_info("bnet", "CHANGE PASSWORD REQUEST");
    bnet->change_pw = TRUE;
    bnet->change_pw_from = g_strdup(oldpass);
    bnet->change_pw_to = g_strdup(newpass);
}

static void
bnet_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    PurpleConnection *gc = data;
    BnetConnectionData *bnet = gc->proto_data;
    int len = 0;

    g_assert(bnet != NULL && bnet->magic == BNET_UDP_SIG);

    if (bnet->sbncs.inbuflen < bnet->sbncs.inbufused + BNET_INITIAL_BUFSIZE) {
        bnet->sbncs.inbuflen += BNET_INITIAL_BUFSIZE;
        bnet->sbncs.inbuf = g_realloc(bnet->sbncs.inbuf, bnet->sbncs.inbuflen);
    }

    len = read(bnet->sbncs.fd, bnet->sbncs.inbuf + bnet->sbncs.inbufused, bnet->sbncs.inbuflen - bnet->sbncs.inbufused);
    if (len < 0 && errno == EAGAIN) {
        return;
    } else if (len < 0) {
        gchar *tmp = NULL;
        tmp = g_strdup_printf("Lost connection with server: %s\n",
                g_strerror(errno));
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        purple_debug_info("bnet", tmp);
        g_free(tmp);
        if (bnet->sbncs.fd != 0) {
            bnet_input_free(&bnet->sbncs);
        }
        return;
    } else if (len == 0) {
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Server closed the connection\n");
        purple_debug_info("bnet", "BNCS disconnected.\n");
        if (bnet->sbncs.fd != 0) {
            bnet_input_free(&bnet->sbncs);
        }
        return;
    }

    if (bnet->emulate_telnet) {
        bnet_read_telnet_input(bnet, len);
    } else {
        bnet_read_input(bnet, len);
    }
}

static void
bnet_read_telnet_input(BnetConnectionData *bnet, int len)
{
    gchar *this_start = NULL;
    gchar *this_end = NULL;
    guint16 this_len = len;

    bnet->account->gc->last_received = time(NULL);
    bnet->sbncs.inbufused += len;

    this_start = bnet->sbncs.inbuf;
    g_assert(this_start != NULL);
    this_len = len;
    while (this_start + 2 <= bnet->sbncs.inbuf + bnet->sbncs.inbufused) {
        this_end = g_strstr_len(this_start, this_len, "\r\n");
        if (this_end != NULL) {
            this_len = this_end - this_start;
            *this_end = '\0';
            bnet_parse_telnet_line(bnet, this_start);
            if (bnet->sbncs.fd == 0) {
                /* the packet parser closed the connection! -- frees everything */
                return;
            }
            this_start += this_len + 2;
            this_len = len - this_len - 2;
        } else break;
    }

    if (this_start == bnet->sbncs.inbuf) {
        /* no full lines */
    } else if (this_start != bnet->sbncs.inbuf + bnet->sbncs.inbufused) {
        /* found at least one full lines, but ended with a partial line */
        bnet->sbncs.inbufused -= (this_start - bnet->sbncs.inbuf);
        memmove(bnet->sbncs.inbuf, this_start, bnet->sbncs.inbufused);
    } else {
        /* found at least one full line, no more data left in buffer */
        bnet->sbncs.inbufused = 0;
    }
}

static void
bnet_read_input(BnetConnectionData *bnet, int len)
{
    gchar *this_start = NULL;
    guint16 inbuftouse = 0;

    bnet->account->gc->last_received = time(NULL);
    bnet->sbncs.inbufused += len;

    this_start = bnet->sbncs.inbuf;

    while (this_start + 4 <= bnet->sbncs.inbuf + bnet->sbncs.inbufused) {
#pragma pack(push)
#pragma pack(1)
        struct {
            guint8 flag;
            guint8 id;
            guint16 len;
        } *header = (void *)this_start;
#pragma pack(pop)
        inbuftouse += header->len;
        g_assert(header->len != BNET_IDENT_FLAG);
        if (inbuftouse <= bnet->sbncs.inbufused) {
            bnet_parse_packet(bnet, header->id, this_start, header->len);
            if (bnet->sbncs.fd == 0) {
                /* the packet parser closed the connection! -- frees everything */
                return;
            }
            this_start += header->len;
        } else break;
    }

    if (this_start == bnet->sbncs.inbuf) {
        /* no full packets */
    } else if (this_start != bnet->sbncs.inbuf + bnet->sbncs.inbufused) {
        /* found at least one full packet, but ended with a partial packet */
        bnet->sbncs.inbufused -= (this_start - bnet->sbncs.inbuf);
        memmove(bnet->sbncs.inbuf, this_start, bnet->sbncs.inbufused);
    } else {
        /* found at least one full packet, no more data left in buffer */
        bnet->sbncs.inbufused = 0;
    }
}

/* this method would do nothing as all fields received are defunct
   static void
   bnet_recv_CLIENTID(BnetConnectionData *bnet, BnetPacket *pkt)
   {
   }*/

static void
bnet_recv_STARTVERSIONING(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint64 mpq_ft = bnet_packet_read_qword(pkt);
    char* mpq_fn = bnet_packet_read_cstring(pkt);
    char* checksum_formula = bnet_packet_read_cstring(pkt);

    bnet_bnls_send_VERSIONCHECKEX2(bnet,
            bnet->logon_system, bnet->server_cookie, bnet->session_cookie, mpq_ft, mpq_fn, checksum_formula);

    g_free(mpq_fn);
    g_free(checksum_formula);
}

static void
bnet_recv_REPORTVERSION(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);
    char *extra_info = bnet_packet_read_cstring(pkt);

    PurpleConnection *gc = bnet->account->gc;

    char *tmp = NULL;
    char *tmpe = NULL;
    char *tmpf = NULL;

    PurpleConnectionError conn_error = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;

    switch (result) {
        case BNET_REPORTVERS_SUCCESS:
            {
                int key_count = bnet_get_key_count(bnet);

                bnet->versioning_complete = TRUE;            
                purple_debug_info("bnet", "Version check passed!\n");

                if (key_count > 0) {
                    switch (bnet->versioning_system) {
                        case BNET_VERSIONING_LEGACY:
                            bnet_send_CDKEY(bnet);
                            break;
                        case BNET_VERSIONING_LEGACY2:
                            bnet_send_CDKEY2(bnet);
                            break;
                        default:
                            purple_debug_fatal("bnet", "Received SID_REPORTVERSION during AUTH logon sequence. Key required for this product. Unknown next packet. Logging on to account instead.");

                            if (!bnet->account_create) {
                                purple_connection_update_progress(gc, "Authenticating", BNET_STEP_LOGON, BNET_STEP_COUNT);
                            }

                            bnet_account_logon(bnet);
                            break;
                    }
                } else {
                    if (!bnet->account_create) {
                        purple_connection_update_progress(gc, "Authenticating", BNET_STEP_LOGON, BNET_STEP_COUNT);
                    }

                    bnet_account_logon(bnet);
                }
                g_free(extra_info);
                return;
            }
        case BNET_REPORTVERS_FAILED:
            tmp = "Version check failed%s.";
            break;
        case BNET_REPORTVERS_OLD:
            tmp = "Old version%s.";
            break;
        case BNET_REPORTVERS_INVALID:
            tmp = "Version invalid%s.";
            break;
        default:
            tmp = "Version check failed%s.";
            break;
    }

    tmpe = g_strdup_printf(" (%s)", extra_info);
    tmpf = g_strdup_printf(tmp, strlen(extra_info) > 0 ? tmpe : "");
    purple_connection_error_reason(gc, conn_error, tmpf);

    g_free(tmpe);
    g_free(tmpf);

    g_free(extra_info);
}

static void
bnet_recv_ENTERCHAT(BnetConnectionData *bnet, BnetPacket *pkt)
{
    char *unique_username = bnet_packet_read_cstring(pkt);
    char *statstring = bnet_packet_read_cstring(pkt);
    char *account = bnet_packet_read_cstring(pkt);

    if (bnet->my_accountname != NULL) {
        g_free(bnet->my_accountname);
    }
    bnet->my_statstring = statstring;
    bnet->my_accountname = account;
    bnet->unique_username = unique_username;

    if (bnet_is_d2(bnet) || bnet_is_w3(bnet)) {
        // reset news count
        bnet_news_load(bnet);
        bnet_send_NEWS_INFO(bnet, bnet->news_latest);
    }
}

static void
bnet_recv_GETCHANNELLIST(BnetConnectionData *bnet, BnetPacket *pkt)
{
    char *channel = NULL;

    while (TRUE) {
        channel = bnet_packet_read_cstring(pkt);
        if (channel == NULL) {
            break;
        } else if (strlen(channel) == 0) {
            g_free(channel);
            break;
        }
        bnet->channel_list = g_list_prepend(bnet->channel_list, channel);
    }

    bnet->channel_list = g_list_reverse(bnet->channel_list);
}

static char *
bnet_locale_to_utf8(const char *input)
{
    char *output = NULL;

    // no error
    if (input == NULL) return g_strdup("");

    if (g_utf8_validate(input, -1, NULL)) {
        return g_strdup(input);
    } else {
        GError *err = NULL;
        output = g_convert_with_fallback(input, -1, "UTF-8", "ISO-8859-1", NULL, NULL, NULL, &err);
        if (err != NULL) {
            purple_debug_error("bnet", "Unable to convert to UTF-8 from ISO-8859-1: %s\n", err->message);
            if (output == NULL) {
                output = g_strdup(err->message);
            }
            g_error_free(err);
            return output;
        }
    }

    return output;
}

static char *
bnet_locale_from_utf8(const char *input)
{
    GError *err = NULL;
    char *output = g_convert_with_fallback(input, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL, &err);
    if (err != NULL) {
        purple_debug_error("bnet", "Unable to convert to ISO-8859-1 from UTF-8: %s\n", err->message);
        if (output == NULL) {
            output = g_strdup(err->message);
        }
        g_error_free(err);
        return output;
    }

    return output;
}

static void
bnet_recv_event_SHOWUSER(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    GList *li = NULL;

    li = g_list_find_custom(bnet->channel_users, name, bnet_channel_user_compare);
    if (li != NULL) {
        // user stats update
        BnetChannelUser *bcu = li->data;

        bcu->flags = flags;
        bcu->ping = ping;
        if (strlen(text) > 0) {
            g_free(bcu->stats_data);
            bcu->stats_data = g_strdup(text);
        }
        if (chat != NULL) {
            purple_conv_chat_user_set_flags(chat, name,
                    bnet_channel_flags_to_prpl_flags(flags));
        }
    } else {
        // new user
        gchar *name_normal = NULL;
        gchar *my_unique_username = NULL;
        BnetChannelUser *bcu = g_new0(BnetChannelUser, 1);

        bcu->type = BNET_USER_TYPE_CHANNELUSER;
        bcu->username = g_strdup(name);
        bcu->stats_data = g_strdup(text);
        bcu->flags = flags;
        bcu->ping = ping;
        bcu->hidden = FALSE;
        bnet->channel_users = g_list_append(bnet->channel_users, bcu);
        if (bnet->channel_seen_self) {
            if (chat != NULL) {
                gchar *channel_message = bnet_channel_message_parse(bcu->stats_data, flags, ping);
                purple_conv_chat_add_user(chat, name,
                        channel_message,
                        bnet_channel_flags_to_prpl_flags(flags), FALSE);
            }
        }

        name_normal = g_strdup(bnet_normalize(bnet->account, name));
        my_unique_username = g_strdup(bnet_normalize(bnet->account, bnet->unique_username));
        if (strcmp(name_normal, my_unique_username) == 0 && !bnet->channel_seen_self) {
            //purple_debug_info("bnet", "join channel complete\n");
            GList *users = NULL;
            GList *extras = NULL;
            GList *flags = NULL;
            GList *el = g_list_first(bnet->channel_users);

            bnet->channel_seen_self = TRUE;
            //int i = 0;
            while (el != NULL) {
                BnetChannelUser *bcuel = el->data;
                int bcuelflags = bnet_channel_flags_to_prpl_flags(bcuel->flags);

                users = g_list_prepend(users, bcuel->username);
                extras = g_list_prepend(extras, bnet_channel_message_parse(bcuel->stats_data, bcuel->flags, bcuel->ping));
                flags = g_list_prepend(flags, GINT_TO_POINTER(bcuelflags));
                //i++;
                //purple_debug_info("bnet", "%d: %s status: %d\n", i, bcuel->username, bcuel->status);
                el = g_list_next(el);
            }
            if (bnet->channel_first_join) {
                bnet->channel_first_join = FALSE;
            } else {
                PurpleConversation *conv;

                conv = serv_got_joined_chat(gc, bnet->channel_id, bnet->channel_name);
                if (conv != NULL) {
                    chat = purple_conversation_get_chat_data(conv);
                }
                if (chat != NULL) {
                    if (bnet->clan_info != NULL && bnet_clan_info_get_tag(bnet->clan_info) != 0) {
                        if (bnet_clan_is_clan_channel(bnet->clan_info, bnet->channel_name)) {
                            gchar *motd = bnet->motds[BNET_MOTD_TYPE_CLAN].message;
                            purple_conv_chat_set_topic(chat, "(clan leader)", motd);
                        }
                    }
                    purple_conv_chat_add_users(chat, users, extras, flags, FALSE);
                }
            }
            g_list_free(users);
            _g_list_free_full(extras, g_free);
            g_list_free(flags);
        }
        g_free(name_normal);
        g_free(my_unique_username);
    }
}

static void
bnet_recv_event_JOIN(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    BnetChannelUser *bcu = NULL;

    bcu = g_new0(BnetChannelUser, 1);
    bcu->type = BNET_USER_TYPE_CHANNELUSER;
    bcu->username = g_strdup(name);
    bcu->stats_data = g_strdup(text);
    bcu->flags = flags;
    bcu->ping = ping;
    bcu->hidden = FALSE;
    bnet->channel_users = g_list_append(bnet->channel_users, bcu);

    if (chat != NULL) {
        gchar *channel_message = bnet_channel_message_parse(bcu->stats_data, flags, ping);
        purple_conv_chat_add_user(chat, name,
                channel_message,
                bnet_channel_flags_to_prpl_flags(flags), TRUE);
        g_free(channel_message);
    }
}

static void
bnet_recv_event_LEAVE(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    GList *li;

    li = g_list_find_custom(bnet->channel_users, name, bnet_channel_user_compare);
    if (li != NULL) {
        bnet->channel_users = g_list_delete_link(bnet->channel_users, li);
    }
    if (chat != NULL) {
        purple_conv_chat_remove_user(chat, name, NULL);
    }
}

static gchar *
bnet_escape_text(const gchar *text, int length, gboolean replace_linebreaks)
{
    gchar *tmp1 = purple_markup_escape_text(text, length);
    
    if (g_str_has_suffix(tmp1, "\n")) {
        tmp1[strlen(tmp1) - 1] = '\0';
    }

    if (replace_linebreaks) {
        gchar *tmp2 = purple_strdup_withhtml(tmp1);
        g_free(tmp1);
        
        return tmp2;
    } else {
        return tmp1;
    }
}

static void
bnet_recv_event_WHISPER(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    gboolean prpl_level_ignore = FALSE;

    if (strlen(text) > 0) {
        GError *err = NULL;
        GMatchInfo *mi = NULL;
        GRegex *regex = NULL;
        const char *name_gateway_normalize = bnet_gateway_normalize(bnet->account, name);

        //////////////////////////
        // MUTUAL FRIEND STATUS //
        char *regex_str = g_strdup_printf("Your friend %s (?:has entered Battle\\.net|has exited Battle\\.net|entered a (?:.+) game called (?:.+))\\.",
                g_regex_escape_string(name_gateway_normalize, -1));

        regex = g_regex_new(regex_str, 0, 0, &err);

        if (err != NULL) {
            purple_debug_warning("bnet", "regex create failed: %s\n", err->message);
            g_error_free(err);
        } else if (g_regex_match(regex, text, 0, &mi) &&
                !purple_account_get_bool(bnet->account, "showmutual", FALSE)) {
            prpl_level_ignore = TRUE;
        }
        g_match_info_free(mi);
        g_regex_unref(regex);
    }

    if (!prpl_level_ignore) {
        gchar *esc_text;
        esc_text = bnet_escape_text(text, -1, FALSE);
        serv_got_im(gc, name, esc_text, PURPLE_MESSAGE_RECV, time(NULL));
        g_free(esc_text);
    }

    //if (bnet->is_away) {
    // our "auto-response" is sent by BNET if we are away
    // but we don't see it, so lets just show it anyway
    // because we can.
    //serv_got_im(gc, bnet->unique_username, bnet->away_msg,
    //        PURPLE_MESSAGE_AUTO_RESP | PURPLE_MESSAGE_RECV, time(NULL));
    // isn't working as intended >:/
    //}
}

static void
bnet_recv_event_TALK(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    gchar *esc_text;

    esc_text = bnet_escape_text(text, -1, FALSE);
    serv_got_chat_in(gc, bnet->channel_id, name, PURPLE_MESSAGE_RECV, esc_text, time(NULL));
    g_free(esc_text);
}

static void
bnet_recv_event_BROADCAST(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    if (chat != NULL) {
        gchar *esc_text;
        esc_text = bnet_escape_text(text, -1, FALSE);
        purple_conv_chat_write(chat, name, esc_text, PURPLE_MESSAGE_SYSTEM, time(NULL));
        g_free(esc_text);
    }
}

static void
bnet_recv_event_CHANNEL(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    const gchar *text_normalized;
    int chat_id;
    const char *norm = NULL;
    int trying_chat_id = 0;

    bnet->channel_seen_self = FALSE;

    // if libpurple thinks we're in a channel, leave it
    if (!bnet->channel_first_join && bnet->channel_id != 0) {
        if (chat != NULL) {    
            purple_conv_chat_write(chat, "Battle.net",
                    "You have left this chat channel. Battle.net only allows being in one channel at any time.", PURPLE_MESSAGE_SYSTEM, time(NULL));
        }
        serv_got_chat_left(gc, bnet->channel_id);
    }

    // clear the user list
    if (bnet->channel_users != NULL) {
        _g_list_free_full(bnet->channel_users, (GDestroyNotify)bnet_channel_user_free);
        bnet->channel_users = NULL;
    }

    // generate chat ID
    text_normalized = bnet_normalize(bnet->account, text);
    chat_id = g_str_hash(text_normalized);

    // in clan, we are going to join clan's home instead
    /*if (bnet->clan_info != NULL) {
        bnet->channel_first_join = FALSE;
    }*/

    // the PvPGN check...
    /*if (bnet->channel_first_join && strcmp("lobby", norm) == 0) {
        bnet->channel_first_join = FALSE;
    }*/

    // the only way to get out of channel_first_join now is to actually have *tried* to join this channel
    if (bnet->joining_channel != NULL) {
        norm = bnet_normalize(bnet->account, bnet->joining_channel);
        trying_chat_id = g_str_hash(norm);
        if (trying_chat_id == chat_id) {
            bnet->channel_first_join = FALSE;
            g_free(bnet->joining_channel);
            bnet->joining_channel = NULL;
        }
    }

    // store current channel data
    g_free(bnet->channel_name);
    bnet->channel_id = chat_id;
    bnet->channel_name = g_strdup(text);
    bnet->channel_flags = flags;

    // if we're in our own clan channel, we'll get a EID_INFO with our motd
    // here we make sure that our motd
    // 1. gets displayed to the chat,
    // 2. does not get handled as a normal event
    // imagine the fun someone could have by setting their clan motd to "You were kicked out of the channel by X."
    if (bnet->clan_info != NULL &&
            bnet_clan_info_get_tag(bnet->clan_info) != 0 &&
            bnet_clan_is_clan_channel(bnet->clan_info, bnet->channel_name)) {
        bnet->got_channel_motd = FALSE;
    }

    // the silent channel check: we don't get ourself in one case, when we are in a silent channel
    if ((bnet->channel_flags & BNET_CHAN_FLAG_SILENT) == BNET_CHAN_FLAG_SILENT) {
        bnet->channel_first_join = FALSE;
        g_free(bnet->joining_channel);
        bnet->joining_channel = NULL;
        serv_got_joined_chat(gc, chat_id, text);
    }
}


static void
bnet_recv_event_USERFLAGS(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    if (chat != NULL) {
        GList *li = g_list_find_custom(bnet->channel_users, name, bnet_channel_user_compare);
        if (li != NULL) {
            BnetChannelUser *bcu = li->data;
            bcu->flags = flags;
            bcu->ping = ping;
            if (strlen(text) > 0) {
                g_free(bcu->stats_data);
                bcu->stats_data = g_strdup(text);
            }
        }

        purple_conv_chat_user_set_flags(chat, name,
                bnet_channel_flags_to_prpl_flags(flags));
    }
}

static void
bnet_recv_event_WHISPERSENT(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    if (bnet->last_sent_to != NULL) {
        bnet->awaiting_whisper_confirm = FALSE;
    }
    if (strcmp(name, "your friends") == 0) {
        PurpleConnection *gc = bnet->account->gc;
        gchar *esc_text = bnet_escape_text(text, -1, FALSE);
        serv_got_chat_in(gc, bnet->channel_id, name, PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_WHISPER, esc_text, time(NULL));
        g_free(esc_text);
    }
}

static void
bnet_recv_event_CHANNELFULL(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    //PurpleConnection *gc = bnet->account->gc;
    purple_debug_info("bnet", "CHANNEL IS FULL %s %x %dms: %s\n",
            name, flags, ping, text);

    //purple_serv_got_join_chat_failed(gc, bnet->join_attempt);
}

static void
bnet_recv_event_CHANNELDOESNOTEXIST(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    //PurpleConnection *gc = bnet->account->gc;
    purple_debug_info("bnet", "CHANNEL DOES NOT EXIST %s %x %dms: %s\n",
            name, flags, ping, text);

    //purple_serv_got_join_chat_failed(gc, bnet->join_attempt);
}

static void
bnet_recv_event_CHANNELRESTRICTED(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    //PurpleConnection *gc = bnet->account->gc;
    purple_debug_info("bnet", "CHANNEL IS RESTRICTED %s %x %dms: %s\n",
            name, flags, ping, text);

    //purple_serv_got_join_chat_failed(gc, bnet->join_attempt);
}

static gboolean
bnet_recv_event_INFO_whois(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    gboolean handled = FALSE;
    PurpleBuddy *b;

    gchar *whois_user = g_match_info_fetch(mi, 1);
    gchar *whois_product = g_match_info_fetch(mi, 2);
    gchar *whois_location = g_match_info_fetch(mi, 3);
    const gchar *whois_user_n = NULL;

    whois_user_n = bnet_d2_normalize(bnet->account, whois_user);

    b = purple_find_buddy(bnet->account, whois_user_n);
    if (b != NULL) {
        BnetUser *bfi = purple_buddy_get_protocol_data(b);
        if (bfi != NULL) {
            if (bfi->type == BNET_USER_TYPE_FRIEND) {
                if (((BnetFriendInfo *)bfi)->automated_lookup) {
                    handled = TRUE;
                }
            }
        }
    }

    if (!handled && (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_WHOIS)) {
        handled = TRUE;

        bnet->lookup_info_got_locprod = TRUE;
        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_WHOIS;
        // allow away and dnd messages to be captured too
        // bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES;

        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            if (!bnet->lookup_info) {
                bnet->lookup_info = purple_notify_user_info_new();
            } else if (!bnet->lookup_info_first_section) {
                purple_notify_user_info_add_section_break(bnet->lookup_info);
            }
            bnet->lookup_info_first_section = FALSE;

            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current location", whois_location);
            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current product", whois_product);

            if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc, whois_user_n,
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }

            purple_debug_info("bnet", "Lookup complete: WHOIS(%s) [allowing WHOIS_STATUSES_*]\n", bnet->lookup_info_user);
        } else {
            purple_debug_info("bnet", "Lookup complete: WHOIS([freed]) [allowing WHOIS_STATUSES_*]\n");
        }

    }

    g_free(whois_user);
    g_free(whois_product);
    g_free(whois_location);

    return handled;
}

static gboolean
bnet_recv_event_INFO_away_response(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    PurpleConnection *gc = bnet->account->gc;
    gboolean handled = FALSE;
    PurpleBuddy *b;

    gchar *away_user = g_match_info_fetch(mi, 1);
    gchar *away_msg = g_match_info_fetch(mi, 2);
    const gchar *away_user_n = NULL;

    if (strlen(away_user) == 0) {
        g_free(away_user);
        away_user = g_strdup(bnet->unique_username);
    }

    away_user_n = bnet_d2_normalize(bnet->account, away_user);

    b = purple_find_buddy(bnet->account, away_user_n);
    if (b != NULL) {
        BnetUser *bfi = purple_buddy_get_protocol_data(b);
        if (bfi != NULL) {
            if (bfi->type == BNET_USER_TYPE_FRIEND) {
                ((BnetFriendInfo *)bfi)->away_stored_status = g_strdup(away_msg);
                if (((BnetFriendInfo *)bfi)->automated_lookup & BNET_FRIEND_STATUS_AWAY) {
                    handled = TRUE;
                    ((BnetFriendInfo *)bfi)->automated_lookup &= ~BNET_FRIEND_STATUS_AWAY;
                }
            }
        }

        purple_debug_info("bnet", "purple_prpl_got_user_status for %s\n", away_user_n);
        purple_prpl_got_user_status(bnet->account, away_user_n,
                BNET_STATUS_AWAY, "message", g_strdup(away_msg), NULL);
    }

    if (!handled && (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES_AWAY)) {
        handled = TRUE;

        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES_AWAY;
        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            if (!bnet->lookup_info) {
                bnet->lookup_info = purple_notify_user_info_new();
            } else if (!bnet->lookup_info_first_section) {
                purple_notify_user_info_add_section_break(bnet->lookup_info);
            }
            bnet->lookup_info_first_section = FALSE;

            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Away", away_msg);

            /*if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc,
                        bnet_d2_normalize(bnet->account, away_user_n),
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }*/
            purple_debug_info("bnet", "Lookup complete: WHOIS_STATUSES_AWAY(%s)\n", bnet->lookup_info_user);
        } else {
            purple_debug_info("bnet", "Lookup complete: WHOIS_STATUSES_AWAY([freed])\n");
        }
    }

    if (!handled && bnet->last_sent_to != NULL) {
        PurpleConversation *conv = 
            purple_find_conversation_with_account(
                    PURPLE_CONV_TYPE_IM, bnet->last_sent_to, bnet->account);
        if (conv) {
            PurpleConvIm *im = purple_conversation_get_im_data(conv);
            if (im) {
                char *tmp = g_strdup_printf("Away (%s)", away_msg);
                handled = TRUE;
                // this is our "auto-response"
                serv_got_im(gc, away_user_n, tmp,
                        PURPLE_MESSAGE_AUTO_RESP, time(NULL));
                g_free(tmp);
            }
        }

        bnet->awaiting_whisper_confirm = FALSE;
    }

    g_free(away_user);
    g_free(away_msg);

    return handled;
}

static gboolean
bnet_recv_event_INFO_dnd_response(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    gboolean handled = FALSE;
    PurpleBuddy *b;

    gchar *dnd_user = g_match_info_fetch(mi, 1);
    gchar *dnd_msg = g_match_info_fetch(mi, 2);
    const gchar *dnd_user_n = NULL;

    if (strlen(dnd_user) == 0) {
        g_free(dnd_user);
        dnd_user = g_strdup(bnet->unique_username);
    }

    dnd_user_n = bnet_d2_normalize(bnet->account, dnd_user);

    b = purple_find_buddy(bnet->account, dnd_user_n);
    if (b != NULL) {
        BnetUser *bfi = purple_buddy_get_protocol_data(b);
        if (bfi != NULL) {
            if (bfi->type == BNET_USER_TYPE_FRIEND) {
                ((BnetFriendInfo *)bfi)->dnd_stored_status = g_strdup(dnd_msg);
                if (((BnetFriendInfo *)bfi)->automated_lookup & BNET_FRIEND_STATUS_DND) {
                    handled = TRUE;
                    ((BnetFriendInfo *)bfi)->automated_lookup &= ~BNET_FRIEND_STATUS_DND;
                }
            }
        }

        purple_debug_info("bnet", "purple_prpl_got_user_status for %s\n", dnd_user_n);
        purple_prpl_got_user_status(bnet->account, dnd_user_n,
                BNET_STATUS_DND, "message", g_strdup(dnd_msg), NULL);
    }

    if (!handled && (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES_DND)) {
        handled = TRUE;

        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_WHOIS_STATUSES_DND;
        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            if (!bnet->lookup_info) {
                bnet->lookup_info = purple_notify_user_info_new();
            } else if (!bnet->lookup_info_first_section) {
                purple_notify_user_info_add_section_break(bnet->lookup_info);
            }
            bnet->lookup_info_first_section = FALSE;

            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Do Not Disturb", dnd_msg);

            /*if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc,
                        bnet_d2_normalize(bnet->account, dnd_user_n),
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }*/
            purple_debug_info("bnet", "Lookup complete: WHOIS_STATUSES_DND(%s)\n", bnet->lookup_info_user);
        } else {
            purple_debug_info("bnet", "Lookup complete: WHOIS_STATUSES_DND([freed])\n");
        }
    }

    g_free(dnd_user);
    g_free(dnd_msg);

    return handled;
}

static gboolean
bnet_recv_event_INFO_away_state(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    gboolean handled = FALSE;

    gchar *away_state_string = g_match_info_fetch(mi, 1);

    if (strcmp(away_state_string, "still") == 0) {
        if (bnet->last_sent_to != NULL) {
            PurpleConversation *conv = 
                purple_find_conversation_with_account(
                        PURPLE_CONV_TYPE_IM, bnet->last_sent_to, bnet->account);
            if (conv) {
                PurpleConvIm *im = purple_conversation_get_im_data(conv);
                if (im) {
                    handled = TRUE;
                    purple_conv_im_write(im, "Battle.net", text, PURPLE_MESSAGE_SYSTEM, time(NULL));
                }
            }
        }
    } else {
        bnet->is_away = (strcmp(away_state_string, "now") == 0);

        if (bnet->setting_away_status) {
            handled = TRUE;
            bnet->setting_away_status = FALSE;
        }
    }

    g_free(away_state_string);
    
    return handled;
}

static gboolean
bnet_recv_event_INFO_dnd_state(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    gboolean handled = FALSE;

    gchar *dnd_state_string = g_match_info_fetch(mi, 1);
    bnet->is_dnd = (strcmp(dnd_state_string, "engaged") == 0);

    if (bnet->setting_dnd_status) {
        handled = TRUE;
        bnet->setting_dnd_status = FALSE;
    }

    g_free(dnd_state_string);

    return handled;
}

static gboolean
bnet_recv_event_INFO_dnd_error(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    PurpleConnection *gc = bnet->account->gc;
    gboolean handled = FALSE;

    if (bnet->last_sent_to != NULL) {
        handled = TRUE;
        if (!purple_conv_present_error(bnet->last_sent_to, bnet->account, text)) {
            gchar *tmp = g_strdup_printf("%s did not receive your whisper.", bnet->last_sent_to);
            purple_notify_error(gc, "Do Not Disturb", text, tmp);
            g_free(tmp);
        }

        bnet->awaiting_whisper_confirm = FALSE;
    }

    return handled;
}

static gboolean
bnet_recv_event_INFO_ban(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    gboolean handled = FALSE;

    if (!purple_account_get_bool(bnet->account, "showbans", FALSE)) {
        // hide it!
        handled = TRUE;
    }

    return handled;
}

static void
bnet_recv_event_INFO(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    gboolean regex_matched = FALSE;
    gboolean show_in_chat = TRUE;

    if (strlen(text) > 0) {
        int i = 0;

        if (bnet->clan_info != NULL &&
                bnet_clan_info_get_tag(bnet->clan_info) != 0 &&
                bnet_clan_is_clan_channel(bnet->clan_info, bnet->channel_name) &&
                bnet->motds[BNET_MOTD_TYPE_CLAN].message != NULL &&
                strcmp(text, bnet->motds[BNET_MOTD_TYPE_CLAN].message) == 0 &&
                !bnet->got_channel_motd) {
            regex_matched = TRUE;
            bnet->got_channel_motd = TRUE;
        }

        while (bnet_regex_store[i].regex != NULL) {
            GRegex *regex = bnet_regex_store[i].regex;
            GMatchInfo *mi = NULL;

            if (regex_matched) {
                break;
            }

            if (bnet_regex_store[i].event_id == BNET_EID_INFO) {
                if (g_regex_match(regex, text, 0, &mi)) {
                    show_in_chat = !bnet_regex_store[i].fn(bnet, regex, text, mi);
                    regex_matched = TRUE;
                }
                if (mi != NULL) {
                    g_match_info_free(mi);
                    mi = NULL;
                }
            }

            i++;
        }

        if (show_in_chat) {
            gchar *esc_text = bnet_escape_text(text, -1, FALSE);
            if (bnet->last_command_conv != NULL) {
                PurpleConversation *conv = bnet->last_command_conv;
                PurpleConvIm *im = purple_conversation_get_im_data(conv);
                if (im) {
                    purple_conv_im_write(im, "Battle.net", esc_text, PURPLE_MESSAGE_SYSTEM, time(NULL));
                } else if (chat) {
                    purple_conv_chat_write(chat, "Battle.net", esc_text, PURPLE_MESSAGE_SYSTEM, time(NULL));
                } else {
                    purple_notify_info(gc, "Information", text, NULL);
                }
            } else if (chat) {
                purple_conv_chat_write(chat, "Battle.net", esc_text, PURPLE_MESSAGE_SYSTEM, time(NULL));
            } else {
                //bnet->welcome_msgs = g_list_append(bnet->welcome_msgs, text);
            }
        }
    }
}

static void
bnet_recv_event_ERROR(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    gboolean handled = FALSE;

    ////////////////////////
    // WHISPERS AND WHOIS //
    if (strcmp(text, "That user is not logged on.") == 0) {
        if (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_WHOIS) {
            handled = TRUE;

            bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_WHOIS;
            if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
                if (!bnet->lookup_info) {
                    bnet->lookup_info = purple_notify_user_info_new();
                } else if (!bnet->lookup_info_first_section) {
                    purple_notify_user_info_add_section_break(bnet->lookup_info);
                }
                bnet->lookup_info_first_section = FALSE;

                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current location", "Offline");

                bnet->lookup_info_got_locprod = TRUE;

                if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                    purple_notify_userinfo(gc,
                            bnet_d2_normalize(bnet->account, bnet->lookup_info_user),
                            bnet->lookup_info, bnet_lookup_info_close, bnet);
                }
                purple_debug_info("bnet", "Lookup complete: WHOIS(%s)\n", bnet->lookup_info_user);
            } else {
                purple_debug_info("bnet", "Lookup complete: WHOIS([freed])\n");
            }
        }

        if (!handled && bnet->last_sent_to != NULL) {
            handled = TRUE;
            if (!purple_conv_present_error(bnet->last_sent_to, bnet->account, text)) {
                purple_notify_error(gc, "Not logged in", text,
                        g_strdup_printf("%s did not receive your whisper.", bnet->last_sent_to));
            }

            bnet->awaiting_whisper_confirm = FALSE;
        }
    }


    /////////////////////////
    // UNHANDLED EID_ERROR //
    if (!handled) {
        gchar *esc_text = bnet_escape_text(text, -1, FALSE);
        if (bnet->last_command_conv) {
            PurpleConversation *conv = bnet->last_command_conv;
            PurpleConvIm *im = purple_conversation_get_im_data(conv);
            if (im) {
                purple_conv_im_write(im, "Battle.net", esc_text, PURPLE_MESSAGE_ERROR, time(NULL));
            } else if (chat) {
                purple_conv_chat_write(chat, "Battle.net", esc_text, PURPLE_MESSAGE_ERROR, time(NULL));
            } else {
                purple_notify_info(gc, "Error", text, NULL);
            }
        } else if (chat) {
            purple_conv_chat_write(chat, "Battle.net", esc_text, PURPLE_MESSAGE_ERROR, time(NULL));
        } else {
            purple_notify_error(gc, "Error", text, NULL);
        }
    }
}

static void
bnet_recv_event_EMOTE(BnetConnectionData *bnet, PurpleConvChat *chat,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    PurpleConnection *gc = bnet->account->gc;
    gchar *esc_text;
    gchar *emote_text;

    if (strlen(text) == 0) {
        emote_text = g_strdup("/me ");
    } else {
        esc_text = bnet_escape_text(text, -1, FALSE);
        emote_text = g_strdup_printf("/me %s", esc_text);
        g_free(esc_text);
    }

    serv_got_chat_in(gc, bnet->channel_id, name, 
            ((strcmp(bnet->unique_username, name) == 0) ?
             PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV),
            emote_text, time(NULL));
    g_free(emote_text);
}

static void
bnet_recv_event(BnetConnectionData *bnet, PurpleConvChat *chat, BnetChatEventID event_id,
        const gchar *name, const gchar *text, BnetChatEventFlags flags, gint32 ping)
{
    if (event_id < BNET_EID_SHOWUSER || event_id > BNET_EID_EMOTE || bnet_events[event_id].id == 0) {
        purple_debug_warning("bnet", "Received unhandled event 0x%02x: \"%s\" 0x%04x %dms: %s \n", event_id, name, flags, ping, text);
    } else {
        struct BnetChatEvent ev = bnet_events[event_id];
        purple_debug_misc("bnet", "Event 0x%02x: \"%s\" 0x%04x %dms: %s\n", event_id, name, flags, ping, text);
        if (!bnet->emulate_telnet && !ev.text_is_statstring) {
            gchar *text_utf8;
            text_utf8 = bnet_locale_to_utf8(text);
            ev.fn(bnet, chat, name, text_utf8, flags, ping);
            g_free(text_utf8);
        } else {
            ev.fn(bnet, chat, name, text, flags, ping);
        }
    }
}

static void
bnet_entered_chat(BnetConnectionData *bnet)
{
    PurpleConnection *gc = bnet->account->gc;
    PurplePresence *pres = NULL;
    PurpleStatus *status = NULL;

    bnet->is_online = TRUE;
    bnet->channel_first_join = TRUE;
    bnet->channel_seen_self = FALSE;

    bnet->ka_handle = purple_timeout_add_seconds(30, (GSourceFunc)bnet_keepalive_timer, bnet);

    purple_connection_set_state(gc, PURPLE_CONNECTED);

    pres = purple_account_get_presence(bnet->account);
    status = purple_presence_get_active_status(pres);
    bnet_set_status(bnet->account, status);
}

static void
bnet_recv_CHATEVENT(BnetConnectionData *bnet, BnetPacket *pkt)
{
    BnetChatEventID id = 0;
    BnetChatEventFlags flags = 0;
    gint32 ping = 0;
    char *name = NULL;
    char *text = NULL;

    PurpleConnection *gc = bnet->account->gc;
    PurpleConversation *conv = NULL;
    PurpleConvChat *chat = NULL;
    char *name_d2n = NULL;

    if (!bnet->is_online) {
        bnet_entered_chat(bnet);
    }
    if (!bnet->channel_first_join && bnet->channel_id != 0) {
        conv = purple_find_chat(gc, bnet->channel_id);
    }
    if (conv != NULL) {
        chat = purple_conversation_get_chat_data(conv);
    }

    id = bnet_packet_read_dword(pkt);
    flags = bnet_packet_read_dword(pkt);
    ping = bnet_packet_read_dword(pkt);
    bnet_packet_read_dword(pkt); // defunct
    bnet_packet_read_dword(pkt); // defunct
    bnet_packet_read_dword(pkt); // defunct
    name = bnet_packet_read_cstring(pkt);
    text = bnet_packet_read_cstring(pkt);

    /* so that users don't see other users as D2 names on D2 */
    name_d2n = g_strdup(bnet_d2_normalize(bnet->account, name));

    bnet_recv_event(bnet, chat, id, name_d2n, text, flags, ping);

    g_free(name);
    g_free(name_d2n);
    g_free(text);
}

static void
bnet_recv_MESSAGEBOX(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 style = bnet_packet_read_dword(pkt);
    char *text = bnet_packet_read_cstring(pkt);
    char *caption = bnet_packet_read_cstring(pkt);
    char *title = NULL;
    const char *title_type = NULL;

    //PurpleConnection *gc = bnet->account->gc;

    if (style & 0x00000010L) { // error
        title_type = "error";
    } else if (style & 0x00000030L) { // warning
        title_type = "warning";
    } else { // info, question, or nothing
        title_type = "info";
    }
    
    title = g_strdup_printf("Battle.net %s: %s", title_type, caption);
    purple_notify_error(bnet, title, text, NULL);
    g_free(title);
    g_free(caption);
    g_free(text);
}

static void
bnet_recv_LOGONCHALLENGEEX(BnetConnectionData *bnet, BnetPacket *pkt)
{
    bnet->session_cookie = bnet_packet_read_dword(pkt);
    bnet->server_cookie = bnet_packet_read_dword(pkt);
}

static void
bnet_recv_PING(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 cookie = bnet_packet_read_dword(pkt);

    // echo
    bnet_send_PING(bnet, cookie);
}

static void
bnet_recv_READUSERDATA(BnetConnectionData *bnet, BnetPacket *pkt)
{
    // readuserdata
    guint32 key_count, request_cookie/*, account_count*/;
    int i, j;
    /*account_count = */bnet_packet_read_dword(pkt); // always 1
    key_count = bnet_packet_read_dword(pkt);
    request_cookie = bnet_packet_read_dword(pkt);

    for (i = 0; i < g_list_length(bnet->userdata_requests); i++) {
        BnetUserDataRequest *req = g_list_nth_data(bnet->userdata_requests, i);
        if (bnet_userdata_request_get_cookie(req) == request_cookie) {
            GHashTable *userdata = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
            gboolean showing_lookup_dialog = FALSE;
            BnetUserDataRequestType request_type = bnet_userdata_request_get_type(req);
            char *pstr = NULL;
            gchar *esc_text = NULL;

            for (j = 0; j < key_count; j++) {
                g_hash_table_insert(userdata,
                        bnet_userdata_request_get_key_by_index(req, j),
                        bnet_packet_read_cstring(pkt));
            }

            if (!bnet->writing_profile &&
                    bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_USER_DATA) {
                bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_USER_DATA;
                if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
                    showing_lookup_dialog = TRUE;

                    if (!bnet->lookup_info) {
                        bnet->lookup_info = purple_notify_user_info_new();
                    } else if (!bnet->lookup_info_first_section) {
                        purple_notify_user_info_add_section_break(bnet->lookup_info);
                    }
                    bnet->lookup_info_first_section = FALSE;
                    purple_debug_info("bnet", "Lookup complete: USER_DATA(%s)\n", bnet->lookup_info_user);
                } else {
                    purple_debug_info("bnet", "Lookup complete: USER_DATA([freed])\n");
                }
            }

            if (request_type & BNET_READUSERDATA_REQUEST_PROFILE) {
                if (bnet->writing_profile) {
                    const char *psex = g_hash_table_lookup(userdata, "profile\\sex");
                    const char *page = g_hash_table_lookup(userdata, "profile\\age");
                    const char *ploc = g_hash_table_lookup(userdata, "profile\\location");
                    const char *pdescr = g_hash_table_lookup(userdata, "profile\\description");
                    bnet_profile_show_write_dialog(bnet, psex, page, ploc, pdescr);
                } else if (showing_lookup_dialog) {
                    char *pstr_utf8 = NULL;
                    int section_count = 0;

                    // profile\sex
                    pstr = g_hash_table_lookup(userdata, "profile\\sex");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        pstr_utf8 = bnet_locale_to_utf8(pstr);
                        esc_text = bnet_escape_text(pstr_utf8, -1, TRUE);
                        purple_notify_user_info_add_pair(bnet->lookup_info, "Profile sex", esc_text);
                        g_free(esc_text);
                        g_free(pstr_utf8);
                        section_count++;
                    }

                    // profile\age
                    pstr = g_hash_table_lookup(userdata, "profile\\age");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        pstr_utf8 = bnet_locale_to_utf8(pstr);
                        esc_text = bnet_escape_text(pstr_utf8, -1, TRUE);
                        purple_notify_user_info_add_pair(bnet->lookup_info, "Profile age", esc_text);
                        g_free(esc_text);
                        g_free(pstr_utf8);
                        section_count++;
                    }

                    // profile\location
                    pstr = g_hash_table_lookup(userdata, "profile\\location");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        pstr_utf8 = bnet_locale_to_utf8(pstr);
                        esc_text = bnet_escape_text(pstr_utf8, -1, TRUE);
                        purple_notify_user_info_add_pair(bnet->lookup_info, "Profile location", esc_text);
                        g_free(esc_text);
                        g_free(pstr_utf8);
                        section_count++;
                    }

                    // profile\description
                    pstr = g_hash_table_lookup(userdata, "profile\\description");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        pstr_utf8 = bnet_locale_to_utf8(pstr);
                        esc_text = bnet_escape_text(pstr_utf8, -1, TRUE);
                        purple_notify_user_info_add_pair(bnet->lookup_info, "Profile description", esc_text);
                        g_free(esc_text);
                        g_free(pstr_utf8);
                        section_count++;
                    }

                    if (section_count == 0) {
                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Profile", 
                                "No information is stored in this user's profile.");
                    }
                }
            }

            if (request_type & BNET_READUSERDATA_REQUEST_SYSTEM) {
                if (showing_lookup_dialog) {
                    gboolean is_section = FALSE;

                    // System\Time Logged
                    pstr = g_hash_table_lookup(userdata, "System\\Time Logged");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        gchar *str_sec = bnet_format_strsec(pstr);
                        if (!is_section) {
                            purple_notify_user_info_add_section_break(bnet->lookup_info);
                            is_section = TRUE;
                        }

                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Account time logged", str_sec);
                        g_free(str_sec);
                    }

                    // System\Account Created
                    pstr = g_hash_table_lookup(userdata, "System\\Account Created");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        gchar *str_time = bnet_format_filetime_string(pstr);
                        if (!is_section) {
                            purple_notify_user_info_add_section_break(bnet->lookup_info);
                            is_section = TRUE;
                        }

                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Account creation time", str_time);
                        g_free(str_time);
                    }

                    // System\Last Logoff
                    pstr = g_hash_table_lookup(userdata, "System\\Last Logoff");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        gchar *str_time = bnet_format_filetime_string(pstr);
                        if (!is_section) {
                            purple_notify_user_info_add_section_break(bnet->lookup_info);
                            is_section = TRUE;
                        }

                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Account last logged off", str_time);
                        g_free(str_time);
                    }

                    // System\Last Logon
                    pstr = g_hash_table_lookup(userdata, "System\\Last Logon");
                    if (pstr != NULL && strlen(pstr) > 0) {
                        gchar *str_time = bnet_format_filetime_string(pstr);
                        if (!is_section) {
                            purple_notify_user_info_add_section_break(bnet->lookup_info);
                            is_section = TRUE;
                        }

                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Account last logged on", str_time);
                        g_free(str_time);
                    }
                }
            }

            if (request_type & BNET_READUSERDATA_REQUEST_RECORD) {
                if (showing_lookup_dialog) {
                    gboolean is_section = FALSE;

                    for (j = 0; j < 4; j++) {
                        char *zero = "0";
                        char *key; char *prpl_key; char *prpl_val;
                        char *wins; char *losses; char *discs; char *lgame; char *lgameres;
                        char *rating; char *hrating; char *rank; char *hrank;
                        char *header_text = NULL;
                        char *product_id = bnet_get_product_id_str(bnet_userdata_request_get_product(req));
                        char *product = bnet_get_product_name(bnet_userdata_request_get_product(req));

                        switch (j) {
                            case 0: header_text = "Normal"; break;
                            case 1: header_text = "Ladder"; break;
                            case 3: header_text = "IronMan"; break;
                        }

                        key = g_strdup_printf("Record\\%s\\%d\\wins", product_id, j);
                        wins = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, wins);
                        g_free(key);
                        key = g_strdup_printf("Record\\%s\\%d\\losses", product_id, j);
                        losses = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, losses);
                        g_free(key);
                        key = g_strdup_printf("Record\\%s\\%d\\disconnects", product_id, j);
                        discs = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, discs);
                        g_free(key);
                        key = g_strdup_printf("Record\\%s\\%d\\last game", product_id, j);
                        lgame = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, lgame);
                        g_free(key);
                        key = g_strdup_printf("Record\\%s\\%d\\last game result", product_id, j);
                        lgameres = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, lgameres);
                        g_free(key);

                        if (wins != NULL && losses != NULL && discs != NULL &&
                                lgame != NULL && lgameres != NULL) {
                            if (!is_section) {
                                purple_notify_user_info_add_section_break(bnet->lookup_info);
                                is_section = TRUE;
                            }

                            if (strlen(wins) == 0) wins = zero;
                            if (strlen(losses) == 0) losses = zero;
                            if (strlen(discs) == 0) discs = zero;
                            if (strlen(lgame) == 0 || strcmp(lgameres, "NONE") == 0) {
                                lgame = "never";
                            } else {
                                char *tmp = bnet_format_filetime_string(lgame);
                                lgame = g_strdup_printf("%s on %s", lgameres, tmp);
                                g_free(tmp);
                            }

                            prpl_key = g_strdup_printf("%s record for %s", header_text, product);
                            prpl_val = g_strdup_printf("%s-%s-%s", wins, losses, discs);
                            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                            g_free(prpl_key);
                            g_free(prpl_val);

                            prpl_key = g_strdup_printf("Last %s game", header_text);
                            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, lgame);
                            g_free(prpl_key);
                        }

                        key = g_strdup_printf("Record\\%s\\%d\\rating", product_id, j);
                        rating = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, rating);
                        g_free(key);
                        key = g_strdup_printf("Record\\%s\\%d\\high rating", product_id, j);
                        hrating = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, hrating);
                        g_free(key);
                        key = g_strdup_printf("DynKey\\%s\\%d\\rank", product_id, j);
                        rank = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, rank);
                        g_free(key);
                        key = g_strdup_printf("Record\\%s\\%d\\high rank", product_id, j);
                        hrank = g_hash_table_lookup(userdata, key);
                        purple_debug_info("bnet", "key: %s  value: %s\n", key, hrank);
                        g_free(key);

                        if (rating != NULL && hrating != NULL &&
                                rank != NULL && hrank != NULL) {

                            if (!is_section) {
                                purple_notify_user_info_add_section_break(bnet->lookup_info);
                                is_section = TRUE;
                            }

                            if (strlen(rating) == 0) rating = zero;
                            if (strlen(hrating) == 0) hrating = zero;
                            if (strlen(rank) == 0) rank = zero;
                            if (strlen(hrank) == 0) hrank = zero;

                            prpl_key = g_strdup_printf("%s rating", header_text);
                            prpl_val = g_strdup_printf("%s (high: %s)", rating, hrating);
                            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                            g_free(prpl_key);
                            g_free(prpl_val);

                            prpl_key = g_strdup_printf("%s rank", header_text);
                            prpl_val = g_strdup_printf("%s (high: %s)", rank, hrank);
                            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                            g_free(prpl_key);
                            g_free(prpl_val);
                        }
                    }
                }
            }

            if (showing_lookup_dialog) {
                if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                    purple_notify_userinfo(bnet->account->gc,
                            bnet_d2_normalize(bnet->account, bnet->lookup_info_user),
                            bnet->lookup_info, bnet_lookup_info_close, bnet);
                }
            }

            bnet->userdata_requests = g_list_remove(bnet->userdata_requests, req);

            g_hash_table_destroy(userdata);

            bnet_userdata_request_free(req);
        }
    }
}

static void
bnet_recv_LOGONCHALLENGE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    bnet->server_cookie = bnet_packet_read_dword(pkt);
}

static void
bnet_recv_CDKEY(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);
    char *extra_info = bnet_packet_read_cstring(pkt);

    PurpleConnection *gc = bnet->account->gc;

    char *tmp = NULL;
    char *tmpe = NULL;
    char *tmpf = NULL;

    PurpleConnectionError conn_error = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;

    switch (result) {
        case BNET_CDKEY_SUCCESS:
            {
                bnet->versioning_complete = TRUE;

                purple_debug_info("bnet", "Key check passed!\n");

                if (!bnet->account_create) {
                    purple_connection_update_progress(gc, "Authenticating", BNET_STEP_LOGON, BNET_STEP_COUNT);
                }

                bnet_account_logon(bnet);

                g_free(extra_info);
                return;
            }
        case BNET_CDKEY_INVALID:
            tmp = "CD-key invalid%s.";
            break;
        case BNET_CDKEY_BADPRODUCT:
            tmp = "CD-key is for another game%s.";
            break;
        case BNET_CDKEY_BANNED:
            tmp = "CD-key is banned%s.";
            break;
        case BNET_CDKEY_INUSE:
            tmp = "CD-key is in use%s.";
            break;
        default:
            tmp = "CD-key invalid%s.";
            break;
    }

    tmpe = g_strdup_printf(" (%s)", extra_info);
    tmpf = g_strdup_printf(tmp, strlen(extra_info) > 0 ? tmpe : "");
    purple_connection_error_reason(gc, conn_error, tmpf);

    g_free(tmpe);
    g_free(tmpf);

    g_free(extra_info);
}

static void
bnet_recv_W3PROFILE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 cookie;
    BnetClanResponseCode status;
    BnetClanTag tag = (BnetClanTag) 0;
    gchar *s_clan = NULL;
    gchar *username = NULL;
    
    cookie = bnet_packet_read_dword(pkt);
    status = bnet_packet_read_byte(pkt);
    username = bnet_clan_packet_unregister(bnet->clan_info, BNET_SID_W3PROFILE, cookie);

    if (username == NULL) {
        username = strdup("");
    }

    switch (status) {
        case BNET_CLAN_RESPONSE_SUCCESS:
            /* location = */bnet_packet_read_cstring(pkt);
            /* description = */bnet_packet_read_cstring(pkt);
            tag = bnet_packet_read_dword(pkt);
            bnet->lookup_info_found_clan = TRUE;
            break;
        default:
            purple_debug_warning("bnet", "Error retrieving profile for %s: status code 0x%02x\n", username, status);
            break;
    }

    s_clan = bnet_clan_tag_to_string(tag);

    if (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_W3_USER_PROFILE) {
        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_W3_USER_PROFILE;
        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            //if (g_strcmp(bnet->lookup_info_user, username) == 0) { -- do this check if we use W3PROFILE for anything else
            purple_debug_info("bnet", "Lookup complete: W3_USER_PROFILE(%s)\n", bnet->lookup_info_user);
            
            // step 4b.2: get user data we won't get via SID_W3PROFILE: profile\sex, system\*...
            bnet_lookup_info_user_data(bnet);
            // step 4a.3: get W3 stats (await SID_WARCRAFTGENERAL.WID_USERRESPONSE response)
            bnet_lookup_info_w3_user_stats(bnet);
            if (tag != (BnetClanTag) 0) {
                bnet->lookup_info_clan = tag;
                // step 4a.4: get clan stats (await SID_WARCRAFTGENERAL.WID_CLANRECORD response)
                bnet_lookup_info_w3_clan_stats(bnet);
                // step 4a.5: get clan member join date (await SID_CLANMEMBERINFO response)
                bnet_lookup_info_w3_clan_mi(bnet);
            }
            if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }
        } else {
            purple_debug_info("bnet", "Lookup complete: W3_USER_PROFILE([freed])\n");
        }
    } else {
        purple_debug_warning("bnet", "Not waiting for 0x35 SID_W3PROFILE\n");
    }

    g_free(s_clan);
    g_free(username);
}

static void
bnet_recv_CDKEY2(BnetConnectionData *bnet, BnetPacket *pkt)
{
    bnet_recv_CDKEY(bnet, pkt);
}

static const gchar *
bnet_get_w3record_type_string(BnetW3RecordType type)
{
    switch (type) {
        case BNET_W3RECORD_USER_SOLO:
            return "Solo";
        case BNET_W3RECORD_USER_TEAM:
            return "Team";
        case BNET_W3RECORD_USER_FFA:
            return "FFA";
        case BNET_W3RECORD_TEAM_2VS2:
            return "Arranged 2 vs 2";
        case BNET_W3RECORD_TEAM_3VS3:
            return "Arranged 3 vs 3";
        case BNET_W3RECORD_TEAM_4VS4:
            return "Arranged 4 vs 4";
        case BNET_W3RECORD_CLAN_SOLO:
            return "Clan Solo";
        case BNET_W3RECORD_CLAN_2VS2:
            return "Clan 2 vs 2";
        case BNET_W3RECORD_CLAN_3VS3:
            return "Clan 3 vs 3";
        case BNET_W3RECORD_CLAN_4VS4:
            return "Clan 4 vs 4";
        case 0: // race index 0
            return "Random";
        case 1: // race index 1
            return "Human";
        case 2: // race index 2
            return "Orc";
        case 3: // race index 3
            return "Undead";
        case 4: // race index 4
            return "Night Elf";
        case 5: // race index 5
            return "Tournament";
        default:
            return "Unknown";
    }
}

static void
bnet_recv_LOGONREALMEX(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 mcp_cookie;
    BnetRealmStatus mcp_status;
    
    mcp_cookie = bnet_packet_read_dword(pkt);
    mcp_status = bnet_packet_read_dword(pkt);
    if (bnet_packet_can_read(pkt, 65)) {
        guint32 mcp_ip;
        guint32 mcp_port;
        guint32 mcp_data[16];
        gchar *bncs_unique_username;
        
        struct sockaddr_in mcp_addr;
        int i;

        mcp_data[0] = mcp_cookie;
        mcp_data[1] = mcp_status;
        mcp_data[2] = bnet_packet_read_dword(pkt);
        mcp_data[3] = bnet_packet_read_dword(pkt);
        mcp_ip = bnet_packet_read_dword(pkt);
        mcp_port = bnet_packet_read_dword(pkt);
        for (i = 4; i < 16; i++) {
            mcp_data[i] = bnet_packet_read_dword(pkt);
            purple_debug_info("bnet", "MCP value %d = 0x%08x\n", i, mcp_data[i]);
        }
        bncs_unique_username = bnet_packet_read_cstring(pkt);
        
        mcp_addr.sin_addr.s_addr = mcp_ip;
        mcp_addr.sin_port = htons(mcp_port);
        
        purple_debug_info("bnet", "MCP realm logon succeeded. Connect to %s:%d\n", inet_ntoa(mcp_addr.sin_addr), mcp_addr.sin_port);
        bnet_realm_connect(bnet, mcp_addr, mcp_data, bncs_unique_username);
        
        g_free(bncs_unique_username);
    } else {
        // TODO throw error
        purple_debug_warning("bnet", "MCP realm logon failed. 0x%08x\n", mcp_status);
    }
}

static void
bnet_recv_QUERYREALMS2(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 count;
    GList *realms = NULL;
    gboolean auto_join = FALSE;
    gchar *d2realm_join;
    int i;
    
    /* unknown = */bnet_packet_read_dword(pkt);
    count = bnet_packet_read_dword(pkt);
     
    d2realm_join = g_strdup(purple_account_get_string(bnet->account, "d2realm_name", ""));
    if (d2realm_join && strlen(d2realm_join) > 0) {
        auto_join = TRUE;
    } else if (count == 0) {
        // TODO throw error: no realms on this server
        purple_debug_warning("bnet", "MCP There are no realms on this server!\n");
    } else if (count == 1) {
        // join first
        auto_join = TRUE;
    } else {
        // TODO list realms to user
        // init dialog
        purple_debug_info("bnet", "MCP There multiple realms on this server!\n");
    }
    
    for (i = 0; i < count; i++) {
        guint32 d2realm_up = bnet_packet_read_dword(pkt);
        gchar *d2realm_name = bnet_packet_read_cstring(pkt);
        gchar *d2realm_descr = bnet_packet_read_cstring(pkt);
        
        // if we don't know what to autojoin yet,
        // set it to the first realm
        if (auto_join && strlen(d2realm_join) == 0) {
            g_free(d2realm_join);
            d2realm_join = g_strdup(d2realm_name);
        }
        
        if (strcmp(d2realm_join, d2realm_name) == 0) {
            bnet->mcp_name = g_strdup(d2realm_join);
            bnet->mcp_descr = g_strdup(d2realm_descr);
        }
        
        // TODO append to dialog
        g_free(d2realm_name);
        g_free(d2realm_descr);
    }
    
    if (auto_join) {            
        const gchar *d2realm_pass = purple_account_get_string(bnet->account, "d2realm_pass", "password");
        bnet_realm_logon(bnet, bnet->client_cookie, d2realm_join, d2realm_pass);
        auto_join = FALSE;
    }
}

static void
bnet_recv_W3GENERAL_USERRECORD(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 cookie;
    //guint32 icon_id;
    guint8 ladder_record_count;
    guint8 race_record_count;
    guint8 team_record_count;
    guint16 visible_record_count = 0;
    int i, j;
    
    gchar *username;
    gchar *s_icon = NULL;
    const gchar *s_type = NULL;
    gchar *prpl_key = NULL;
    gchar *prpl_val = NULL;
    
    cookie = bnet_packet_read_dword(pkt);
    /*icon_id = */bnet_packet_read_dword(pkt);

    username = bnet_clan_packet_unregister(bnet->clan_info, BNET_SID_W3GENERAL, cookie);

    if (username == NULL) {
        return;
    }

    //s_icon = bnet_clan_tag_to_string(icon_id);

    if (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_W3_USER_STATS) {
        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_W3_USER_STATS;
        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            //if (g_strcmp(bnet->lookup_info_user, username) == 0) { -- do this check if we use W3PROFILE for anything else
            if (!bnet->lookup_info) {
                bnet->lookup_info = purple_notify_user_info_new();
            } else if (!bnet->lookup_info_first_section) {
                purple_notify_user_info_add_section_break(bnet->lookup_info);
            }
            bnet->lookup_info_first_section = FALSE;

            /*prpl_key = g_strdup_printf("%s profile icon", bnet_get_product_name(bnet->product_id));
            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, s_icon);
            g_free(prpl_key);*/
            
            // ladder record parsing
            ladder_record_count = bnet_packet_read_byte(pkt);

            for (i = 0; i < ladder_record_count; i++) {
                BnetW3RecordType type;
                guint16 wins;
                guint16 losses;
                guint8 level;
                guint16 exp;
                guint32 rank;

                gchar *s_rank = NULL;

                type = bnet_packet_read_dword(pkt);
                wins = bnet_packet_read_word(pkt);
                losses = bnet_packet_read_word(pkt);
                level = bnet_packet_read_byte(pkt);
                /*guint8 level_bar = */bnet_packet_read_byte(pkt);
                exp = bnet_packet_read_word(pkt);
                rank = bnet_packet_read_dword(pkt);

                s_type = bnet_get_w3record_type_string(type);

                if (rank != 0) {
                    s_rank = g_strdup_printf(", rank: %d", rank);
                } else {
                    s_rank = g_strdup("");
                }
                prpl_key = g_strdup_printf("%s record for %s", s_type, bnet_get_product_name(bnet->product_id));
                prpl_val = g_strdup_printf("%d-%d (level: %d, exp: %d%s)", wins, losses, level, exp, s_rank);
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                g_free(prpl_key);
                g_free(prpl_val);
                g_free(s_rank);
                
                visible_record_count++;
            }

            // race record parsing
            race_record_count = bnet_packet_read_byte(pkt);

            for (i = 0; i < race_record_count; i++) {
                guint16 wins;
                guint16 losses;

                wins = bnet_packet_read_word(pkt);
                losses = bnet_packet_read_word(pkt);

                s_type = bnet_get_w3record_type_string(i);

                if (wins != 0 || losses != 0) {
                    prpl_key = g_strdup_printf("%s record for %s", s_type, bnet_get_product_name(bnet->product_id));
                    prpl_val = g_strdup_printf("%d-%d", wins, losses);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                    g_free(prpl_key);
                    g_free(prpl_val);
                    
                    visible_record_count++;
                }
            }

            // team record parsing
            team_record_count = bnet_packet_read_byte(pkt);

            for (i = 0; i < team_record_count; i++) {
                BnetW3RecordType type;
                guint16 wins;
                guint16 losses;
                guint8 level;
                guint16 exp;
                guint32 rank;
                guint64 last_game;
                guint8 partner_count;

                gchar *partner_list = NULL;
                gchar *s_last_game = NULL;
                gchar *s_rank = NULL;

                type = bnet_packet_read_dword(pkt);
                wins = bnet_packet_read_word(pkt);
                losses = bnet_packet_read_word(pkt);
                level = bnet_packet_read_byte(pkt);
                /*guint8 level_bar = */bnet_packet_read_byte(pkt);
                exp = bnet_packet_read_word(pkt);
                rank = bnet_packet_read_dword(pkt);
                last_game = bnet_packet_read_qword(pkt);
                partner_count = bnet_packet_read_byte(pkt);

                for (j = 0; j < partner_count; j++) {
                    if (partner_list == NULL) {
                        partner_list = bnet_packet_read_cstring(pkt);
                    } else {
                        gchar *new_p = bnet_packet_read_cstring(pkt);
                        gchar *new_l = g_strdup_printf("%s, %s", partner_list, new_p);
                        g_free(partner_list);
                        g_free(new_p);
                        partner_list = new_l;
                    }
                }

                s_type = bnet_get_w3record_type_string(type);

                s_last_game = bnet_format_filetime(last_game);
                if (rank != 0) {
                    s_rank = g_strdup_printf(", rank: %d", rank);
                } else {
                    s_rank = g_strdup("");
                }
                prpl_key = g_strdup_printf("%s record for %s with %s", s_type, bnet_get_product_name(bnet->product_id), partner_list);
                prpl_val = g_strdup_printf("%d-%d (level: %d, exp: %d%s, last played: %s)", wins, losses, level, exp, s_rank, s_last_game);
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                g_free(prpl_key);
                g_free(prpl_val);
                g_free(s_last_game);
                g_free(s_rank);
                if (partner_list != NULL) {
                    g_free(partner_list);
                }
                
                visible_record_count++;
            }

            if (visible_record_count == 0) {
                prpl_key = g_strdup_printf("Record for %s", bnet_get_product_name(bnet->product_id));
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key,
                        "No game statistics are stored in this user's record.");
                g_free(prpl_key);
            }

            if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }
            
            purple_debug_info("bnet", "Lookup complete: W3_USER_STATS(%s)\n", bnet->lookup_info_user);
        } else {
            purple_debug_info("bnet", "Lookup complete: W3_USER_STATS([freed])\n");
        }
    } else {
        purple_debug_warning("bnet", "Not waiting for 0x44 SID_W3GENERAL.WID_USERRECORD\n");
    }

    g_free(s_icon);
    g_free(username);
}

static void
bnet_recv_W3GENERAL_CLANRECORD(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 cookie;
    guint8 ladder_record_count;
    guint8 race_record_count;
    guint16 visible_record_count = 0;
    int i;
    
    gchar *s_clan;
    const gchar *s_type = NULL;
    gchar *prpl_key = NULL;
    gchar *prpl_val = NULL;
    
    cookie = bnet_packet_read_dword(pkt);

    s_clan = bnet_clan_packet_unregister(bnet->clan_info, BNET_SID_W3GENERAL, cookie);

    if (s_clan == NULL) {
        return;
    }

    if (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_W3_CLAN_STATS) {
        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_W3_CLAN_STATS;
        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            purple_debug_info("bnet", "Lookup complete: W3_CLAN_STATS(Clan %s)\n", s_clan);
            //if (g_strcmp(bnet->lookup_info_user, username) == 0) { -- do this check if we use W3PROFILE for anything else
            if (!bnet->lookup_info) {
                bnet->lookup_info = purple_notify_user_info_new();
            } else if (!bnet->lookup_info_first_section) {
                purple_notify_user_info_add_section_break(bnet->lookup_info);
            }
            bnet->lookup_info_first_section = FALSE;
            
            // ladder record parsing
            ladder_record_count = bnet_packet_read_byte(pkt);

            for (i = 0; i < ladder_record_count; i++) {
                BnetW3RecordType type;
                guint32 wins;
                guint32 losses;
                guint8 level;
                guint32 exp;
                guint32 rank;

                gchar *s_rank = NULL;

                type = bnet_packet_read_dword(pkt);
                wins = bnet_packet_read_dword(pkt);
                losses = bnet_packet_read_dword(pkt);
                level = bnet_packet_read_byte(pkt);
                /*guint8 level_bar = */bnet_packet_read_byte(pkt);
                exp = bnet_packet_read_dword(pkt);
                rank = bnet_packet_read_dword(pkt);

                s_type = bnet_get_w3record_type_string(type);

                if (rank != 0) {
                    s_rank = g_strdup_printf(", rank: %d", rank);
                } else {
                    s_rank = g_strdup("");
                }
                prpl_key = g_strdup_printf("Clan %s %s record for %s", s_clan, s_type, bnet_get_product_name(bnet->product_id));
                prpl_val = g_strdup_printf("%d-%d (level: %d, exp: %d%s)", wins, losses, level, exp, s_rank);
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                g_free(prpl_key);
                g_free(prpl_val);
                g_free(s_rank);
                
                visible_record_count++;
            }

            // race record parsing
            race_record_count = bnet_packet_read_byte(pkt);

            for (i = 0; i < race_record_count; i++) {
                guint32 wins;
                guint32 losses;

                wins = bnet_packet_read_dword(pkt);
                losses = bnet_packet_read_dword(pkt);

                s_type = bnet_get_w3record_type_string(i);

                if (wins != 0 || losses != 0) {
                    prpl_key = g_strdup_printf("Clan %s %s record for %s", s_clan, s_type, bnet_get_product_name(bnet->product_id));
                    prpl_val = g_strdup_printf("%d-%d", wins, losses);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key, prpl_val);
                    g_free(prpl_key);
                    g_free(prpl_val);
                    
                    visible_record_count++;
                }
            }

            if (visible_record_count == 0) {
                prpl_key = g_strdup_printf("Clan %s record for %s", s_clan, bnet_get_product_name(bnet->product_id));
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, prpl_key,
                        "No game statistics are stored in this user's clan's record.");
                g_free(prpl_key);
            }

            if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }
        } else {
            purple_debug_info("bnet", "Lookup complete: W3_CLAN_STATS([freed])\n");
        }
    } else {
        purple_debug_warning("bnet", "Not waiting for 0x44 SID_W3GENERAL.WID_USERRECORD\n");
    }

    g_free(s_clan);
}

static void
bnet_recv_W3GENERAL(BnetConnectionData *bnet, BnetPacket *pkt)
{
    BnetW3GeneralSubcommand subcommand = bnet_packet_read_byte(pkt);
    switch (subcommand) {
        case BNET_WID_USERRECORD:
            bnet_recv_W3GENERAL_USERRECORD(bnet, pkt);
            break;
        case BNET_WID_CLANRECORD:
            bnet_recv_W3GENERAL_CLANRECORD(bnet, pkt);
            break;
        default:
            // unhandled
            purple_debug_warning("bnet", "Received unhandled SID_W3GENERAL packet command 0x%02x\n", subcommand);
            break;
    }
}

static void
bnet_recv_NEWS_INFO(BnetConnectionData *bnet, BnetPacket *pkt)
{
    int i;
    guint8 number_of_entries = bnet_packet_read_byte(pkt);
    /*guint32 last_logon_timestamp = */bnet_packet_read_dword(pkt);
    /*guint32 oldest = */bnet_packet_read_dword(pkt);
    /*guint32 newest = */bnet_packet_read_dword(pkt);

    for (i = 0; i < number_of_entries; i++) {
        guint32 timestamp = bnet_packet_read_dword(pkt);
        gchar *message = bnet_packet_read_cstring(pkt);

        if (timestamp == 0) {
            bnet_motd_free(bnet, BNET_MOTD_TYPE_BNCS);
            bnet->motds[BNET_MOTD_TYPE_BNCS].name = NULL;
            bnet->motds[BNET_MOTD_TYPE_BNCS].subname = NULL;
            bnet->motds[BNET_MOTD_TYPE_BNCS].message = message;
            
            if (!bnet->sent_enter_channel) {
                bnet->news = g_list_sort(bnet->news, bnet_news_item_sort);
                bnet_news_save(bnet);
                bnet->sent_enter_channel = TRUE;
                bnet_enter_channel(bnet);
            }

            purple_debug_info("bnet", "News items: %d\n", bnet->news_count);
        } else {
            GList *el2 = g_list_first(bnet->news);
            BnetNewsItem *item = g_new0(BnetNewsItem, 1);
                
            while (el2 != NULL) {
                if (((BnetNewsItem *)el2->data)->timestamp == timestamp) {
                    purple_debug_warning("bnet", "duplicate in bnet_recv_NEWS_INFO\n");
                }
                el2 = g_list_next(el2);
            }
            
            item->timestamp = timestamp;
            item->message = message;

            bnet->news = g_list_append(bnet->news, item);
            bnet->news_count++;
            if (item->timestamp > bnet->news_latest) {
                bnet->news_latest = item->timestamp;
            }
        }
    }
}

static void
bnet_recv_AUTH_INFO(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 logon_system = bnet_packet_read_dword(pkt);
    guint32 server_cookie = bnet_packet_read_dword(pkt);
    guint32 session_cookie = bnet_packet_read_dword(pkt);
    guint64 mpq_ft = bnet_packet_read_qword(pkt);
    char* mpq_fn = bnet_packet_read_cstring(pkt);
    char* checksum_formula = bnet_packet_read_cstring(pkt);

    //purple_debug_info("bnet", "mpqfn: %s; chfm: %s\n",
    //    mpq_fn, checksum_formula);
    bnet->logon_system = logon_system;
    bnet->server_cookie = server_cookie;
    bnet->session_cookie = session_cookie;

    if (bnet_is_w3(bnet)) {
        gchar *signature;
        union {
            struct sockaddr_in as_in;
            struct sockaddr as_generic;
        } sa;
        socklen_t sa_len = sizeof(sa);

        signature = (gchar *)bnet_packet_read(pkt, 128);
        if (signature == NULL) {
            purple_debug_warning("bnet", "WarCraft III: No server signature for the current Battle.net server IP provided. This may be a private server.\n");
        } else if (getpeername(bnet->sbncs.fd, &sa.as_generic, &sa_len) == 0) {
            struct in_addr addr = sa.as_in.sin_addr;
            purple_debug_info("bnet", "Server IP: %s\n", inet_ntoa(addr));
            if (srp_check_signature(addr.s_addr, signature) == FALSE) {
                purple_debug_warning("bnet", "WarCraft III: Server sent an incorrect server signature for the current Battle.net server IP. You are connecting through a proxy or this may be a malicious server.\n");
            } else {
                purple_debug_info("bnet", "WarCraft III: Validated Battle.net server signature. This is an official Battle.net server.\n");
            }
            g_free(signature);
        } else {
            purple_debug_warning("bnet", "WarCraft III: Unable to verify server signature for the current Battle.net server IP. Error getting peer IP: %s\n", strerror(errno));
            g_free(signature);
        }
    }

    bnet_bnls_send_VERSIONCHECKEX2(bnet,
            logon_system, server_cookie, session_cookie, mpq_ft, mpq_fn, checksum_formula);

    g_free(mpq_fn);
    g_free(checksum_formula);
}

static void
bnet_recv_AUTH_CHECK(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);
    char *extra_info = bnet_packet_read_cstring(pkt);

    PurpleConnection *gc = bnet->account->gc;

    char *tmp = NULL;
    char *tmpe = NULL;
    char *tmpf = NULL;
    char *tmpkn = NULL;

    PurpleConnectionError conn_error = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;

    if (result == BNET_SUCCESS) {
        bnet->versioning_complete = TRUE;

        purple_debug_info("bnet", "Version and key check passed!\n");

        if (!bnet->account_create) {
            purple_connection_update_progress(gc, "Authenticating", BNET_STEP_LOGON, BNET_STEP_COUNT);
        }

        bnet_account_logon(bnet);

        g_free(extra_info);

        return;
    } else if (result & BNET_AUTH_CHECK_VERERROR_MASK) {
        switch (result & BNET_AUTH_CHECK_ERROR_MASK) {
            case BNET_AUTH_CHECK_VERERROR_INVALID:
                tmp = "Version invalid%s.";
                break;
            case BNET_AUTH_CHECK_VERERROR_OLD:
                tmp = "Old version%s.";
                break;
            case BNET_AUTH_CHECK_VERERROR_NEW:
                tmp = "New version%s.";
                break;
            default:
                tmp = "Version invalid%s.";
                break;
        }
    } else if (result & BNET_AUTH_CHECK_KEYERROR_MASK) {
        guint32 keynum = (result & BNET_AUTH_CHECK_KEYNUMBER_MASK) >> 4;
        switch (result & BNET_AUTH_CHECK_ERROR_MASK) {
            case BNET_AUTH_CHECK_KEYERROR_INVALID:
                tmp = "CD-key invalid%s.";
                break;
            case BNET_AUTH_CHECK_KEYERROR_INUSE:
                tmp = "CD-key is in use%s.";
                if (strlen(extra_info) > 0) {
                    if (strcmp(extra_info, bnet->username) == 0) {
                        tmp = "CD-key is in use%s. Battle.net may not have discovered that you disconnected yet. Try again in five minutes.";
                        conn_error = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
                    }
                }
                break;
            case BNET_AUTH_CHECK_KEYERROR_BANNED:
                tmp = "CD-key is banned%s.";
                break;
            case BNET_AUTH_CHECK_KEYERROR_BADPRODUCT:
                tmp = "CD-key is for another game%s.";
                break;
            default:
                tmp = "CD-key invalid%s.";
                break;
        }
        tmpkn = g_strdup_printf("%s%s", (keynum == 1) ? "Expansion " : "", tmp);
        tmp = tmpkn;
    } else if (result & BNET_AUTH_CHECK_VERCODEERROR_MASK) {
        tmp = "Version code invalid%s.";
    } else {
        tmp = "Authorization failed%s.";
    }

    tmpe = g_strdup_printf(" (%s)", extra_info);
    tmpf = g_strdup_printf(tmp, strlen(extra_info) > 0 ? tmpe : "");
    purple_connection_error_reason(gc, conn_error, tmpf);

    g_free(tmpe);
    g_free(tmpf);
    if (tmpkn) g_free(tmpkn);

    //purple_debug_info("bnet", "AUTH_CHECK: 0x%08x %s\n", result, extra_info);

    g_free(extra_info);
}

static void
bnet_recv_AUTH_ACCOUNTCREATE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);

    PurpleConnection *gc = bnet->account->gc;

    switch (result) {
        case BNET_SUCCESS:
            purple_debug_info("bnet", "Account created!\n");
            bnet->account_create = FALSE;
            bnet_close(gc);
            return;
        case BNET_AUTH_ACCOUNT_EXISTS:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account name in use");
            break;
        case BNET_AUTH_ACCOUNT_SHORT:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name is too short.");
            break;
        case BNET_AUTH_ACCOUNT_BADCHAR:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name contains an illigal character");
            break;
        case BNET_AUTH_ACCOUNT_BADWORD:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name contains a banned word");
            break;
        case BNET_AUTH_ACCOUNT_NOTENOUGHALPHA:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name does not contain enough alphanumeric characters");
            break;
        case BNET_AUTH_ACCOUNT_ADJPUNCT:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name contains adjacent punctuation characters");
            break;
        case BNET_AUTH_ACCOUNT_TOOMANYPUNCT:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name contains too many punctuation characters");
            break;
        default:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account create failure");
            break;
    }

    if (bnet->account_data != NULL) {
        srp_free(bnet->account_data);
        bnet->account_data = NULL;
    }
}


static void
bnet_recv_AUTH_ACCOUNTLOGON(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);

    PurpleConnection *gc = bnet->account->gc;
    
    bnet_account_lockout_cancel(bnet);

    switch (result) {
        case BNET_SUCCESS:
            {
                gchar M1[SHA1_HASH_SIZE];
                gchar *salt = (gchar *)bnet_packet_read(pkt, 32);
                gchar *B = (gchar *)bnet_packet_read(pkt, 32);
                srp_get_M1(bnet->account_data, M1, B, salt);
                bnet_send_AUTH_ACCOUNTLOGONPROOF(bnet, M1);
                g_free(salt);
                g_free(B);
                return;
            }
        case BNET_AUTH_ACCOUNT_DNE:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account does not exist");
            break;
        case BNET_AUTH_ACCOUNT_REQUPGRADE:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account requires upgrade");
            break;
        default:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account logon failure");
            break;
    }

    if (bnet->account_data != NULL) {
        srp_free(bnet->account_data);
        bnet->account_data = NULL;
    }
}

static void
bnet_recv_AUTH_ACCOUNTLOGONPROOF(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);

    PurpleConnection *gc = bnet->account->gc;

    switch (result) {
        case BNET_SUCCESS:
            {
                gchar *M2 = (gchar *)bnet_packet_read(pkt, SHA1_HASH_SIZE);

                if (srp_check_M2(bnet->account_data, M2) == FALSE) {
                    purple_debug_warning("bnet", "SRP: Server sent an incorrect M[2] value!\n");
                } else {
                    purple_debug_info("bnet", "SRP: Validated M[2] value.\n");
                }

                g_free(M2);

                purple_debug_info("bnet", "Logged in!\n");
                purple_connection_update_progress(gc, "Entering chat", BNET_STEP_FINAL, BNET_STEP_COUNT);

                bnet_enter_chat(bnet);
                break;
            }
        case BNET_AUTH_ACCOUNT_BADPW:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Password incorrect");
            break;
        case BNET_AUTH_ACCOUNT_CLOSED:
            {
                char *extra_info = bnet_packet_read_cstring(pkt);
                purple_connection_error_reason(gc,
                        PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                        "Account closed");

                purple_debug_info("bnet", "ACCOUNT CLOSED: %s\n", extra_info);
                g_free(extra_info);
                break;
            }
        case BNET_AUTH_ACCOUNT_REQEMAIL:
            bnet_request_set_email(bnet, FALSE);
            purple_debug_info("bnet", "Logged in!\n");
            purple_connection_update_progress(gc, "Entering chat", BNET_STEP_FINAL, BNET_STEP_COUNT);
            bnet_enter_chat(bnet);
            break;
        case BNET_AUTH_ACCOUNT_ERROR:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account logon failure");
            break;
    }
}

static void
bnet_recv_SETEMAIL(BnetConnectionData *bnet, BnetPacket *pkt)
{
    bnet_request_set_email(bnet, FALSE);
}

static void
bnet_recv_LOGONRESPONSE2(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);

    PurpleConnection *gc = bnet->account->gc;
    
    bnet_account_lockout_cancel(bnet);

    switch (result) {
        case BNET_SUCCESS:
            purple_debug_info("bnet", "Logged in!\n");
            purple_connection_update_progress(gc, "Entering chat", BNET_STEP_FINAL, BNET_STEP_COUNT);

            bnet_enter_chat(bnet);
            break;
        case BNET_LOGONRESP2_DNE:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account does not exist");
            break;
        case BNET_LOGONRESP2_BADPW:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Password incorrect");
            break;
        case BNET_LOGONRESP2_CLOSED:
            {
                char *extra_info = bnet_packet_read_cstring(pkt);
                purple_connection_error_reason(gc,
                        PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                        "Account closed");

                purple_debug_info("bnet", "ACCOUNT CLOSED: %s\n", extra_info);
                g_free(extra_info);
                break;
            }
        default:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account logon failure");
            break;
    }

    //purple_debug_info("bnet", "LOGONRESPONSE2: 0x%08x\n", result);
}

static void
bnet_recv_CREATEACCOUNT2(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 result = bnet_packet_read_dword(pkt);

    PurpleConnection *gc = bnet->account->gc;

    switch (result) {
        case BNET_SUCCESS:
            purple_debug_info("bnet", "Account created!\n");
            bnet->account_create = FALSE;
            bnet_close(gc);
            break;
        case BNET_CREATEACC2_BADCHAR:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name contains an illigal character");
            break;
        case BNET_CREATEACC2_BADWORD:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name contains a banned word");
            break;
        case BNET_CREATEACC2_EXISTS:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account name in use");
            break;
        case BNET_CREATEACC2_NOTENOUGHALPHA:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
                    "Account name does not contain enough alphanumeric characters");
            break;
        default:
            purple_connection_error_reason(gc,
                    PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                    "Account create failure");
            break;
    }

    //purple_debug_info("bnet", "LOGONRESPONSE2: 0x%08x\n", result);
}

static void
bnet_recv_FRIENDSLIST(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint8 fcount = bnet_packet_read_byte(pkt);
    guint8 idx = 0;
    GList *old_friends_list = bnet->friends_list;
    GList *el = NULL;

    bnet->friends_list = NULL;
    purple_debug_info("bnet", "%d friends on list\n", fcount);

    if (fcount > 0) {
        while (idx < fcount) {
            BnetFriendInfo *bfi = NULL;
            BnetFriendInfo *old_bfi = NULL;

            gchar *account_name = bnet_packet_read_cstring(pkt);
            BnetFriendStatus status = bnet_packet_read_byte(pkt);
            BnetFriendLocation location = bnet_packet_read_byte(pkt);
            BnetProductID product_id = bnet_packet_read_dword(pkt);
            gchar *location_name = bnet_packet_read_cstring(pkt);

            el = g_list_first(old_friends_list);
            while (el != NULL) {
                if (el->data != NULL) {
                    if (strcmp(((BnetFriendInfo *)el->data)->account, account_name) == 0) {
                        old_bfi = el->data;
                    }
                }
                el = g_list_next(el);
            }

            if (old_bfi == NULL) {
                bfi = g_new0(BnetFriendInfo, 1);
                bfi->type = BNET_USER_TYPE_FRIEND;
                bfi->account = account_name;
                bfi->status = -1;
                bfi->location = -1;
                bfi->product = -1;
                bfi->location_name = g_strdup("");
                purple_debug_info("bnet", "Friend diff: %s added\n", bfi->account);
            } else {
                bfi = old_bfi;
                //purple_debug_info("bnet", "Friend diff: %s still on list\n", bfi->account);
            }
            bfi->on_list = TRUE;

            bnet->friends_list = g_list_append(bnet->friends_list, bfi);

            bnet_friend_update(bnet, idx, bfi, status, location, product_id, location_name);

            //purple_debug_error("bnet", "Location: %s\n", location_name);

            idx++;
        }
        //g_free(bfi);
    }

    el = g_list_first(old_friends_list);
    while (el != NULL) {
        if (el->data != NULL) {
            if (!((BnetFriendInfo *)el->data)->on_list) {
                PurpleBuddy *buddy;
                BnetFriendInfo *old_bfi = NULL;

                old_bfi = el->data;
                purple_debug_info("bnet", "Friend diff: %s no longer on list\n", old_bfi->account);

                buddy = purple_find_buddy(bnet->account, old_bfi->account);

                bnet_friend_info_free(old_bfi);

                if (buddy) {
                    // set proto data to NULL so that it doesn't /f r again.
                    purple_buddy_set_protocol_data(buddy, NULL);
                    // remove
                    purple_blist_remove_buddy(buddy);
                }
            }
        }
        el = g_list_next(el);
    }

    g_list_free(old_friends_list);

    el = g_list_first(bnet->friends_list);
    while (el != NULL) {
        ((BnetFriendInfo *)el->data)->on_list = FALSE;
        el = g_list_next(el);
    }

    bnet_find_detached_buddies(bnet);
}

static void
bnet_recv_FRIENDSUPDATE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint8 index = bnet_packet_read_byte(pkt);
    BnetFriendInfo *bfi = g_list_nth_data(bnet->friends_list, index);

    BnetFriendStatus status = bnet_packet_read_byte(pkt);
    BnetFriendLocation location = bnet_packet_read_byte(pkt);
    BnetProductID product_id = bnet_packet_read_dword(pkt);
    gchar *location_name = bnet_packet_read_cstring(pkt);

    bnet_friend_update(bnet, index, bfi, status, location, product_id, location_name);

    g_free(location_name);
}

static void
bnet_recv_FRIENDSADD(BnetConnectionData *bnet, BnetPacket *pkt)
{
    BnetFriendInfo *bfi = g_new0(BnetFriendInfo, 1);
    guint8 index = g_list_length(bnet->friends_list);

    gchar *account_name = bnet_packet_read_cstring(pkt);

    BnetFriendStatus status = bnet_packet_read_byte(pkt);
    BnetFriendLocation location = bnet_packet_read_byte(pkt);
    BnetProductID product_id = bnet_packet_read_dword(pkt);
    gchar *location_name = bnet_packet_read_cstring(pkt);

    bfi->type = BNET_USER_TYPE_FRIEND;
    bfi->account = account_name;
    bfi->status = -1;
    bfi->location = -1;
    bfi->product = -1;
    bfi->location_name = g_strdup("");

    bnet->friends_list = g_list_append(bnet->friends_list, bfi);

    bnet_friend_update(bnet, index, bfi, status, location, product_id, location_name);

    g_free(location_name);

    //g_free(bfi);
}

static void
bnet_recv_FRIENDSREMOVE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    PurpleBuddy *buddy = NULL;
    BnetFriendInfo *bfi = NULL;
    guint8 index = bnet_packet_read_byte(pkt);
    GList *el = g_list_nth(bnet->friends_list, index);

    g_return_if_fail(el != NULL);

    bfi = (BnetFriendInfo *) el->data;

    if (bfi == NULL) {
        // already freed (was a libpurple initiated remove), simply remove link
        bnet->friends_list = g_list_remove_link(bnet->friends_list, el);
        g_list_free_1(el);
    } else {
        // chat command initiated remove, find libpurple buddy
        buddy = purple_find_buddy(bnet->account, bfi->account);

        if (buddy) {
            // set proto data to NULL so that it doesn't /f r again.
            purple_buddy_set_protocol_data(buddy, NULL);
            // remove
            purple_blist_remove_buddy(buddy);
            // free locally
            bnet_friend_info_free(el->data);
        }

        bnet->friends_list = g_list_remove_link(bnet->friends_list, el);
        g_list_free_1(el);
    }
}

static void
bnet_recv_FRIENDSPOSITION(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint8 old_index = bnet_packet_read_byte(pkt);
    guint8 new_index = bnet_packet_read_byte(pkt);
    GList *bfi_link = g_list_nth(bnet->friends_list, old_index);

    bnet->friends_list = g_list_remove_link(bnet->friends_list, bfi_link);
    bnet->friends_list = g_list_insert(bnet->friends_list, bfi_link->data, new_index);
}

static void
bnet_recv_CLANFINDCANDIDATES(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANINVITEMULTIPLE(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANCREATIONINVITATION(BnetConnectionData *bnet, BnetPacket *pkt)
{
    gint32 cookie = bnet_packet_read_dword(pkt);
    BnetClanTag clan_tag = bnet_packet_read_dword(pkt);
    gchar *clan_name = bnet_packet_read_cstring(pkt);
    gchar *inviter_name = bnet_packet_read_cstring(pkt);
    char invitees_buf[200];
    guint8 invitees_count = bnet_packet_read_byte(pkt);
    int i;
    int pos = 0;
    gchar *clan_tag_string = bnet_clan_tag_to_string(clan_tag);
    BnetClanInvitationCallbackData *callback_data = NULL;
    gchar *inv_text;

    for (i = 0; i < invitees_count && i < 10; i++) {
        gchar *user = bnet_packet_read_cstring(pkt);
        if (pos < 199 && pos > 0) {
            invitees_buf[pos] = ',';
            invitees_buf[pos + 1] = ' ';
            pos += 2;
        }
        if (pos < 200 - strlen(user)) {
            memmove(invitees_buf + pos, user, strlen(user));
            pos += strlen(user);
        }
        g_free(user);
    }
    invitees_buf[pos] = '\0';
    inv_text = g_strdup_printf("You have been invited by %s to help create Clan %s, %s with %d other users:",
                inviter_name, clan_tag_string, clan_name, invitees_count),

    callback_data = g_new0(BnetClanInvitationCallbackData, 1);
    callback_data->bnet = bnet;
    callback_data->packet_id = BNET_SID_CLANCREATIONINVITATION;
    callback_data->cookie = cookie;
    callback_data->clan_tag = clan_tag;
    callback_data->inviter = g_strdup(inviter_name);
    callback_data->clan_name = g_strdup(clan_name);

    purple_request_action(bnet->account->gc, "Clan Creation Invitation",
            inv_text,
            invitees_buf,
            0,
            bnet->account,
            NULL, NULL, 
            callback_data,
            2,
            "_Decline", bnet_clan_invite_decline_cb,
            "_Accept", bnet_clan_invite_accept_cb);

    g_free(inv_text);
    g_free(clan_name);
    g_free(inviter_name);
    g_free(clan_tag_string);
}

static void
bnet_recv_CLANDISBAND(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANMAKECHIEFTAIN(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANINFO(BnetConnectionData *bnet, BnetPacket *pkt)
{
    BnetClanTag clan_tag;
    BnetClanMemberRank rank;
    int motd_cookie, memblist_cookie, selfinfo_cookie;
    const gchar *acct_norm = bnet->my_accountname;

    bnet_packet_read_byte(pkt);
    clan_tag = (BnetClanTag) bnet_packet_read_dword(pkt);
    rank = (BnetClanMemberRank) bnet_packet_read_byte(pkt);
    bnet_clan_info_join_clan(bnet->clan_info, clan_tag, rank);

    memblist_cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_CLANMEMBERLIST, NULL);
    bnet_send_CLANMEMBERLIST(bnet, memblist_cookie);

    selfinfo_cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_CLANMEMBERINFO, NULL);
    bnet->lookup_info_clan = clan_tag;
    bnet_send_CLANMEMBERINFO(bnet, selfinfo_cookie, clan_tag, acct_norm);

    motd_cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_CLANMOTD, NULL);
    bnet_send_CLANMOTD(bnet, motd_cookie);
}

static void
bnet_recv_CLANQUITNOTIFY(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANINVITATION(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANREMOVEMEMBER(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANINVITATIONRESPONSE(BnetConnectionData *bnet, BnetPacket *pkt)
{
    gint32 cookie = bnet_packet_read_dword(pkt);
    BnetClanTag clan_tag = bnet_packet_read_dword(pkt);
    gchar *clan_name = bnet_packet_read_cstring(pkt);
    gchar *inviter_name = bnet_packet_read_cstring(pkt);

    gchar *clan_tag_string = bnet_clan_tag_to_string(clan_tag);
    BnetClanInvitationCallbackData *callback_data = NULL;
    gchar *inv_text = g_strdup_printf("You have been inviteby %s to join Clan %s, %s!",
                inviter_name, clan_tag_string, clan_name);

    callback_data = g_new0(BnetClanInvitationCallbackData, 1);
    callback_data->bnet = bnet;
    callback_data->packet_id = BNET_SID_CLANINVITATIONRESPONSE;
    callback_data->cookie = cookie;
    callback_data->clan_tag = clan_tag;
    callback_data->inviter = g_strdup(inviter_name);
    callback_data->clan_name = g_strdup(clan_name);

    purple_request_action(bnet->account->gc, "Clan Invitation",
            inv_text,
            NULL,
            0,
            bnet->account,
            NULL, NULL, 
            callback_data,
            2,
            "_Decline", bnet_clan_invite_decline_cb,
            "_Accept", bnet_clan_invite_accept_cb);

    g_free(inv_text);
    g_free(clan_name);
    g_free(inviter_name);
    g_free(clan_tag_string);
}

static void
bnet_recv_CLANRANKCHANGE(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANMOTD(BnetConnectionData *bnet, BnetPacket *pkt)
{
    PurpleConversation *conv = NULL;
    PurpleConvChat *chat = NULL;
    guint32 cookie;
    gchar *motd;
    gchar *s_tag;
    gchar *s_name;

    cookie = bnet_packet_read_dword(pkt);
    bnet_packet_read_dword(pkt);
    motd = bnet_packet_read_cstring(pkt);

    bnet_clan_packet_unregister(bnet->clan_info, BNET_SID_CLANMOTD, cookie);
    s_tag = bnet_clan_tag_to_string(bnet_clan_info_get_tag(bnet->clan_info));
    s_name = bnet_clan_info_get_name(bnet->clan_info);
    bnet_motd_free(bnet, BNET_MOTD_TYPE_CLAN);
    bnet->motds[BNET_MOTD_TYPE_CLAN].name = g_strdup_printf("Clan %s", s_tag);
    if (s_name != NULL) {
        bnet->motds[BNET_MOTD_TYPE_CLAN].subname = g_strdup(s_name);
    }
    bnet->motds[BNET_MOTD_TYPE_CLAN].message = g_strdup(motd);
    if (!bnet->channel_first_join && bnet->channel_id != 0) {
        conv = purple_find_chat(bnet->account->gc, bnet->channel_id);
    }
    if (conv != NULL) {
        chat = purple_conversation_get_chat_data(conv);
    }
    if (chat != NULL && bnet_clan_is_clan_channel(bnet->clan_info, bnet->channel_name)) {
        purple_conv_chat_set_topic(chat, "(clan leader)", motd);
    }
    g_free(s_tag);
    g_free(motd);
}

static void
bnet_recv_CLANMEMBERLIST(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 cookie;
    guint8 number_of_members;
    GList *members = NULL;
    const gchar *group_name_setting;
    gchar *group_name;
    PurpleGroup *group;
    BnetClanTag clan_tag;
    gchar *clan_tag_text;
    int i;
    gboolean do_not_free = FALSE;

    cookie = bnet_packet_read_dword(pkt);
    bnet_clan_packet_unregister(bnet->clan_info, BNET_SID_CLANMEMBERLIST, cookie);

    clan_tag = bnet_clan_info_get_tag(bnet->clan_info);
    clan_tag_text = bnet_clan_tag_to_string(clan_tag);

    number_of_members = bnet_packet_read_byte(pkt);

    purple_debug_info("bnet", "Clan members: %d\n", number_of_members);
    // get or create default "Buddies" group
    group_name_setting = purple_account_get_string(bnet->account, "grpclan", BNET_DEFAULT_GROUP_CLAN);
    group_name = g_strdup_printf(group_name_setting, clan_tag_text);
    group = purple_group_new(group_name);

    for (i = 0; i < number_of_members; i++) {
        gchar *name = bnet_packet_read_cstring(pkt);
        BnetClanMemberRank rank = bnet_packet_read_byte(pkt);
        BnetClanMemberStatus status = bnet_packet_read_byte(pkt);
        gchar *location = bnet_packet_read_cstring(pkt);

        BnetClanMember *member = bnet_clan_member_new(name, rank, status, location);
        members = g_list_append(members, member);
    }

    if (purple_account_get_bool(bnet->account, "showgrpclan", FALSE)) {
        GList *el = g_list_first(members);
        for (i = 0; i < number_of_members; i++) {
            BnetClanMember *member = el->data;
            gchar *name = bnet_clan_member_get_name(member);
            const gchar *prpl_status = NULL;
            GSList *buddies;
            PurpleBuddy *buddy = NULL;
            BnetUser *current_member = NULL;
            gboolean found_mergable;

            bnet->clan_members_in_blist = TRUE;

            switch (bnet_clan_member_get_status(member)) {
                case BNET_CLAN_STATUS_OFFLINE:
                    prpl_status = BNET_STATUS_OFFLINE;
                    break;
                case BNET_CLAN_STATUS_ONLINE:
                default:
                    prpl_status = BNET_STATUS_ONLINE;
                    break;
            }

            buddies = purple_find_buddies(bnet->account, name);
            found_mergable = FALSE;
            while (buddies != NULL) {
                buddy = buddies->data;
                current_member = purple_buddy_get_protocol_data(buddy);
                if (current_member != NULL && current_member->type == BNET_USER_TYPE_CLANMEMBER) {
                    //purple_debug_info("bnet", "Clan diff: %s merged\n", name);
                    found_mergable = TRUE;
                    purple_buddy_set_protocol_data(buddy, member);
                    bnet_clan_member_set_joindate(member, bnet_clan_member_get_joindate((BnetClanMember *)current_member));
                    break;
                }
                buddies = g_slist_next(buddies);
            }
            if (!found_mergable) {
                purple_debug_info("bnet", "Clan diff: %s added\n", name);
                buddy = purple_buddy_new(bnet->account, name, name);
                purple_blist_node_set_flags(PURPLE_BLIST_NODE(buddy), PURPLE_BLIST_NODE_FLAG_NO_SAVE);
                purple_blist_add_buddy(buddy, NULL, group, NULL);
                purple_buddy_set_protocol_data(buddy, member);
                purple_prpl_got_user_status(bnet->account, name, prpl_status, NULL);
            } else if (bnet_clan_member_get_status((BnetClanMember *)current_member) !=
                    bnet_clan_member_get_status(member)) {
                purple_debug_info("bnet", "Clan diff: %s updated\n", name);
                purple_prpl_got_user_status(bnet->account, name, prpl_status, NULL);
            }
            el = g_list_next(el);
        }
    } else if (bnet->clan_members_in_blist) {
        // the user turned off the setting while connected
        // prpl holds the memory to the old list, do not free it
        bnet->clan_members_in_blist = FALSE;
        do_not_free = TRUE;
    }

    bnet_clan_info_set_members(bnet->clan_info, members, !do_not_free);
}

static void
bnet_recv_CLANMEMBERREMOVED(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANMEMBERSTATUSCHANGE(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANMEMBERRANKCHANGE(BnetConnectionData *bnet, BnetPacket *pkt)
{
}

static void
bnet_recv_CLANMEMBERINFO(BnetConnectionData *bnet, BnetPacket *pkt)
{
    guint32 cookie;
    BnetClanResponseCode status;
    gchar *s_clan = NULL;
    const gchar *s_rank = NULL;
    gchar *s_clan_joindate = NULL;
    gchar *clan_name = NULL;
    BnetClanMemberRank clan_rank = BNET_CLAN_RANK_INITIATE;
    guint64 clan_joindate = 0;
    
    cookie = bnet_packet_read_dword(pkt);
    status = bnet_packet_read_byte(pkt);
    s_clan = bnet_clan_packet_unregister(bnet->clan_info, BNET_SID_CLANMEMBERINFO, cookie);

    switch (status) {
        case BNET_CLAN_RESPONSE_SUCCESS:
            clan_name = bnet_packet_read_cstring(pkt);
            clan_rank = bnet_packet_read_byte(pkt);
            clan_joindate = bnet_packet_read_qword(pkt);

            if (bnet_clan_info_get_tag(bnet->clan_info) == bnet->lookup_info_clan) {
                BnetClanMember *member = bnet_clan_info_get_member(bnet->clan_info, bnet->lookup_info_user);
                bnet_clan_info_set_name(bnet->clan_info, g_strdup(clan_name));
                if (member != NULL) {
                    bnet_clan_member_set_joindate(member, clan_joindate);
                }
            }
            break;
        case BNET_CLAN_RESPONSE_USERNOTFOUND:
            purple_debug_warning("bnet", "Error retrieving member info for %s: user not found in that clan\n", bnet->lookup_info_user);
            break;
        default:
            purple_debug_warning("bnet", "Error retrieving member info for %s: status code 0x%02x\n", bnet->lookup_info_user, status);
            break;
    }

    if (s_clan == NULL) {
        // this is a logon sequence getting of clan name
        return;
    }

    s_rank = bnet_clan_rank_to_string(clan_rank);
    s_clan_joindate = bnet_format_filetime(clan_joindate);

    if (bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_W3_CLAN_MI) {
        bnet->lookup_info_await &= ~BNET_LOOKUP_INFO_AWAIT_W3_CLAN_MI;
        if (!(bnet->lookup_info_await & BNET_LOOKUP_INFO_AWAIT_CANCELLED)) {
            //if (g_strcmp(bnet->lookup_info_user, username) == 0) { -- do this check if we use W3PROFILE for anything else
            purple_debug_info("bnet", "Lookup complete: W3_CLAN_MI(%s, Clan %s)\n", bnet->lookup_info_user, s_clan);
            if (!bnet->lookup_info) {
                bnet->lookup_info = purple_notify_user_info_new();
            } else if (!bnet->lookup_info_first_section) {
                purple_notify_user_info_add_section_break(bnet->lookup_info);
            }
            bnet->lookup_info_first_section = FALSE;

            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Clan tag", s_clan);
            if (status == BNET_CLAN_RESPONSE_SUCCESS) {
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Clan name", clan_name);
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Clan rank", s_rank);
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Clan join date", s_clan_joindate);

                if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                    purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
                            bnet->lookup_info, bnet_lookup_info_close, bnet);
                }
            }

            if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
                purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
                        bnet->lookup_info, bnet_lookup_info_close, bnet);
            }
        } else {
            purple_debug_info("bnet", "Lookup complete: W3_CLAN_MI([freed])\n");
        }
    } else {
        purple_debug_warning("bnet", "Not waiting for 0x82 SID_CLANMEMBERINFO\n");
    }

    g_free(s_clan);
    if (clan_name != NULL) {
        g_free(clan_name);
    }
    if (s_clan_joindate != NULL) {
        g_free(s_clan_joindate);
    }
}

static gboolean
bnet_parse_telnet_line_event(BnetConnectionData *bnet, GRegex *regex, const gchar *text, GMatchInfo *mi)
{
    gchar *id_str = g_match_info_fetch(mi, 1);
    gchar *rest = g_match_info_fetch(mi, 2);
    int id = atoi(id_str);
    BnetChatEventFlags flags;
    gint32 ping;
    PurpleConversation *conv = NULL;
    PurpleConvChat *chat = NULL;
    PurpleConnection *gc = bnet->account->gc;

    if (!bnet->is_online) {
        bnet_entered_chat(bnet);
    }
    if (!bnet->channel_first_join && bnet->channel_id != 0) {
        conv = purple_find_chat(gc, bnet->channel_id);
    }
    if (conv != NULL) {
        chat = purple_conversation_get_chat_data(conv);
    }

    if (id >= BNET_TELNET_EID && id < BNET_TELNET_SID) {
        gchar *name = NULL;
        gchar *flags_str = NULL;
        gchar *text_str = NULL;
        int i, j;
        gboolean regex_matched = FALSE;

        id -= BNET_TELNET_EID;

        i = 0;
        while (bnet_regex_store[i].regex != NULL) {
            GRegex *ev_regex = bnet_regex_store[i].regex;
            GMatchInfo *ev_mi = NULL;

            if (regex_matched) {
                break;
            }

            if (bnet_regex_store[i].event_id == BNET_TELNET_EID) {
                if (g_regex_match(ev_regex, rest, 0, &ev_mi)) {
                    for (j = 0; j < strlen(bnet_regex_store[i].arg_format); j++) {
                        char arg = bnet_regex_store[i].arg_format[j];
                        switch (arg) {
                            case '\0':
                                break;
                            case 'n':
                                name = g_match_info_fetch(ev_mi, j + 1);
                                break;
                            case 'f':
                                flags_str = g_match_info_fetch(ev_mi, j + 1);
                                break;
                            case 't':
                                text_str = g_match_info_fetch(ev_mi, j + 1);
                                break;
                            case 'p':
                                text_str = g_match_info_fetch(ev_mi, j + 1);
                                g_strreverse(text_str);
                                break;
                        }
                    }
                    regex_matched = TRUE;
                }
                if (mi != NULL) {
                    g_match_info_free(ev_mi);
                    mi = NULL;
                }
            }

            i++;
        }

        if (name == NULL) {
            name = g_strdup("");
        }
        if (flags_str == NULL) {
            flags_str = g_strdup("0");
        }
        if (text_str == NULL) {
            text_str = g_strdup("");
        }

        flags = atoi(flags_str);
        ping = -1;

        bnet_recv_event(bnet, chat, id, name, text_str, flags, ping);
        g_free(name);
        g_free(flags_str);
        g_free(text_str);
    } else if (id >= BNET_TELNET_SID && id < BNET_TELNET_XID) {
        id -= BNET_TELNET_SID;
        switch (id) {
            case BNET_SID_NULL:
                // do nothing bnet_recv_NULL();
                break;
            case BNET_SID_ENTERCHAT:
                if (bnet->my_accountname != NULL) {
                    g_free(bnet->my_accountname);
                }
                // 2010 NAME "Ribose#2"
                bnet->my_statstring = g_strdup("");
                bnet->my_accountname = g_strdup(bnet->username);
                bnet->unique_username = g_strdup(rest);
                break;
        }
    } else if (id == BNET_TELNET_XID) {
        bnet_recv_event_INFO(bnet, chat, "Battle.net 3000", rest, 0, -1);
    }

    g_free(id_str);
    g_free(rest);

    return TRUE;
}

static void
bnet_parse_telnet_line(BnetConnectionData *bnet, const gchar *line)
{
    gchar *text = bnet_locale_to_utf8(line);

    purple_debug_misc("bnet", "TELNET S>C: %s\n", text);

    if (strlen(text) > 0) {
        gboolean regex_matched = FALSE;
        gboolean handled = FALSE;
        int i = 0;
        while (bnet_regex_store[i].regex != NULL) {
            GRegex *regex = bnet_regex_store[i].regex;
            GMatchInfo *mi = NULL;

            if (handled) {
                break;
            }

            if (bnet_regex_store[i].event_id == 0) {
                if (g_regex_match(regex, text, 0, &mi)) {
                    bnet_regex_store[i].fn(bnet, regex, text, mi);
                    regex_matched = TRUE;
                }
                if (mi != NULL) {
                    g_match_info_free(mi);
                    mi = NULL;
                }
                handled = TRUE;
            }

            i++;
        }

        if (!regex_matched) {
            //bnet_recv_event_INFO(bnet, chat, "Battle.net Line", text, 0, -1);
        }
    }
    g_free(text);
}

static void
bnet_parse_packet(BnetConnectionData *bnet, const guint8 packet_id, const gchar *packet_start, const guint16 packet_len)
{
    BnetPacket *pkt = NULL;

    purple_debug_misc("bnet", "BNCS S>C 0x%02x: length %d\n", packet_id, packet_len);

    pkt = bnet_packet_refer(packet_start, packet_len);

    switch (packet_id) {
        case BNET_SID_NULL:
            // do nothing bnet_recv_NULL();
            break;
        case BNET_SID_CLIENTID:
            // do nothing bnet_recv_CLIENTID(bnet, pkt);
            break;
        case BNET_SID_STARTVERSIONING:
            bnet_recv_STARTVERSIONING(bnet, pkt);
            break;
        case BNET_SID_REPORTVERSION:
            bnet_recv_REPORTVERSION(bnet, pkt);
            break;
        case BNET_SID_ENTERCHAT:
            bnet_recv_ENTERCHAT(bnet, pkt);
            break;
        case BNET_SID_GETCHANNELLIST:
            bnet_recv_GETCHANNELLIST(bnet, pkt);
            break;
        case BNET_SID_CHATEVENT:
            bnet_recv_CHATEVENT(bnet, pkt);
            break;
        case BNET_SID_FLOODDETECTED:
            // handle and ignore
            break;
        case BNET_SID_MESSAGEBOX:
            bnet_recv_MESSAGEBOX(bnet, pkt);
            break;
        case BNET_SID_LOGONCHALLENGEEX:
            bnet_recv_LOGONCHALLENGEEX(bnet, pkt);
            break;
        case BNET_SID_PING:
            bnet_recv_PING(bnet, pkt);
            break;
        case BNET_SID_READUSERDATA:
            bnet_recv_READUSERDATA(bnet, pkt);
            break;
        case BNET_SID_LOGONCHALLENGE:
            bnet_recv_LOGONCHALLENGE(bnet, pkt);
            break;
        case BNET_SID_CDKEY:
            bnet_recv_CDKEY(bnet, pkt);
            break;
        case BNET_SID_W3PROFILE:
            bnet_recv_W3PROFILE(bnet, pkt);
            break;
        case BNET_SID_CDKEY2:
            bnet_recv_CDKEY2(bnet, pkt);
            break;
        case BNET_SID_CREATEACCOUNT2:
            bnet_recv_CREATEACCOUNT2(bnet, pkt);
            break;
        case BNET_SID_LOGONREALMEX:
            bnet_recv_LOGONREALMEX(bnet, pkt);
            break;
        case BNET_SID_QUERYREALMS2:
            bnet_recv_QUERYREALMS2(bnet, pkt);
            break;
        case BNET_SID_W3GENERAL:
            bnet_recv_W3GENERAL(bnet, pkt);
            break;
        case BNET_SID_NEWS_INFO:
            bnet_recv_NEWS_INFO(bnet, pkt);
            break;
        case BNET_SID_OPTIONALWORK:
        case BNET_SID_REQUIREDWORK:
            // handle and ignore
            break;
        case BNET_SID_AUTH_INFO:
            bnet_recv_AUTH_INFO(bnet, pkt);
            break;
        case BNET_SID_AUTH_CHECK:
            bnet_recv_AUTH_CHECK(bnet, pkt);
            break;
        case BNET_SID_AUTH_ACCOUNTCREATE:
            bnet_recv_AUTH_ACCOUNTCREATE(bnet, pkt);
            break;
        case BNET_SID_AUTH_ACCOUNTLOGON:
            bnet_recv_AUTH_ACCOUNTLOGON(bnet, pkt);
            break;
        case BNET_SID_AUTH_ACCOUNTLOGONPROOF:
            bnet_recv_AUTH_ACCOUNTLOGONPROOF(bnet, pkt);
            break;
        case BNET_SID_SETEMAIL:
            bnet_recv_SETEMAIL(bnet, pkt);
            break;
        case BNET_SID_LOGONRESPONSE2:
            bnet_recv_LOGONRESPONSE2(bnet, pkt);
            break;
        case BNET_SID_FRIENDSLIST:
            bnet_recv_FRIENDSLIST(bnet, pkt);
            break;
        case BNET_SID_FRIENDSUPDATE:
            bnet_recv_FRIENDSUPDATE(bnet, pkt);
            break;
        case BNET_SID_FRIENDSADD:
            bnet_recv_FRIENDSADD(bnet, pkt);
            break;
        case BNET_SID_FRIENDSREMOVE:
            bnet_recv_FRIENDSREMOVE(bnet, pkt);
            break;
        case BNET_SID_FRIENDSPOSITION:
            bnet_recv_FRIENDSPOSITION(bnet, pkt);
            break;
        case BNET_SID_CLANFINDCANDIDATES:
            bnet_recv_CLANFINDCANDIDATES(bnet, pkt);
            break;
        case BNET_SID_CLANINVITEMULTIPLE:
            bnet_recv_CLANINVITEMULTIPLE(bnet, pkt);
            break;
        case BNET_SID_CLANCREATIONINVITATION:
            bnet_recv_CLANCREATIONINVITATION(bnet, pkt);
            break;
        case BNET_SID_CLANDISBAND:
            bnet_recv_CLANDISBAND(bnet, pkt);
            break;
        case BNET_SID_CLANMAKECHIEFTAIN:
            bnet_recv_CLANMAKECHIEFTAIN(bnet, pkt);
            break;
        case BNET_SID_CLANINFO:
            bnet_recv_CLANINFO(bnet, pkt);
            break;
        case BNET_SID_CLANQUITNOTIFY:
            bnet_recv_CLANQUITNOTIFY(bnet, pkt);
            break;
        case BNET_SID_CLANINVITATION:
            bnet_recv_CLANINVITATION(bnet, pkt);
            break;
        case BNET_SID_CLANREMOVEMEMBER:
            bnet_recv_CLANREMOVEMEMBER(bnet, pkt);
            break;
        case BNET_SID_CLANINVITATIONRESPONSE:
            bnet_recv_CLANINVITATIONRESPONSE(bnet, pkt);
            break;
        case BNET_SID_CLANRANKCHANGE:
            bnet_recv_CLANRANKCHANGE(bnet, pkt);
            break;
        case BNET_SID_CLANMOTD:
            bnet_recv_CLANMOTD(bnet, pkt);
            break;
        case BNET_SID_CLANMEMBERLIST:
            bnet_recv_CLANMEMBERLIST(bnet, pkt);
            break;
        case BNET_SID_CLANMEMBERREMOVED:
            bnet_recv_CLANMEMBERREMOVED(bnet, pkt);
            break;
        case BNET_SID_CLANMEMBERSTATUSCHANGE:
            bnet_recv_CLANMEMBERSTATUSCHANGE(bnet, pkt);
            break;
        case BNET_SID_CLANMEMBERRANKCHANGE:
            bnet_recv_CLANMEMBERRANKCHANGE(bnet, pkt);
            break;
        case BNET_SID_CLANMEMBERINFO:
            bnet_recv_CLANMEMBERINFO(bnet, pkt);
            break;
        default:
            // unhandled
            purple_debug_warning("bnet", "Received unhandled packet 0x%02x, length %d\n", packet_id, packet_len);
            break;
    }

    bnet_packet_free(pkt);
}

static void
bnet_request_set_email_null_cb(gpointer data)
{
    BnetConnectionData *bnet;
    PurpleRequestFields *fields;
    GList *group_list; PurpleRequestFieldGroup *group;
    GList *field_list; PurpleRequestField *field;
    gboolean donotaskagain = FALSE;

    bnet = data;
    g_return_if_fail(bnet != NULL);
    fields = bnet->set_email_fields;
    g_return_if_fail(fields != NULL);
    group_list = g_list_first(purple_request_fields_get_groups(fields));
    g_return_if_fail(group_list != NULL);
    group = group_list->data; // only one group
    g_return_if_fail(group != NULL);
    field_list = g_list_first(purple_request_field_group_get_fields(group));

    while (field_list != NULL) {
        field = field_list->data;
        if (field != NULL) {
            const gchar *name = purple_request_field_get_id(field);
            if (strcmp(name, "donotaskagain") == 0) {
                donotaskagain = purple_request_field_bool_get_value(field);
            }
        }
        field_list = g_list_next(field_list);
    }
    if (donotaskagain) {
        bnet_send_SETEMAIL(bnet, "");
    }
}

static void
bnet_request_set_email_cb(gpointer data)
{
    BnetConnectionData *bnet;
    PurpleRequestFields *fields;
    GList *group_list; PurpleRequestFieldGroup *group;
    GList *field_list; PurpleRequestField *field;
    const char *email = NULL;
    const char *email2 = NULL;
    gboolean donotaskagain = FALSE;

    bnet = data;
    g_return_if_fail(bnet != NULL);
    fields = bnet->set_email_fields;
    g_return_if_fail(fields != NULL);
    group_list = g_list_first(purple_request_fields_get_groups(fields));
    g_return_if_fail(group_list != NULL);
    group = group_list->data; // only one group
    g_return_if_fail(group != NULL);
    field_list = g_list_first(purple_request_field_group_get_fields(group));

    while (field_list != NULL) {
        field = field_list->data;
        if (field != NULL) {
            const gchar *name = purple_request_field_get_id(field);
            if (strcmp(name, "email") == 0) {
                email = purple_request_field_string_get_value(field);
            } else if (strcmp(name, "email2") == 0) {
                email2 = purple_request_field_string_get_value(field);
            } else if (strcmp(name, "donotaskagain") == 0) {
                donotaskagain = purple_request_field_bool_get_value(field);
            }
        }
        field_list = g_list_next(field_list);
    }
    if (donotaskagain && (email == NULL || strlen(email) == 0) && (email2 == NULL || strlen(email2) == 0)) {
        // both fields are empty and DoNotAsk is checked
        // set null
        bnet_send_SETEMAIL(bnet, "");
    } else if (email != NULL && email2 != NULL && strcmp(email, email2) == 0 && strlen(email) > 0) {
        // both fields have content and they match
        // ignore DoNotAsk and set this content
        bnet_send_SETEMAIL(bnet, email);
    } else {
        // one or both fields have content but they don't match
        // request again
        bnet_request_set_email(bnet, TRUE);
    }
}

static void
bnet_request_set_email(BnetConnectionData *bnet, gboolean nomatch_error)
{
    gchar *group_text = g_strdup_printf("Bind an e-mail address to %s on %s%s", bnet->username, bnet->server, nomatch_error ? " (addresses did not match!)" : "");
    PurpleRequestField *field;
    PurpleRequestFields *fields = purple_request_fields_new();
    PurpleRequestFieldGroup *group = purple_request_field_group_new("If you wish to bind an e-mail address, do so here.");

    field = purple_request_field_string_new("email", "e-mail address", "", FALSE);
    purple_request_field_group_add_field(group, field);
    purple_request_field_string_set_editable(field, TRUE);
    purple_request_field_set_type_hint(field, "email");

    field = purple_request_field_string_new("email2", "Retype e-mail address", "", FALSE);
    purple_request_field_group_add_field(group, field);
    purple_request_field_string_set_editable(field, TRUE);
    purple_request_field_set_required(field, FALSE);

    field = purple_request_field_bool_new("donotaskagain", "Do not ask again for this account. \n"
            "This will bind an \"empty\" address to your account. \n"
            "You will not be able to recover this account's password.", FALSE);
    purple_request_field_group_add_field(group, field);

    purple_request_fields_add_group(fields, group);

    bnet->set_email_fields = fields;

    purple_debug_warning("bnet", "Battle.net wants to register an email address with this account.\n");
    purple_request_fields(bnet->account->gc, "Bind an e-mail address",
            group_text,
            "This address can be used later to recover your account. \n"
            "When telling them to reset your password, you must use this address again. \n"
            "You may safely ignore this request.",
            fields,
            "_Register", (GCallback)bnet_request_set_email_cb,
            "_Ignore", (GCallback)bnet_request_set_email_null_cb,
            bnet->account,
            NULL, NULL,
            bnet);
    g_free(group_text);
}

static void
bnet_clan_invite_accept_cb(void *data, int act_index)
{
    BnetClanInvitationCallbackData *callback_data = data;
    BnetConnectionData *bnet = callback_data->bnet;
    BnetPacketID packet_id = callback_data->packet_id;
    gint32 cookie = callback_data->cookie;
    BnetClanTag clan_tag = callback_data->clan_tag;
    gchar *inviter = callback_data->inviter;
    gchar *clan_name = callback_data->clan_name;

    g_free(callback_data);

    if (packet_id == BNET_SID_CLANCREATIONINVITATION) {
        bnet_send_CLANCREATIONINVITATION(bnet, cookie, clan_tag, inviter, TRUE);
    } else if (packet_id == BNET_SID_CLANINVITATIONRESPONSE) {
        bnet_send_CLANINVITATIONRESPONSE(bnet, cookie, clan_tag, inviter, TRUE);
    }

    g_free(inviter);
    g_free(clan_name);
}

static void
bnet_clan_invite_decline_cb(void *data, int act_index)
{
    BnetClanInvitationCallbackData *callback_data = data;
    BnetConnectionData *bnet = callback_data->bnet;
    BnetPacketID packet_id = callback_data->packet_id;
    gint32 cookie = callback_data->cookie;
    BnetClanTag clan_tag = callback_data->clan_tag;
    gchar *inviter = callback_data->inviter;
    gchar *clan_name = callback_data->clan_name;

    g_free(callback_data);

    if (packet_id == BNET_SID_CLANCREATIONINVITATION) {
        bnet_send_CLANCREATIONINVITATION(bnet, cookie, clan_tag, inviter, FALSE);
    } else if (packet_id == BNET_SID_CLANINVITATIONRESPONSE) {
        bnet_send_CLANINVITATIONRESPONSE(bnet, cookie, clan_tag, inviter, FALSE);
    }

    g_free(inviter);
    g_free(clan_name);
}

/*
   static void
   bnet_queue(const BnetConnectionData *bnet, BnetQueueElement *qel)
   {
   int delay = 1;
   delay += (bnet_packet_get_length(qel->pkt));
   qel->delay = delay;

   g_queue_push_head(bnet->action_q, qel);
   }

   static void
   bnet_dequeue_tick(const BnetConnectionData *bnet)
   {
   gboolean last_responded = FALSE;
   if (bnet->active_q_item) {
   if (!bnet->active_q_item->responded) {
   last_responded = TRUE;
   }
   }
   if (!g_queue_is_empty(bnet->action_q)) {
   BnetQueueElement *qel = g_queue_peek_tail(bnet->action_q);
   if (qel->delay > 0 || !last_responded)
   qel->delay -= 100;
   } else {
   bnet_dequeue(bnet);
   }
   }
   }


   static int
   bnet_dequeue(const BnetConnectionData *bnet)
   {
   BnetQueueElement *qel = g_queue_pop_tail(bnet->action_q);
   int ret = -1;

   if (bnet->active_q_item) {
   g_free(bnet->active_q_item);
   }
   bnet->active_q_item = qel;
   ret = bnet_packet_send(bnet, qel->pkt, qel->pkt_id, bnet->sbncs.fd);
   if (qel->pkt_response == 0xFF) {
   qel->responded = TRUE;
   }

   return ret;
   }*/

static gint
bnet_channel_user_compare(gconstpointer a, gconstpointer b)
{
    const BnetChannelUser *bcu = a;
    const char *usr = b;
    const char *a_n = NULL;
    const char *b_n = NULL;
    char *a_nc;
    int cmp = 0;
    if (a == NULL || b == NULL) {
        return 1;
    }
    if (bcu->username == NULL) {
        return 1;
    }
    a_n = bnet_normalize(NULL, bcu->username);
    a_nc = g_strdup(a_n);
    b_n = bnet_normalize(NULL, usr);
    cmp = strcmp(a_nc, b_n);
    g_free(a_nc);
    return cmp;
}

static gint
bnet_friend_user_compare(gconstpointer a, gconstpointer b)
{
    const BnetFriendInfo *bfi = a;
    const char *usr = b;
    const char *a_n = NULL;
    const char *b_n = NULL;
    char *a_nc;
    int cmp = 0;
    if (a == NULL || b == NULL) {
        return 1;
    }
    if (bfi->account == NULL) {
        return 1;
    }
    a_n = bnet_normalize(NULL, bfi->account);
    a_nc = g_strdup(a_n);
    b_n = bnet_normalize(NULL, usr);
    cmp = strcmp(a_nc, b_n);
    g_free(a_nc);
    return cmp;
}

static PurpleCmdRet
bnet_handle_cmd(PurpleConversation *conv, const gchar *cmdword,
        gchar **args, gchar **error, void *data)
{
    struct BnetCommand *c = data;
    PurpleConnection *gc;
    BnetConnectionData *bnet;
    char *cmd;
    char *s_args;

    gc = purple_conversation_get_gc(conv);
    if (!gc)
        return PURPLE_CMD_RET_FAILED;

    bnet = gc->proto_data;

    if (!bnet)
        return PURPLE_CMD_RET_FAILED;

    if (!c)
        return PURPLE_CMD_RET_FAILED;

    if (!args) {
        s_args = g_malloc0(1);
    } else {
        s_args = g_strjoinv(" ", args);

        if (strlen(s_args) == 0) {
            char *tmp = g_malloc0(1);
            g_free(s_args);
            s_args = tmp;
        } else {
            char *tmp;
            if ((c->bnetflags & BNET_CMD_FLAG_STAROND2) == BNET_CMD_FLAG_STAROND2)
                tmp = g_strdup_printf(" %s%s", bnet->d2_star, s_args);
            else
                tmp = g_strdup_printf(" %s", s_args);
            g_free(s_args);
            s_args = tmp;
        }
    }

    if (c->id == BNET_CMD_WHISPER && strlen(s_args) > 1 &&
            g_strstr_len(s_args + 1, strlen(s_args - 1) - 1, " ") != NULL) {

        char *who = g_strdup(s_args + 1);
        const char *norm = NULL;
        char *whatloc = g_strstr_len(s_args + 1, strlen(s_args - 1) - 1, " ");
        char *what = g_strdup(whatloc + 1);
        PurpleConvIm *im = NULL;
        PurpleConversation *conv = NULL;

        *(who + (whatloc - s_args - 1)) = '\0';
        norm = bnet_d2_normalize(bnet->account, who);

        conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, bnet->account, norm);
        im = PURPLE_CONV_IM(conv);
        purple_conversation_present(conv);

        purple_conv_im_send(im, what);
        g_free(who);
        g_free(what);
        g_free(s_args);
        return PURPLE_CMD_RET_OK;
    }

    cmd = g_strdup_printf("/%s%s", cmdword, s_args);
    if ((c->bnetflags & BNET_CMD_FLAG_INFORESPONSE) == BNET_CMD_FLAG_INFORESPONSE) {
        bnet->last_command_conv = conv;
    } else {
        bnet->last_command_conv = NULL;
    }
    if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM &&
            (c->bnetflags & BNET_CMD_FLAG_WHISPERPRPLCONTINUE) == BNET_CMD_FLAG_WHISPERPRPLCONTINUE) {
        PurpleConvIm *im = purple_conversation_get_im_data(conv);
        if (im) {
            purple_conv_im_send(im, cmd);
        } else {
            if (bnet->emulate_telnet) {
                bnet_send_telnet_line(bnet, cmd);
            } else {
                bnet_send_CHATCOMMAND(bnet, cmd);
            }
        }
    } else {
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, cmd);
        } else {
            bnet_send_CHATCOMMAND(bnet, cmd);
        }
    }

    g_free(cmd);
    g_free(s_args);

    if (c->bnetflags & BNET_CMD_FLAG_PRPLCONTINUE) {
        return PURPLE_CMD_RET_CONTINUE;
    }

    return PURPLE_CMD_RET_OK;
}

static double
bnet_get_tz_bias(void)
{
    time_t t_local, t_utc;
    struct tm *tm_utc = NULL;

    t_local = time(NULL);
    tm_utc = gmtime(&t_local);
    t_utc = mktime(tm_utc);

    return difftime(t_utc, t_local);
}

static char *
bnet_format_time(guint64 unixtime)
{
    time_t ut = 0;
    struct tm *t = NULL;

    if (unixtime == 0) {
        return g_strdup("never");
    }

    ut = unixtime;
    t = localtime(&ut);

    return g_strdup(asctime(t));
}

#define FILETIME_TICK 10000000LL
#define FILETIME_TO_UNIXTIME_DIFF 11644473600LL
static char *
bnet_format_filetime_string(char *ftime_str)
{
    union {
        struct {
            guint32 dwLowDateTime;
            guint32 dwHighDateTime;
        } as_ft; // filetime parts
        guint64 as_int64;
    } data;
    char *space_loc; // used to parse string

    if (strlen(ftime_str) == 0) {
        return g_strdup("never");
    }

    data.as_ft.dwHighDateTime = (guint32)g_ascii_strtoull(ftime_str, &space_loc, 10);
    data.as_ft.dwLowDateTime = 0;
    if (space_loc != NULL) {
        data.as_ft.dwLowDateTime = (guint32)g_ascii_strtoull(space_loc + 1, NULL, 10);
    }

    return bnet_format_filetime(data.as_int64);
}

static char *
bnet_format_filetime(guint64 ft)
{
    guint64 ut = (ft / FILETIME_TICK - FILETIME_TO_UNIXTIME_DIFF);

    return bnet_format_time(ut);
}

static guint64
bnet_get_filetime(time_t time)
{
    guint64 ft; // filetime
    guint64 ut; // unixtime
    ut = time;
    ft = (ut + FILETIME_TO_UNIXTIME_DIFF) * FILETIME_TICK;

    return ft;
}

static char *
bnet_format_strsec(char *secs_str)
{
    gchar *days_str;

    guint64 total_secs = g_ascii_strtoull(secs_str, NULL, 10);
    guint32 mins = total_secs / 60;
    guint32 hrs = mins / 60;
    guint32 days = hrs / 24;
    guint32 secs = total_secs % 60;
    mins %= 60;
    hrs %= 24;

    if (strlen(secs_str) == 0 || secs <= 0) {
        return g_strdup("0 seconds");
    }

    if (days == 1) {
        days_str = "";
    } else {
        days_str = "s";
    }

    return g_strdup_printf("%d day%s, %d:%02d:%02d", days, days_str, hrs, mins, secs);
}

static void
bnet_find_detached_buddies(BnetConnectionData *bnet)
{
    GSList *all_buddies;
    GSList *el;
    PurpleBuddy *buddy;
    BnetFriendInfo *bfi;

    all_buddies = purple_find_buddies(bnet->account, NULL);
    el = all_buddies;
    while (el != NULL) {
        buddy = el->data;
        bfi = purple_buddy_get_protocol_data(buddy);
        if (bfi == NULL) {
            purple_prpl_got_user_status(bnet->account, purple_buddy_get_name(buddy),
                    BNET_STATUS_OFFLINE, NULL);
        }
        el = g_slist_next(el);
    }
    g_slist_free(all_buddies);
}

static void
bnet_do_whois(const BnetConnectionData *bnet, const char *who)
{
    gchar *cmd;

    cmd = g_strdup_printf("/whois %s%s", bnet->d2_star, who);
    if (bnet->emulate_telnet) {
        bnet_send_telnet_line(bnet, cmd);
    } else {
        bnet_send_CHATCOMMAND(bnet, cmd);
    }
    g_free(cmd);
}

static void
bnet_friend_update(const BnetConnectionData *bnet, int index,
        BnetFriendInfo *bfi, BnetFriendStatus status,
        BnetFriendLocation location, BnetProductID product_id,
        const gchar *location_name)
{
    PurpleBuddy *buddy = NULL;
    BnetFriendStatus whoising = 0;

    g_return_if_fail(bfi != NULL);

    buddy = purple_find_buddy(bnet->account, bfi->account);

    if (!buddy) {
        // get or create default "Buddies" group
        PurpleGroup *grp = purple_group_new(purple_account_get_string(bnet->account, "grpfriends", BNET_DEFAULT_GROUP_FRIENDS));
        // create a new buddy
        buddy = purple_buddy_new(bnet->account, bfi->account, bfi->account);
        // add to the buddy list
        purple_blist_add_buddy(buddy, NULL, grp, NULL);
    }

    purple_buddy_set_protocol_data(buddy, bfi);

    bfi->buddy = buddy;

    if (bfi->status == status && bfi->location == location &&
            bfi->product == product_id && strcmp(bfi->location_name, location_name) == 0) {
        // this friend status unchanged
        // we're done
        return;
    } else {
        // something changed
        bfi->status = status;
        bfi->location = location;
        bfi->product = product_id;
        g_free(bfi->location_name);
        bfi->location_name = g_strdup(location_name);
    }

    purple_debug_info("bnet", "purple_prpl_got_user_status for %s\n", bfi->account);
    if (bfi->location == BNET_FRIEND_LOCATION_OFFLINE) {
        purple_prpl_got_user_status(bnet->account, bfi->account,
                BNET_STATUS_OFFLINE, NULL);
    } else {
        purple_prpl_got_user_status(bnet->account, bfi->account,
                BNET_STATUS_ONLINE, NULL);

        if (bfi->status & BNET_FRIEND_STATUS_AWAY) {
            purple_prpl_got_user_status(bnet->account, bfi->account,
                    BNET_STATUS_AWAY, NULL);

            whoising |= BNET_FRIEND_STATUS_AWAY;
        } else {
            /*purple_prpl_got_user_status(bnet->account, bfi->account,
                    BNET_STATUS_ONLINE, NULL);
            purple_prpl_got_user_status_deactive(bnet->account, bfi->account,
                    BNET_STATUS_AWAY);*/
        }

        if (bfi->status & BNET_FRIEND_STATUS_DND) {
            purple_prpl_got_user_status(bnet->account, bfi->account,
                    BNET_STATUS_DND, NULL);

            whoising |= BNET_FRIEND_STATUS_DND;
        } else {
            /*purple_prpl_got_user_status_deactive(bnet->account, bfi->account,
                    BNET_STATUS_DND);*/
        }
    }

    if (whoising) {
        // TODO: make queue and put this as low priority
        bfi->automated_lookup = whoising;
        bnet_do_whois(bnet, bfi->account);
    }
}

static void
bnet_close(PurpleConnection *gc)
{
    int i;
    BnetConnectionData *bnet = gc->proto_data;
    //purple_connection_set_state(gc, PURPLE_DISCONNECTED);
    if (bnet != NULL) {
        bnet->channel_first_join = FALSE;
        bnet->is_online = FALSE;
        bnet->sent_enter_channel = FALSE;
        if (bnet->ka_handle != 0) {
            purple_debug_info("bnet", "free ka_handle\n");
            purple_timeout_remove(bnet->ka_handle);
            bnet->ka_handle = 0;
        }
        if (bnet->alo_handle != 0) {
            purple_debug_info("bnet", "free alo_handle\n");
            purple_timeout_remove(bnet->alo_handle);
            bnet->alo_handle = 0;
        }
        if (bnet->bnls_server != NULL) {
            purple_debug_info("bnet", "free bnls_server\n");
            g_free(bnet->bnls_server);
            bnet->bnls_server = NULL;
        }
        if (bnet->sbnls.fd != 0) {
            purple_debug_info("bnet", "free sbnls struct\n");
            bnet_input_free(&bnet->sbnls);
        }
        if (bnet->sbncs.fd != 0) {
            purple_debug_info("bnet", "free sbnet struct\n");
            bnet_input_free(&bnet->sbncs);
        }
        if (bnet->sd2mcp.fd != 0) {
            purple_debug_info("bnet", "free sd2mcp struct\n");
            bnet_input_free(&bnet->sd2mcp);
        }
        if (bnet->username != NULL) {
            purple_debug_info("bnet", "free username\n");
            g_free(bnet->username);
            bnet->username = NULL;
        }
        if (bnet->my_statstring != NULL) {
            purple_debug_info("bnet", "free my_statstring\n");
            g_free(bnet->my_statstring);
            bnet->my_statstring = NULL;
        }
        if (bnet->my_accountname != NULL) {
            purple_debug_info("bnet", "free my_accountname\n");
            g_free(bnet->my_accountname);
            bnet->my_accountname = NULL;
        }
        if (bnet->unique_username != NULL) {
            purple_debug_info("bnet", "free unique_username\n");
            g_free(bnet->unique_username);
            bnet->unique_username = NULL;
        }
        if (bnet->clan_info != NULL) {
            purple_debug_info("bnet", "free clan_info\n");
            bnet_clan_info_free(bnet->clan_info, !bnet->clan_members_in_blist);
            bnet->clan_info = NULL;
        }
        if (bnet->channel_list != NULL) {
            purple_debug_info("bnet", "free channel_list\n");
            _g_list_free_full(bnet->channel_list, g_free);
            bnet->channel_list = NULL;
        }
        if (bnet->channel_name != NULL) {
            purple_debug_info("bnet", "free channel_name\n");
            g_free(bnet->channel_name);
            bnet->channel_name = NULL;
        }
        if (bnet->channel_users != NULL) {
            purple_debug_info("bnet", "free channel_users\n");
            _g_list_free_full(bnet->channel_users, (GDestroyNotify)bnet_channel_user_free);
            bnet->channel_users = NULL;
        }
        if (bnet->friends_list != NULL) {
            purple_debug_info("bnet", "free friends_list\n");
            _g_list_free_full(bnet->friends_list, (GDestroyNotify)bnet_friend_info_free);
            bnet->friends_list = NULL;
        }
        if (bnet->news != NULL) {
            purple_debug_info("bnet", "free news\n");
            _g_list_free_full(bnet->news, (GDestroyNotify)bnet_news_item_free);
            bnet->news = NULL;
        }
        for (i = 0; i < BNET_MOTD_TYPES; i++) {
            bnet_motd_free(bnet, i);
        }
        if (bnet->away_msg != NULL) {
            purple_debug_info("bnet", "free away_msg\n");
            g_free(bnet->away_msg);
            bnet->away_msg = NULL;
        }
        if (bnet->dnd_msg != NULL) {
            purple_debug_info("bnet", "free dnd_msg\n");
            g_free(bnet->dnd_msg);
            bnet->dnd_msg = NULL;
        }
        if (bnet->server != NULL) {
            purple_debug_info("bnet", "free server\n");
            g_free(bnet->server);
            bnet->server = NULL;
        }
        if (bnet->account_data != NULL) {
            purple_debug_info("bnet", "free account_data\n");
            srp_free(bnet->account_data);
            bnet->account_data = NULL;
        }
        if (bnet->last_sent_to != NULL) {
            purple_debug_info("bnet", "free last_sent_to\n");
            g_free(bnet->last_sent_to);
            bnet->last_sent_to = NULL;
        }
        if (bnet->joining_channel != NULL) {
            purple_debug_info("bnet", "free joining_channel\n");
            g_free(bnet->joining_channel);
            bnet->joining_channel = NULL;
        }
        bnet_lookup_info_close(bnet);
        g_free(bnet);
        bnet = NULL;
    }
}

// bnet doesn't allow anything below ' ' (nulls, tabs, or newlines), so this function is pointless
// but...
// this function ignores the len if > than any NULs, but otherwise sends anything you put into it
static int
bnet_send_raw(PurpleConnection *gc, const char *buf, int len)
{
    BnetConnectionData *bnet = gc->proto_data;
    char *mybuf = g_strdup(buf);
    int ret = -1;

    char *msg_s = NULL;
    char *msg_locale = NULL;

    if (len < strlen(mybuf)) {
        mybuf[len] = '\0'; // end
    }

    msg_s = purple_markup_strip_html(mybuf);
    msg_locale = bnet_locale_from_utf8(msg_s);

    if (bnet->emulate_telnet) {
        ret = bnet_send_telnet_line(bnet, msg_locale);
    } else {
        ret = bnet_send_CHATCOMMAND(bnet, msg_locale);
    }
    g_free(msg_locale);
    g_free(msg_s);
    g_free(mybuf);

    return ret;
}

/*If the message is too big to be sent, return -E2BIG.  If
 * the account is not connected, return -ENOTCONN.  If the
 * PRPL is unable to send the message for another reason, return
 * some other negative value.  You can use one of the valid
 * errno values, or just big something.  If the message should
 * not be echoed to the conversation window, return 0.*/
static int
bnet_send_whisper(PurpleConnection *gc, const char *who,
        const char *message, PurpleMessageFlags flags)
{
    BnetConnectionData *bnet = gc->proto_data;
    char *msg_nohtml;
    char *cmd;
    int msg_len;

    if (!bnet->is_online) {
        return -ENOTCONN;
    }

    if (strpbrk(message, "\t\v\r\n") != NULL) {
        return -BNET_EBADCHARS;
    }

    msg_nohtml = purple_markup_strip_html(message);
    if (strlen(msg_nohtml) > BNET_MSG_MAXSIZE) {
        return -E2BIG;
    }

    cmd = g_strdup_printf("/w %s%s %s",
            bnet->d2_star, who, msg_nohtml);
    if (bnet->emulate_telnet) {
        bnet_send_telnet_line(bnet, cmd);
    } else {
        bnet_send_CHATCOMMAND(bnet, cmd);
    }
    g_free(cmd);

    if (bnet->last_sent_to != NULL) g_free(bnet->last_sent_to);
    bnet->last_sent_to = g_strdup(who);
    bnet->awaiting_whisper_confirm = TRUE;

    msg_len = strlen(msg_nohtml);

    g_free(msg_nohtml);

    return msg_len;
}

/**
 * Should arrange for purple_notify_userinfo() to be called with
 * @a who's user info.
 */
static void
bnet_lookup_info(PurpleConnection *gc, const char *who)
{
    BnetConnectionData *bnet = gc->proto_data;
    const char *norm = bnet_normalize(bnet->account, who);

    if (bnet->lookup_info_user != NULL) {
        g_free(bnet->lookup_info_user);
    }
    if (bnet->lookup_info != NULL) {
        purple_notify_user_info_destroy(bnet->lookup_info);
    }
    // see these fields in bnet.h for what they mean
    bnet->lookup_info = purple_notify_user_info_new();
    bnet->lookup_info_user = g_strdup(norm);
    bnet->lookup_info_first_section = TRUE;
    bnet->lookup_info_got_locprod = FALSE;
    bnet->lookup_info_found_clan = FALSE;
    bnet->lookup_info_clan = (BnetClanTag)0;
    bnet->lookup_info_await = BNET_LOOKUP_INFO_AWAIT_NONE;

    // show user info
    // step 1: get data from channel list (stored in bnet->channel_users)
    bnet_lookup_info_cached_channel(bnet);

    // step 2: get data from friends list (stored in bnet->friends_list)
    bnet_lookup_info_cached_friends(bnet);

    // step 2: do a /whois (await EID_INFO response)
    // PRECOND: must not have gotten location and product information from channel or friend list
    if (!bnet->lookup_info_got_locprod) {
        bnet_lookup_info_whois(bnet);
    }

    // step 3...: get data from profile
    if (bnet_is_w3(bnet)) {
        // step 3: get data from clan member list (stored in bnet->clan_member_list)
        bnet_lookup_info_cached_clan(bnet);

        // step 4a: get clan tag then we can optionally get clan stats and clan member join date later
        // PRECOND: must not have "found" clan tag
        if (!bnet->lookup_info_found_clan) {
            // step 4a.1: get clan tag from W3 profile (await SID_W3PROFILE response)
            bnet_lookup_info_w3_user_profile(bnet);
            
            // to do on receiving SID_W3PROFILE...
            // step 4b.2: get user data we won't get via SID_W3PROFILE: profile\sex, system\*...
            // bnet_lookup_info_user_data(bnet);
            // step 4a.3: get W3 stats (await SID_WARCRAFTGENERAL.WID_USERRESPONSE response)
            // bnet_lookup_info_w3_user_stats(bnet);
            // step 4a.4: get clan stats (await SID_WARCRAFTGENERAL.WID_CLANRECORD response)
            // bnet_lookup_info_w3_clan_stats(bnet);
            // step 4a.5: get clan member join date (await SID_CLANMEMBERINFO response)
            // bnet_lookup_info_w3_clan_mi(bnet);
        }
        // step 4b: get clan stats and clan member join date now
        // PRECOND: must have "found" clan tag and it is not 0
        else if (bnet->lookup_info_clan != (BnetClanTag)0) {
            // step 4b.1: get user data we won't get via SID_W3PROFILE: profile\sex, system\*...
            bnet_lookup_info_user_data(bnet);
            // step 4b.2: get W3 stats (await SID_WARCRAFTGENERAL.WID_USERRESPONSE response)
            bnet_lookup_info_w3_user_stats(bnet);
            // step 4b.3: get clan stats (await SID_WARCRAFTGENERAL.WID_CLANRECORD response)
            bnet_lookup_info_w3_clan_stats(bnet);
            // step 4b.4: get clan member join date (await SID_CLANMEMBERINFO response)
            bnet_lookup_info_w3_clan_mi(bnet);
        }
        // step 4c: don't do anything more because we know that the user is not in a clan (as seen in channel list)
        else {
            // step 4c.1: get user data we won't get via SID_W3PROFILE: profile\sex, system\*...
            bnet_lookup_info_user_data(bnet);
            // step 4c.2: get W3 stats (await SID_WARCRAFTGENERAL.WID_USERRESPONSE response)
            bnet_lookup_info_w3_user_stats(bnet);
        }
    } else if (!bnet->emulate_telnet) {
        // step 3 (non-W3): get user data
        bnet_lookup_info_user_data(bnet);
    }

    if (bnet->lookup_info_await == BNET_LOOKUP_INFO_AWAIT_NONE) {
        purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
                bnet->lookup_info, bnet_lookup_info_close, bnet);
    }
}

static void
bnet_lookup_info_close(gpointer user_data)
{
    BnetConnectionData *bnet = (BnetConnectionData *)user_data;
    if (bnet->lookup_info_user != NULL) {
        g_free(bnet->lookup_info_user);
        bnet->lookup_info_user = NULL;
    }
    if (bnet->lookup_info != NULL) {
        purple_notify_user_info_destroy(bnet->lookup_info);
        bnet->lookup_info = NULL;
    }
    purple_debug_info("bnet", "Lookup closed by user\n");
    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_CANCELLED;
}

static gboolean
bnet_lookup_info_cached_channel(BnetConnectionData *bnet)
{
    GList *li = g_list_find_custom(bnet->channel_users, bnet->lookup_info_user, bnet_channel_user_compare);
    BnetChannelUser *bcu;
    char *s_ping;
    char *s_caps = g_malloc0(1);
    BnetProductID product_id;
    char *product;
    char *location_string;
    //char *s_stats;

    char *start; char *loc;
    char *key; char *value;
    //guint32 icon_id; - assigned but not used
    char *s_clan;

    if (li == NULL) {
        // the user was not in our channel
        return FALSE;
    }

    purple_debug_info("bnet", "Lookup local found: CHANNEL_LIST(%s)\n", bnet->lookup_info_user);

    bcu = li->data;

    s_ping = g_strdup_printf("%dms", bcu->ping);

    if (bcu->flags & BNET_USER_FLAG_BLIZZREP) {
        char *tmp = g_strdup("Blizzard Representative");
        g_free(s_caps);
        s_caps = tmp;
    }

    if (bcu->flags & BNET_USER_FLAG_OP) {
        if (strlen(s_caps)) {
            char *tmp = g_strdup_printf("%s, Channel Operator", s_caps);
            g_free(s_caps);
            s_caps = tmp;
        } else {
            char *tmp = g_strdup("Channel Operator");
            g_free(s_caps);
            s_caps = tmp;
        }
    }

    if (bcu->flags & BNET_USER_FLAG_BNETADMIN) {
        if (strlen(s_caps)) {
            char *tmp = g_strdup_printf("%s, Battle.net Administrator", s_caps);
            g_free(s_caps);
            s_caps = tmp;
        } else {
            char *tmp = g_strdup("Battle.net Administrator");
            g_free(s_caps);
            s_caps = tmp;
        }
    }

    if (bcu->flags & BNET_USER_FLAG_NOUDP) {
        if (strlen(s_caps)) {
            char *tmp = g_strdup_printf("%s, No UDP Support", s_caps);
            g_free(s_caps);
            s_caps = tmp;
        } else {
            char *tmp = g_strdup("No UDP Support");
            g_free(s_caps);
            s_caps = tmp;
        }
    }

    if (bcu->flags & BNET_USER_FLAG_SQUELCH) {
        if (strlen(s_caps)) {
            char *tmp = g_strdup_printf("%s, Squelched", s_caps);
            g_free(s_caps);
            s_caps = tmp;
        } else {
            char *tmp = g_strdup("Squelched");
            g_free(s_caps);
            s_caps = tmp;
        }
    }

    if (strlen(s_caps) == 0) {
        char *tmp = g_strdup("Normal");
        g_free(s_caps);
        s_caps = tmp;
    }

    product_id = bnet_clan_string_to_tag(bcu->stats_data);
    product = bnet_get_product_name(product_id);

    location_string = bnet_get_location_text(BNET_FRIEND_LOCATION_CHANNEL, bnet->channel_name);

    if (!bnet->lookup_info) {
        bnet->lookup_info = purple_notify_user_info_new();
    } else if (!bnet->lookup_info_first_section) {
        purple_notify_user_info_add_section_break(bnet->lookup_info);
    }
    bnet->lookup_info_first_section = FALSE;

    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current location", location_string);
    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current product", product);
    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Ping at logon", s_ping);
    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Channel capabilities", s_caps);

    start = g_strdup(bcu->stats_data + 4);
    loc = start;
    bnet->lookup_info_found_clan = TRUE;
    switch (product_id) {
        case BNET_PRODUCT_STAR:
        case BNET_PRODUCT_SEXP:
        case BNET_PRODUCT_SSHR:
        case BNET_PRODUCT_JSTR:
        case BNET_PRODUCT_W2BN:
            {
                guint32 l_rating, l_rank, wins, spawn, l_hirating;

                loc++;
                l_rating = g_ascii_strtod(loc, &loc);
                loc++;
                l_rank = g_ascii_strtod(loc, &loc);
                loc++;
                wins = g_ascii_strtod(loc, &loc);
                loc++;
                spawn = g_ascii_strtod(loc, &loc);
                loc++;
                g_ascii_strtod(loc, &loc);
                loc++;
                l_hirating = g_ascii_strtod(loc, &loc);
                loc++;
                g_ascii_strtod(loc, &loc);
                loc++;
                g_ascii_strtod(loc, &loc);
                loc++;
                //icon_id = *((guint32 *)loc);
                if (l_rating || l_rank || l_hirating) {
                    key = g_strdup_printf("%s ladder rating", product);
                    value = g_strdup_printf("%d (high: %d)", l_rating, l_hirating);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, key, value);
                    g_free(key); g_free(value);

                    key = g_strdup_printf("%s ladder rank", product);
                    value = g_strdup_printf("%d", l_rank);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, key, value);
                    g_free(key); g_free(value);
                }
                if (wins) {
                    key = g_strdup_printf("%s wins", product);
                    value = g_strdup_printf("%d", wins);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, key, value);
                    g_free(key); g_free(value);
                }
                if (spawn) {
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Spawned client", "Yes");
                }
                break;
            }
        case BNET_PRODUCT_DRTL:
        case BNET_PRODUCT_DSHR:
            {
                char *tmp;
                guint32 char_lvl = 0, char_class = 0, char_dots = 0;
                guint32 char_str = 0, char_mag = 0, char_dex = 0, char_vit = 0;
                guint32 char_gold = 0, spawn = 0;

                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_lvl = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_class = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_dots = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_str = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_mag = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_dex = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_vit = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    char_gold = g_ascii_strtod(loc, &loc);
                if (strlen(loc))
                    loc++;
                if (strlen(loc))
                    spawn = g_ascii_strtod(loc, NULL);

                if (char_lvl) {
                    tmp = g_strdup_printf("%d", char_lvl);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character level", tmp);
                    g_free(tmp);
                }
                if (TRUE) { // char_class can = 0
                    char *char_type_name;
                    switch (char_class) {
                        default: char_type_name = "Unknown";  break;
                        case 0:  char_type_name = "Warrior";  break;
                        case 1:  char_type_name = "Sorcerer"; break;
                        case 2:  char_type_name = "Rogue";    break;
                    }
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character class", char_type_name);
                }
                if (TRUE) { // char_dots can = 0
                    char *char_diff_text;
                    switch (char_dots) {
                        default:
                        case 0: char_diff_text = "None";      break;
                        case 1: char_diff_text = "Normal";    break;
                        case 2: char_diff_text = "Nightmare"; break;
                        case 3: char_diff_text = "Hell";      break;
                    }
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Last difficulty completed", char_diff_text);
                }
                if (char_str || char_mag || char_dex || char_vit || char_gold) {
                    tmp = g_strdup_printf("%d", char_str);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character strength", tmp);
                    g_free(tmp);

                    tmp = g_strdup_printf("%d", char_mag);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character magic", tmp);
                    g_free(tmp);

                    tmp = g_strdup_printf("%d", char_dex);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character dexterity", tmp);
                    g_free(tmp);

                    tmp = g_strdup_printf("%d", char_vit);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character vitality", tmp);
                    g_free(tmp);

                    tmp = g_strdup_printf("%d", char_gold);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character gold", tmp);
                    g_free(tmp);
                }
                purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Spawned client", spawn ? "Yes" : "No");
                break;
            }
        case BNET_PRODUCT_D2DV:
        case BNET_PRODUCT_D2XP:
            {
                char *tmp;
                if (strlen(loc) == 0) {
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info,
                            "Diablo II character", "an open Battle.net character");
                } else {
                    char *realm_name; char *char_name; unsigned char *bytes;
                    unsigned char char_type, char_level, char_creation_flags, char_current_act, char_ladder_season;
                    char *char_type_name;
                    //gboolean is_exp;
                    char *char_diff_text;

                    g_strdelimit(loc, ",", '\0'); // replace commas with nulls for easier reading
                    realm_name = loc;
                    loc += strlen(realm_name) + 1;
                    char_name = loc;
                    loc += strlen(char_name) + 1;
                    bytes = (unsigned char *)loc;
                    char_type = bytes[13];
                    char_level = bytes[25];
                    char_creation_flags = bytes[26];
                    char_current_act = bytes[27];
                    char_ladder_season = bytes[30];

                    switch (char_type) {
                        default:   char_type_name = "Unknown";     break;
                        case 0x01: char_type_name = "Amazon";      break;
                        case 0x02: char_type_name = "Sorceress";   break;
                        case 0x03: char_type_name = "Necromancer"; break;
                        case 0x04: char_type_name = "Paladin";     break;
                        case 0x05: char_type_name = "Barbarian";   break;
                        case 0x06: char_type_name = "Druid";       break;
                        case 0x07: char_type_name = "Assassin";    break;
                    }

                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Diablo II realm", realm_name);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Diablo II character", char_name);

                    tmp = g_strdup_printf("%d", char_level);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character level", tmp);
                    g_free(tmp);
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Character class", char_type_name);

                    //[28] Current act data: 100YYXX0
                    // where bits YYXX are distinct for normal
                    //  YY=difficulty XX=act because there happens to be 4 acts in normal
                    // but in expansion, this is not so
                    //  YYXX=act + (difficulty*5)
                    // in both cases act goes from 0 to 3 (or 4 on exp, but this isn't used!)
                    // and difficulty goes from 0 to 3
                    //  when difficulty=3, act=0, means "all acts"
                    char_current_act = (char_current_act ^ 0x80) >> 1; // cancel 10000000 bit and ignore lowest bit
                    if (char_creation_flags & 0x20) {
                        switch (char_current_act) {
                            default:
                            case 0x0: case 0x1: case 0x2: case 0x3: case 0x4: 
                                char_diff_text = "None";      break;
                            case 0x5: case 0x6: case 0x7: case 0x8: case 0x9: 
                                char_diff_text = "Normal";    break;
                            case 0xA: case 0xB: case 0xC: case 0xD: case 0xE:
                                char_diff_text = "Nightmare"; break;
                            case 0xF:
                                char_diff_text = "Hell";      break;
                        }
                    } else {
                        switch (char_current_act >> 2) { // only highest 2 bits matter for norm
                            default:
                                //0000, 0001, 0010, 0011
                            case 0x0:
                                char_diff_text = "None";      break;
                                //0100, 0101, 0110, 0111
                            case 0x1:
                                char_diff_text = "Normal";    break;
                                //1000, 1001, 1010, 1011
                            case 0x2:
                                char_diff_text = "Nightmare"; break;
                                //1100
                            case 0x3:
                                char_diff_text = "Hell";      break;
                        }
                    }
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Last difficulty completed", char_diff_text);

                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Ladder character", (char_ladder_season == 0xFF) ? "No" : "Yes");
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Expansion character", (char_creation_flags & 0x20) ? "Yes" : "No");
                    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Hardcore character", (char_creation_flags & 0x04) ? "Yes" : "No");
                    if (char_creation_flags & 0x04) {
                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Dead", (char_creation_flags & 0x08) ? "Yes" : "No");
                    }
                }
                break;
            }
        case BNET_PRODUCT_WAR3:
        case BNET_PRODUCT_W3XP:
            {
                char *tmp;
                guint32 level = 0;
                int clan_len;

                bnet->lookup_info_found_clan = FALSE;
                if (strlen(loc)) {
                    loc++;
                    //icon_id = *((guint32 *)loc);
                    loc += 5;
                    level = g_ascii_strtod(loc, &loc);

                    // note: we only can say we "found" whether the user is in a clan if the user has
                    // a statstring. if they do not, then we do not know!
                    bnet->lookup_info_found_clan = TRUE;
                    if (strlen(loc)) {
                        loc++;
                        clan_len = strlen(loc);
                        s_clan = g_malloc0(5);
                        bnet->lookup_info_clan = (BnetClanTag)0;
                        g_memmove(s_clan, loc, clan_len);
                        bnet->lookup_info_clan = bnet_clan_string_to_tag(s_clan);
                        g_free(s_clan);
                    } else {
                        bnet->lookup_info_clan = (BnetClanTag)0;
                    }

                    if (level) {
                        tmp = g_strdup_printf("%d", level);
                        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Warcraft III level", tmp);
                        g_free(tmp);
                    }
                }
                break;
            }
    }

    g_free(start);
    g_free(location_string);

    bnet->lookup_info_got_locprod = TRUE;

//    purple_notify_userinfo(bnet->account->gc, who,
//            bnet->lookup_info, bnet_lookup_info_close, bnet);

    return TRUE;
}

static gboolean
bnet_lookup_info_cached_friends(BnetConnectionData *bnet)
{
    const char *acct_norm = bnet_account_normalize(bnet->account, bnet->lookup_info_user);
    GList *li = g_list_find_custom(bnet->friends_list, acct_norm, bnet_friend_user_compare);
    BnetFriendInfo *bfi;

    if (li == NULL) {
        // the user was not on our friends list
        return FALSE;
    }

    purple_debug_info("bnet", "Lookup local found: FRIENDS_LIST(%s)\n", acct_norm);

    bfi = li->data;

    if (!bnet->lookup_info) {
        bnet->lookup_info = purple_notify_user_info_new();
    } else if (!bnet->lookup_info_first_section) {
        purple_notify_user_info_add_section_break(bnet->lookup_info);
    }
    bnet->lookup_info_first_section = FALSE;

    purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Mutual friend",
            (bfi->status & BNET_FRIEND_STATUS_MUTUAL) ? "Yes" : "No");

    if (!bnet->lookup_info_got_locprod) {
        gchar *location_text = bnet_get_location_text(bfi->location, bfi->location_name);
        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current location", location_text);
        g_free(location_text);
        if (bfi->location != BNET_FRIEND_LOCATION_OFFLINE) {
            purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Current product", bnet_get_product_name(bfi->product));
        }
    }
    if (bfi->status & BNET_FRIEND_STATUS_DND) {
        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Do Not Disturb", bfi->dnd_stored_status);
    }
    if (bfi->status & BNET_FRIEND_STATUS_AWAY) {
        purple_notify_user_info_add_pair_plaintext(bnet->lookup_info, "Away", bfi->away_stored_status);
    }

    bnet->lookup_info_got_locprod = TRUE;

//    purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
//            bnet->lookup_info, bnet_lookup_info_close, bnet);

    return TRUE;
}

static gboolean
bnet_lookup_info_cached_clan(BnetConnectionData *bnet)
{
    const char *acct_norm = bnet_account_normalize(bnet->account, bnet->lookup_info_user);
    const BnetClanMember *bcmi = NULL;
    BnetClanTag clan_tag;
    gchar *s_clan = NULL;
    
    if (bnet->clan_info != NULL && bnet_clan_info_get_tag(bnet->clan_info) == 0) {
        return FALSE;
    }

    bcmi = bnet_clan_info_get_member(bnet->clan_info, acct_norm);
    clan_tag = bnet_clan_info_get_tag(bnet->clan_info);
    s_clan = bnet_clan_tag_to_string(clan_tag);

    if (bcmi == NULL) {
        return FALSE;
    }

    bnet->lookup_info_found_clan = TRUE;
    bnet->lookup_info_clan = clan_tag;

    purple_debug_info("bnet", "Lookup local found: W3_CLAN_LIST(%s, Clan %s)\n", acct_norm, s_clan);

//    if (!bnet->lookup_info) {
//        bnet->lookup_info = purple_notify_user_info_new();
//    } else if (!bnet->lookup_info_first_section) {
//        purple_notify_user_info_add_section_break(bnet->lookup_info);
//    }
//    bnet->lookup_info_first_section = FALSE;

//    purple_notify_userinfo(bnet->account->gc, bnet->lookup_info_user,
//            bnet->lookup_info, bnet_lookup_info_close, bnet);

    g_free(s_clan);

    return TRUE;
}

static void
bnet_lookup_info_whois(BnetConnectionData *bnet)
{
    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_WHOIS;
    purple_debug_info("bnet", "Lookup: WHOIS(%s)\n", bnet->lookup_info_user);

    bnet_do_whois(bnet, bnet->lookup_info_user);
}

static void
bnet_lookup_info_user_data(BnetConnectionData *bnet)
{
    gchar *final_request;
    BnetUserDataRequest *req;
    BnetUserDataRequestType request_type;
    gboolean is_self = FALSE;
    int recordbits = 0;
    char **keys;
    int request_cookie = g_str_hash(bnet->lookup_info_user);
    char *acct_norm = g_strdup(bnet_account_normalize(bnet->account, bnet->lookup_info_user));
    char *uu_norm = g_strdup(bnet_account_normalize(bnet->account, bnet_normalize(bnet->account, bnet->unique_username)));

    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_USER_DATA;
    purple_debug_info("bnet", "Lookup: USER_DATA(%s)\n", acct_norm);

    if (strcmp(uu_norm, acct_norm) == 0) {
        final_request = g_strdup_printf("%s\n%s", BNET_USERDATA_PROFILE_REQUEST, BNET_USERDATA_SYSTEM_REQUEST);
        is_self = TRUE;
    } else {
        final_request = g_strdup(BNET_USERDATA_PROFILE_REQUEST);
    }

    switch (bnet->game) {
        case BNET_GAME_TYPE_SSHR:
            recordbits = BNET_RECORD_NORMAL;
            break;
        case BNET_GAME_TYPE_W2BN:
            recordbits = BNET_RECORD_NORMAL |
                BNET_RECORD_LADDER |
                BNET_RECORD_IRONMAN;
            break;
        case BNET_GAME_TYPE_STAR:
        case BNET_GAME_TYPE_SEXP:
        case BNET_GAME_TYPE_JSTR:
            recordbits = BNET_RECORD_NORMAL |
                BNET_RECORD_LADDER;
            break;
        case BNET_GAME_TYPE_DRTL:
        case BNET_GAME_TYPE_DSHR:
        case BNET_GAME_TYPE_D2DV:
        case BNET_GAME_TYPE_D2XP:
        case BNET_GAME_TYPE_WAR3:
        case BNET_GAME_TYPE_W3XP:
            recordbits = BNET_RECORD_NONE;
            break;
    }

    if (recordbits & BNET_RECORD_NORMAL) {
        char *product_id = bnet_get_product_id_str(bnet->product_id);
        char *request_part = g_strdup_printf(BNET_USERDATA_RECORD_REQUEST(product_id, BNET_USERDATA_RECORD_NORMAL));
        char *request_combined = g_strdup_printf("%s\n%s", final_request, request_part);
        g_free(final_request);
        final_request = request_combined;
        g_free(product_id);
        g_free(request_part);
    }

    if (recordbits & BNET_RECORD_LADDER) {
        char *product_id = bnet_get_product_id_str(bnet->product_id);
        char *request_part = g_strdup_printf(BNET_USERDATA_RECORD_LADDER_REQUEST(product_id, BNET_USERDATA_RECORD_LADDER));
        char *request_combined = g_strdup_printf("%s\n%s", final_request, request_part);
        g_free(final_request);
        final_request = request_combined;
        g_free(product_id);
        g_free(request_part);
    }

    if (recordbits & BNET_RECORD_IRONMAN) {
        char *product_id = bnet_get_product_id_str(bnet->product_id);
        char *request_part = g_strdup_printf(BNET_USERDATA_RECORD_LADDER_REQUEST(product_id, BNET_USERDATA_RECORD_IRONMAN));
        char *request_combined = g_strdup_printf("%s\n%s", final_request, request_part);
        g_free(final_request);
        final_request = request_combined;
        g_free(product_id);
        g_free(request_part);
    }

    keys = g_strsplit(final_request, "\n", -1);

    request_type = BNET_READUSERDATA_REQUEST_PROFILE |
        ((is_self) ? BNET_READUSERDATA_REQUEST_SYSTEM : 0) |
        ((recordbits == BNET_RECORD_NONE) ? 0 : BNET_READUSERDATA_REQUEST_RECORD);

    req = bnet_userdata_request_new(request_cookie, request_type,
            acct_norm, keys,
            bnet->product_id);

    bnet->userdata_requests = g_list_append(bnet->userdata_requests, req);

    bnet_send_READUSERDATA(bnet, request_cookie, acct_norm, keys);

    g_free(final_request);
    g_free(acct_norm);
    g_free(uu_norm);
}

static void
bnet_lookup_info_w3_user_profile(BnetConnectionData *bnet)
{
    char *acct_norm = g_strdup(bnet_account_normalize(bnet->account, bnet->lookup_info_user));
    guint32 cookie;

    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_W3_USER_PROFILE;
    purple_debug_info("bnet", "Lookup: W3_USER_PROFILE(%s)\n", acct_norm);
    
    cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_W3PROFILE, g_strdup(acct_norm));

    bnet_send_W3PROFILE(bnet, cookie, acct_norm);
    
    g_free(acct_norm);
}

static void
bnet_lookup_info_w3_user_stats(BnetConnectionData *bnet)
{
    char *acct_norm = g_strdup(bnet_account_normalize(bnet->account, bnet->lookup_info_user));
    guint32 cookie;

    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_W3_USER_STATS;
    purple_debug_info("bnet", "Lookup: W3_USER_STATS(%s)\n", acct_norm);

    cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_W3GENERAL, g_strdup(acct_norm));

    bnet_send_W3GENERAL_USERRECORD(bnet, cookie, acct_norm, bnet->product_id);
    
    g_free(acct_norm);
}

static void
bnet_lookup_info_w3_clan_stats(BnetConnectionData *bnet)
{
    gchar *s_clan = bnet_clan_tag_to_string(bnet->lookup_info_clan);
    guint32 cookie;

    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_W3_CLAN_STATS;
    purple_debug_info("bnet", "Lookup: W3_CLAN_STATS(Clan %s)\n", s_clan);

    cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_W3GENERAL, s_clan);

    bnet_send_W3GENERAL_CLANRECORD(bnet, cookie, bnet->lookup_info_clan, bnet->product_id);
}

static void
bnet_lookup_info_w3_clan_mi(BnetConnectionData *bnet)
{
    gchar *s_clan = bnet_clan_tag_to_string(bnet->lookup_info_clan);
    char *acct_norm = g_strdup(bnet_account_normalize(bnet->account, bnet->lookup_info_user));
    guint32 cookie;

    bnet->lookup_info_await |= BNET_LOOKUP_INFO_AWAIT_W3_CLAN_MI;
    purple_debug_info("bnet", "Lookup: W3_CLAN_MI(%s, Clan %s)\n", acct_norm, s_clan);

    cookie = bnet_clan_packet_register(bnet->clan_info, BNET_SID_CLANMEMBERINFO, s_clan);

    bnet_send_CLANMEMBERINFO(bnet, cookie, bnet->lookup_info_clan, acct_norm);
    
    g_free(acct_norm);
}

static void
bnet_action_set_motd_cb(gpointer data)
{
    BnetConnectionData *bnet;
    PurpleRequestFields *fields;
    GList *group_list; PurpleRequestFieldGroup *group;
    GList *field_list; PurpleRequestField *field = NULL;
    const char *motd = NULL;

    bnet = data;
    g_return_if_fail(bnet != NULL);
    fields = bnet->set_motd_fields;
    g_return_if_fail(fields != NULL);
    group_list = g_list_first(purple_request_fields_get_groups(fields));
    g_return_if_fail(group_list != NULL);
    group = group_list->data; // only one group
    g_return_if_fail(group != NULL);
    field_list = g_list_first(purple_request_field_group_get_fields(group));
    
    if (field_list != NULL) {
        field = field_list->data; // only one field
    }
    if (field != NULL) {
        motd = purple_request_field_string_get_value(field);
    }
    if (motd == NULL) {
        motd = "";
    }

    if (bnet->clan_info != NULL &&
            bnet_clan_info_get_tag(bnet->clan_info) != 0) {
        BnetClanMemberRank rank = bnet_clan_info_get_my_rank(bnet->clan_info);
        if (rank == BNET_CLAN_RANK_CHIEFTAIN || rank == BNET_CLAN_RANK_SHAMAN) {
            PurpleConversation *conv = NULL;
            PurpleConvChat *chat = NULL;
            bnet_send_CLANSETMOTD(bnet, 0xbaadf00du, motd);
            //bnet_clan_info_set_motd(bnet->clan_info, g_strdup(motd));
            if (!bnet->channel_first_join && bnet->channel_id != 0) {
                conv = purple_find_chat(bnet->account->gc, bnet->channel_id);
            }
            if (conv != NULL) {
                chat = purple_conversation_get_chat_data(conv);
            }
            if (chat != NULL && bnet_clan_is_clan_channel(bnet->clan_info, bnet->channel_name)) {
                purple_conv_chat_set_topic(chat, "(clan leader)", motd);
            }
        }
    }
}

static gint
bnet_news_item_sort(gconstpointer a, gconstpointer b)
{
    const BnetNewsItem *news_a = a;
    const BnetNewsItem *news_b = b;
    
    return news_b->timestamp - news_a->timestamp;
}

static gchar *
bnet_locale_full_escape_nullable(const gchar *input)
{
    gchar *r1;
    gchar *r2;

    if (input == NULL) {
        return NULL;
    }
    
    r1 = bnet_locale_to_utf8(input);
    r2 = bnet_escape_text(r1, -1, TRUE);
    g_free(r1);
    return r2;
}

static void
bnet_cache_set(BnetConnectionData *bnet, gchar *name, guint64 timestamp, gchar *key, gchar *val)
{
    xmlnode *current_cache;
    xmlnode *file;
    xmlnode *file_child;
    gboolean was_set = FALSE;
    gchar *output;
    int length;
    
    current_cache = purple_util_read_xml_from_file(BNET_FILE_CACHE, "Battle.net data cache");
    
    if (current_cache != NULL) {
        // wrong root name, replace
        if (!g_str_equal(current_cache->name, "cache")) {
            xmlnode_free(current_cache);
            current_cache = xmlnode_new("cache");
        }
        
        // find any matching entries and replace them
        for (file = current_cache->child; file; file = file->next) {
            if (file->type != XMLNODE_TYPE_TAG) {
                continue;
            }
            if (g_str_equal(file->name, "file")) {
                gchar *current_name = g_strdup(xmlnode_get_attrib(file, "name"));
                gchar *current_key = g_strdup(xmlnode_get_attrib(file, "key"));
                if (g_str_equal(name, current_name) &&
                        g_str_equal(key, current_key)) {
                    gchar buf[G_ASCII_DTOSTR_BUF_SIZE];
                    g_ascii_dtostr(buf, G_ASCII_DTOSTR_BUF_SIZE, timestamp);
                    xmlnode_set_attrib(file,"timestamp", buf);
                    for (file_child = file->child; file_child; file_child = file_child->next) {
                        if (file_child->type != XMLNODE_TYPE_DATA) {
                            continue;
                        }
                        g_free(file_child->data);
                        file_child->data = val;
                        was_set = TRUE;
                    }
                    if (!was_set) {
                        xmlnode_insert_data(file, val, -1);
                        was_set = TRUE;
                    }
                    break;
                }
            }
        }
    } else {
        current_cache = xmlnode_new("cache");
    }
    
    // not found, new file
    if (!was_set) {
        xmlnode *file = xmlnode_new_child(current_cache, "file");
        gchar buf[G_ASCII_DTOSTR_BUF_SIZE];
        g_ascii_dtostr(buf, G_ASCII_DTOSTR_BUF_SIZE, timestamp);
        xmlnode_set_attrib(file, "name", name);
        xmlnode_set_attrib(file, "key", key);
        xmlnode_set_attrib(file, "timestamp", buf);
        xmlnode_insert_data(file, val, -1);
    }
    
    // save to bnet-cache.xml
	output = xmlnode_to_formatted_str(current_cache, &length);
	xmlnode_free(current_cache);
	purple_util_write_data_to_file(BNET_FILE_CACHE, output, length);
}

static gchar *
bnet_cache_get(BnetConnectionData *bnet, gchar *name, guint64 *timestamp, gchar *key)
{
    xmlnode *current_cache;
    xmlnode *file;
    
    *timestamp = 0;
    current_cache = purple_util_read_xml_from_file(BNET_FILE_CACHE, "Battle.net data cache");
    
    if (current_cache != NULL) {
        // wrong root name
        if (!g_str_equal(current_cache->name, "cache")) {
            return NULL;
        }
        
        // find any matching entries and replace them
        for (file = current_cache->child; file; file = file->next) {
            if (file->type != XMLNODE_TYPE_TAG) {
                continue;
            }
            if (g_str_equal(file->name, "file")) {
                const gchar *current_name = xmlnode_get_attrib(file, "name");
                const gchar *current_key = xmlnode_get_attrib(file, "key");
                if (g_str_equal(name, current_name) &&
                        g_str_equal(key, current_key)) {
                    const gchar *current_timestamp = xmlnode_get_attrib(file, "timestamp");
                    const gchar *current_value = xmlnode_get_data(file);
                    *timestamp = g_ascii_strtod(current_timestamp, NULL);
                    return g_strdup(current_value);
                }
            }
        }
    }
    
    return NULL;
}

static void
bnet_news_save(BnetConnectionData *bnet)
{
    GList *el;
    BnetPacket *pkt;
    gchar *cache_key;
    gchar *cache_val;
    
    pkt = bnet_packet_create(BNET_PACKET_RAW);
    bnet_packet_insert(pkt, bnet->server, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, &bnet->product_id, BNET_SIZE_DWORD);
    cache_key = bnet_packet_serialize(pkt);
    
    pkt = bnet_packet_create(BNET_PACKET_RAW);
    bnet_packet_insert(pkt, &bnet->news_count, BNET_SIZE_BYTE);
    el = g_list_first(bnet->news);
    while (el != NULL) {
        BnetNewsItem *item = el->data;
        
        bnet_packet_insert(pkt, &item->timestamp, BNET_SIZE_DWORD);
        bnet_packet_insert(pkt, item->message, BNET_SIZE_CSTRING);
    
        el = g_list_next(el);
    }
    cache_val = bnet_packet_serialize(pkt);
    bnet_cache_set(bnet, "pkt:SID_NEWS_INFO", bnet->news_latest, cache_key, cache_val);
    g_free(cache_key);
    g_free(cache_val);
}

static void
bnet_news_load(BnetConnectionData *bnet)
{
    BnetPacket *pkt;
    gchar *cache_key;
    gchar *cache_val;
    int i;
    guint64 timestamp;
    
    pkt = bnet_packet_create(BNET_PACKET_RAW);
    bnet_packet_insert(pkt, bnet->server, BNET_SIZE_CSTRING);
    bnet_packet_insert(pkt, &bnet->product_id, BNET_SIZE_DWORD);
    cache_key = bnet_packet_serialize(pkt);
    cache_val = bnet_cache_get(bnet, "pkt:SID_NEWS_INFO", &timestamp, cache_key);
    
    bnet->news_latest = timestamp;
    if (cache_val == NULL) {
        bnet->news_count = 0;
        bnet->news = NULL;
    } else {
        pkt = bnet_packet_deserialize(cache_val);
        if (bnet_packet_can_read(pkt, 1)) {
            bnet->news_count = bnet_packet_read_byte(pkt);
            for (i = 0; i < bnet->news_count; i++) {
                BnetNewsItem *item = g_new0(BnetNewsItem, 1);
                guint32 timestamp = bnet_packet_read_dword(pkt);
                gchar *message = bnet_packet_read_cstring(pkt);
                GList *el2 = g_list_first(bnet->news);
                
                while (el2 != NULL) {
                    if (((BnetNewsItem *)el2->data)->timestamp == timestamp) {
                        purple_debug_warning("bnet", "duplicate in bnet_news_load\n");
                    }
                    el2 = g_list_next(el2);
                }
                
                item->timestamp = timestamp;
                item->message = message;
                
                bnet->news = g_list_append(bnet->news, item);
            }
        }
        bnet_packet_free(pkt);
        g_free(cache_val);
    }
    g_free(cache_key);
}

static void
bnet_action_show_news(PurplePluginAction *action)
{
    PurpleConnection *gc = action->context;
    BnetConnectionData *bnet = gc->proto_data;
    GList *el = NULL;
    gchar *formatted = g_malloc0(1);
    int i;

    if (bnet->news != NULL) {
        for (i = 0; i < BNET_MOTD_TYPES; i++) {
            const gchar *type;
            gchar *name;
            gchar *subname;
            gchar *message;
            gchar *s_name;
            gchar *s_message;
            gchar *sum;
            
            switch (i) {
                default:
                case BNET_MOTD_TYPE_BNCS:
                    type = "Message of the Day for Battle.net";
                    break;
                case BNET_MOTD_TYPE_BNLS:
                    type = "Message from the Battle.net Logon Server";
                    break;
                case BNET_MOTD_TYPE_D2MCP:
                    type = "Message of the Day for the Diablo II Realm";
                    break;
                case BNET_MOTD_TYPE_CLAN:
                    type = "Message of the Day for your Warcraft III Clan";
                    break;
                case BNET_MOTD_TYPE_WCG_T:
                    type = "Tournament Information for WCG";
                    break;
                case BNET_MOTD_TYPE_W3_T:
                    type = "Tournament Information for Warcraft III";
                    break;
            }
            
            name = bnet_locale_full_escape_nullable(bnet->motds[i].name);
            subname = bnet_locale_full_escape_nullable(bnet->motds[i].subname);
            message = bnet_locale_full_escape_nullable(bnet->motds[i].message);
            
            if (name != NULL || message != NULL) {
                if (name != NULL) {
                    if (subname != NULL) {
                        s_name = g_strdup_printf("<i>%s: %s</i><br>", name, subname);
                        g_free(subname);
                    } else {
                        s_name = g_strdup_printf("<i>%s</i><br>", name);
                    }
                } else {
                    s_name = g_strdup("");
                }
                if (message != NULL) {
                    s_message = message;
                } else {
                    s_message = g_strdup("<i>No message stored.</i>");
                }
                sum = g_strdup_printf("%s<b>%s</b><br>%s%s<br><br>", formatted, type, s_name, s_message);
                g_free(formatted);
                g_free(s_name);
                g_free(s_message);
                formatted = sum;
            }
        }
        
        
        el = g_list_first(bnet->news);
        do {
            BnetNewsItem *item = el->data;
            gchar *add = NULL;
            gchar *sum = NULL;
            gchar *msgbody = bnet_locale_full_escape_nullable(item->message);
            gchar *tm = bnet_format_time(item->timestamp);
            add = g_strdup_printf("<b>%s</b><br>%s<br><br>", tm, msgbody);
            sum = g_strdup_printf("%s%s", formatted, add);
            g_free(tm);
            g_free(add);
            g_free(formatted);
            g_free(msgbody);
            formatted = sum;

            el = g_list_next(el);
        } while (el != NULL);
    }

    if (strlen(formatted) == 0) {
        g_free(formatted);
        formatted = g_strdup("<i>No news returned.</i>");
    }
    purple_notify_formatted(bnet->account->gc, "Battle.net News",
            "News for this Battle.net server.", NULL, formatted, NULL, NULL);

    g_free(formatted);
}

static void
bnet_action_set_motd(PurplePluginAction *action)
{
    PurpleConnection *gc = action->context;
    BnetConnectionData *bnet = gc->proto_data;
    PurpleRequestField *field = NULL;
    PurpleRequestFields *fields = NULL;
    PurpleRequestFieldGroup *group = NULL;
    BnetClanMemberRank my_rank = 0;
    BnetClanTag tag = 0;
    gchar *group_name = NULL;
    gchar *tag_string = NULL;
    gchar *current_motd = NULL;

    if (bnet == NULL) return;
    if (bnet->emulate_telnet) return;
    if (bnet->clan_info == NULL) return;
    if (bnet_clan_info_get_tag(bnet->clan_info) == 0) return;

    my_rank = bnet_clan_info_get_my_rank(bnet->clan_info);

    if (my_rank != BNET_CLAN_RANK_SHAMAN &&
            my_rank != BNET_CLAN_RANK_CHIEFTAIN) return;

    tag = bnet_clan_info_get_tag(bnet->clan_info);
    tag_string = bnet_clan_tag_to_string(tag);

    current_motd = bnet->motds[BNET_MOTD_TYPE_CLAN].message;
    if (current_motd == NULL) {
        current_motd = g_strdup("");
    }

    fields = purple_request_fields_new();
    group_name = g_strdup_printf("Set clan MOTD for Clan %s", tag_string);
    group = purple_request_field_group_new(group_name);

    field = purple_request_field_string_new("motd", "Message of the Day", current_motd, FALSE);
    purple_request_field_string_set_editable(field, TRUE);
    purple_request_field_set_required(field, TRUE);
    purple_request_field_string_set_value(field, current_motd);
    purple_request_field_group_add_field(group, field);

    purple_request_fields_add_group(fields, group);

    bnet->set_motd_fields = fields;

    purple_request_fields(gc, "Edit Clan MOTD", "Change this WarCraft III clan's MOTD.", NULL, fields,
            "Save", (GCallback)bnet_action_set_motd_cb, "Cancel", NULL,
            bnet->account, NULL, NULL, bnet);

    g_free(tag_string);
    g_free(group_name);
}

static void
bnet_action_set_user_data(PurplePluginAction *action)
{
    PurpleConnection *gc = action->context;
    BnetConnectionData *bnet = gc->proto_data;

    if (bnet == NULL) return;

    if (bnet->emulate_telnet) return;

    bnet_profile_get_for_edit(bnet);
}

static void
bnet_profile_get_for_edit(BnetConnectionData *bnet)
{
    const char *uu_norm = bnet_normalize(bnet->account, bnet->unique_username);
    int request_cookie = g_str_hash(uu_norm);
    BnetUserDataRequest *req;
    char **keys;

    keys = g_strsplit(BNET_USERDATA_PROFILE_REQUEST, "\n", -1);

    bnet->writing_profile = TRUE;

    req = bnet_userdata_request_new(request_cookie, BNET_READUSERDATA_REQUEST_PROFILE,
            bnet->unique_username, keys, bnet->product_id);

    bnet->userdata_requests = g_list_append(bnet->userdata_requests, req);

    bnet_send_READUSERDATA(bnet, request_cookie, bnet->unique_username, keys);
}

static void
bnet_profile_show_write_dialog(BnetConnectionData *bnet,
        const char *psex, const char *page, const char *ploc, const char *pdescr)
{
    PurpleRequestField *field;
    PurpleRequestFields *fields = purple_request_fields_new();
    gchar *group_name = g_strdup_printf("Change profile information for %s", bnet->username);
    PurpleRequestFieldGroup *group = purple_request_field_group_new(group_name);

    field = purple_request_field_string_new("profile\\sex", "Sex", psex, FALSE);
    purple_request_field_group_add_field(group, field);
    purple_request_field_string_set_editable(field, TRUE);
    purple_request_field_set_required(field, FALSE);
    purple_request_field_string_set_value(field, psex);

    /*field = purple_request_field_string_new("profile\\age", "Age", page, FALSE);
      purple_request_field_string_set_editable(field, FALSE);
      purple_request_field_set_required(field, FALSE);
      purple_request_field_string_set_value(field, page);
      purple_request_field_group_add_field(group, field);*/

    field = purple_request_field_string_new("profile\\location", "Location", ploc, FALSE);
    purple_request_field_group_add_field(group, field);
    purple_request_field_string_set_editable(field, TRUE);
    purple_request_field_set_required(field, FALSE);
    purple_request_field_string_set_value(field, ploc);

    field = purple_request_field_string_new("profile\\description", "Description", pdescr, TRUE);
    purple_request_field_group_add_field(group, field);
    purple_request_field_string_set_editable(field, TRUE);
    purple_request_field_set_required(field, FALSE);
    purple_request_field_string_set_value(field, pdescr);

    purple_request_fields_add_group(fields, group);

    bnet->profile_write_fields = fields;

    bnet->writing_profile = FALSE;

    purple_request_fields(bnet->account->gc,
            "Edit Profile",
            NULL, NULL,
            fields,
            "_Save", (GCallback)bnet_profile_write_cb,
            "_Cancel", NULL,
            bnet->account,
            NULL, NULL,
            bnet);
}

static void
bnet_profile_write_cb(gpointer data)
{
    BnetConnectionData *bnet;
    PurpleRequestFields *fields;
    GList *group_list; PurpleRequestFieldGroup *group;
    GList *field_list; PurpleRequestField *field;
    const char *s_const = "";
    const char *sex = s_const;
    const char *age = s_const;
    const char *location = s_const;
    const char *description = s_const;
    const char *field_id;

    bnet = data;
    g_return_if_fail(bnet != NULL);
    fields = bnet->set_motd_fields;
    g_return_if_fail(fields != NULL);
    group_list = g_list_first(purple_request_fields_get_groups(fields));
    g_return_if_fail(group_list != NULL);
    group = group_list->data; // only one group
    g_return_if_fail(group != NULL);
    field_list = g_list_first(purple_request_field_group_get_fields(group));

    while (field_list != NULL) {
        field = field_list->data;
        field_id = purple_request_field_get_id(field);
        if (strcmp(field_id, "profile\\sex") == 0) {
            sex = purple_request_field_string_get_value(field);
            if (sex == NULL) {
                sex = s_const;
            }
        } else if (strcmp(field_id, "profile\\age") == 0) {
            age = purple_request_field_string_get_value(field);
            if (age == NULL) {
                age = s_const;
            }
        } else if (strcmp(field_id, "profile\\location") == 0) {
            location = purple_request_field_string_get_value(field);
            if (location == NULL) {
                location = s_const;
            }
        } else if (strcmp(field_id, "profile\\description") == 0) {
            description = purple_request_field_string_get_value(field);
            if (description == NULL) {
                description = s_const;
            }
        }
        field_list = g_list_next(field_list);
    }

    if (sex != s_const ||
        age != s_const ||
        location != s_const ||
        description == s_const) {
        bnet_send_WRITEUSERDATA(bnet, sex, age, location, description);
    }
}


static GHashTable *
bnet_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
    GHashTable *defaults;

    defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

    if (chat_name != NULL)
        g_hash_table_insert(defaults, "channel", g_strdup(chat_name));

    return defaults;
}

static GList *
bnet_chat_info(PurpleConnection *gc)
{
    GList *m = NULL;
    struct proto_chat_entry *pce;

    pce = g_new0(struct proto_chat_entry, 1);
    pce->label = "_Channel:";
    pce->identifier = "channel";
    pce->required = TRUE;
    m = g_list_append(m, pce);

    return m;
}

static char *
bnet_channel_message_parse(char *stats_data, BnetChatEventFlags flags, int ping)
{
    BnetProductID product_id = bnet_clan_string_to_tag(stats_data);
    return g_strdup_printf("%dms using %s", ping, bnet_get_product_name(product_id));
}

static PurpleConvChatBuddyFlags
bnet_channel_flags_to_prpl_flags(BnetChatEventFlags flags)
{
    PurpleConvChatBuddyFlags result = 0;
    if (flags & BNET_USER_FLAG_BLIZZREP ||
            flags & BNET_USER_FLAG_BNETADMIN) {
        result |= PURPLE_CBFLAGS_FOUNDER;
    }
    if (flags & BNET_USER_FLAG_OP) {
        result |= PURPLE_CBFLAGS_OP;
    }
    if (flags & BNET_USER_FLAG_VOICE) {
        result |= PURPLE_CBFLAGS_VOICE;
    }
    return result;
}

static void
bnet_join_chat(PurpleConnection *gc, GHashTable *components)
{
    BnetConnectionData *bnet = gc->proto_data;
    char *room = g_hash_table_lookup(components, "channel");
    char *cmd;
    const char *norm = NULL;
    int chat_id = 0;

    if (room == NULL) {
        // the roomlist API stores it in "name" instead of "channel"?
        room = g_hash_table_lookup(components, "name");
        if (room == NULL) {
            // we can't find any room names, get out of here
            return;
        }
    }

    purple_debug_info("bnet", "Attempting to join channel %s...\n", room);

    norm = bnet_normalize(bnet->account, room);
    chat_id = g_str_hash(norm);

    if (bnet->channel_id == chat_id) {
        PurpleConversation *conv = NULL;

        serv_got_chat_left(gc, bnet->channel_id);

        bnet->channel_id = chat_id;

        conv = serv_got_joined_chat(gc, chat_id, bnet->channel_name);

        if (bnet->channel_users != NULL) {
            PurpleConvChat *chat = NULL;
            if (!bnet->channel_first_join && conv != NULL)
                chat = purple_conversation_get_chat_data(conv);
            if (chat != NULL) {
                GList *users = NULL;
                GList *extras = NULL;
                GList *flags = NULL;
                GList *el = g_list_first(bnet->channel_users);
                //int i = 0;
                while (el != NULL) {
                    BnetChannelUser *bcuel = el->data;
                    int bcuelflags = bnet_channel_flags_to_prpl_flags(bcuel->flags);

                    users = g_list_prepend(users, bcuel->username);
                    extras = g_list_prepend(extras, bnet_channel_message_parse(bcuel->stats_data, bcuel->flags, bcuel->ping));
                    flags = g_list_prepend(flags, GINT_TO_POINTER(bcuelflags));
                    //i++;
                    //purple_debug_info("bnet", "%d: %s status: %d\n", i, bcuel->username, bcuel->status);
                    el = g_list_next(el);
                }
                purple_conv_chat_add_users(chat, users, extras, flags, FALSE);
                g_list_free(users);
                _g_list_free_full(extras, g_free);
                g_list_free(flags);
            }
        }

        return;
    }

    bnet->joining_channel = g_strdup(room);

    cmd = g_strdup_printf("/join %s", room);
    if (bnet->emulate_telnet) {
        bnet_send_telnet_line(bnet, cmd);
    } else {
        bnet_send_CHATCOMMAND(bnet, cmd);
    }
    g_free(cmd);
}

static int
bnet_chat_im(PurpleConnection *gc, int chat_id, const char *message, PurpleMessageFlags flags)
{
    BnetConnectionData *bnet = gc->proto_data;
    char *msg_nohtml;

    if (!bnet->is_online) {
        return -ENOTCONN;
    }
    if (strpbrk(message, "\t\v\r\n") != NULL) {
        return -BNET_EBADCHARS;
    }
    msg_nohtml = purple_unescape_text(message);
    if (strlen(message) > BNET_MSG_MAXSIZE) {
        return -E2BIG;
    }

    if (message[0] == '/') {
        PurpleConversation *conv = purple_find_chat(gc, bnet->channel_id);
        PurpleConvChat *chat = NULL;
        if (conv != NULL) {
            chat = purple_conversation_get_chat_data(conv);
        }
        if (chat != NULL) {
            gchar *e = NULL;
            if (purple_cmd_do_command(conv, msg_nohtml + 1, msg_nohtml + 1, &e) == PURPLE_CMD_STATUS_NOT_FOUND) {
                if (bnet->emulate_telnet) {
                    bnet_send_telnet_line(bnet, (char *)msg_nohtml);
                } else {
                    bnet_send_CHATCOMMAND(bnet, (char *)msg_nohtml);
                }
            }

            if (e != NULL) {
                serv_got_chat_in(gc, bnet->channel_id, "", PURPLE_MESSAGE_ERROR, e, time(NULL));
            }
        }
        g_free(msg_nohtml);
        return 0;
    } else {
        int len = strlen(msg_nohtml);
        gchar *esc_text = bnet_escape_text(msg_nohtml, -1, FALSE);
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, (char *)msg_nohtml);
        } else {
            bnet_send_CHATCOMMAND(bnet, (char *)msg_nohtml);
        }
        serv_got_chat_in(gc, bnet->channel_id, bnet->username, PURPLE_MESSAGE_SEND, esc_text, time(NULL));
        g_free(msg_nohtml);
        return len;
    }
}

static const char *
bnet_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
    //star, sexp, d2dv, d2xp, w2bn, war3, w3xp, drtl, chat
    return "bnet";
}

static const char *
bnet_list_emblem(PurpleBuddy *b)
{
    BnetUser *bfi = purple_buddy_get_protocol_data(b);
    if (bfi == NULL) {
        return "not-authorized";
    } else if (bfi->type == BNET_USER_TYPE_FRIEND) {
        if (((BnetFriendInfo *)bfi)->location >= BNET_FRIEND_LOCATION_GAME_PUBLIC) {
            return "game";
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }
}

static char *
bnet_status_text(PurpleBuddy *b)
{
    BnetUser *bfi = purple_buddy_get_protocol_data(b);
    if (bfi == NULL) {
        return g_strdup("Not on Battle.net's friend list.");
    } else if (bfi->type == BNET_USER_TYPE_FRIEND && ((BnetFriendInfo *)bfi)->away_stored_status != NULL) {
        return g_strdup(((BnetFriendInfo *)bfi)->away_stored_status);
    } else if (bfi->type == BNET_USER_TYPE_FRIEND && ((BnetFriendInfo *)bfi)->dnd_stored_status != NULL) {
        return g_strdup(((BnetFriendInfo *)bfi)->dnd_stored_status);
    } else {
        return g_strdup("");
    }
}

static void
bnet_tooltip_text(PurpleBuddy *buddy,
        PurpleNotifyUserInfo *info,
        gboolean full)
{
    BnetUser *bfi = purple_buddy_get_protocol_data(buddy);
    purple_debug_info("bnet", "poll buddy tooltip %s \n", buddy->name);
    if (bfi == NULL) {
        // no information saved
        purple_notify_user_info_add_pair_plaintext(info, "Status", "Not on Battle.net's friend list.");
    } else if (bfi->type == BNET_USER_TYPE_FRIEND && ((BnetFriendInfo *)bfi)->location != BNET_FRIEND_LOCATION_OFFLINE) {
        // add things to online friends
        gboolean is_available = TRUE;
        purple_notify_user_info_add_pair_plaintext(info, "Mutual",
                (((BnetFriendInfo *)bfi)->status & BNET_FRIEND_STATUS_MUTUAL) ? "Yes" : "No");

        if (full) {
            gchar *location_text = bnet_get_location_text(((BnetFriendInfo *)bfi)->location, ((BnetFriendInfo *)bfi)->location_name);
            purple_notify_user_info_add_pair_plaintext(info, "Location", location_text);
            g_free(location_text);
            purple_notify_user_info_add_pair_plaintext(info, "Product",
                    bnet_get_product_name(((BnetFriendInfo *)bfi)->product));
        }

        if (((BnetFriendInfo *)bfi)->status & BNET_FRIEND_STATUS_DND) {
            purple_notify_user_info_add_pair_plaintext(info, "Status",
                    g_strdup_printf("Do Not Disturb - %s", ((BnetFriendInfo *)bfi)->dnd_stored_status));
            is_available = FALSE;
        }
        if (((BnetFriendInfo *)bfi)->status & BNET_FRIEND_STATUS_AWAY) {
            purple_notify_user_info_add_pair_plaintext(info, "Status",
                    g_strdup_printf("Away - %s", ((BnetFriendInfo *)bfi)->away_stored_status));
            is_available = FALSE;
        }
        if (is_available) {
            purple_notify_user_info_add_pair_plaintext(info, "Status", "Available");
        }
    } else if (bfi->type == BNET_USER_TYPE_CLANMEMBER) {
        BnetClanMember *bcmi = (BnetClanMember *)bfi;
        if (bnet_clan_member_get_status(bcmi) != BNET_CLAN_STATUS_OFFLINE) {
            purple_notify_user_info_add_pair_plaintext(info, "Status", "Online");
        }
        purple_notify_user_info_add_pair_plaintext(info, "Clan rank", bnet_clan_rank_to_string(bnet_clan_member_get_rank(bcmi)));
        if (bnet_clan_member_get_joindate(bcmi) != 0) {
            gchar *s_joindate = bnet_format_filetime(bnet_clan_member_get_joindate(bcmi));
            purple_notify_user_info_add_pair_plaintext(info, "Clan join date", s_joindate);
            g_free(s_joindate);
        }
    }
}

static char *
bnet_get_location_text(BnetFriendLocation location, char *location_name)
{
    switch (location)
    {
        case BNET_FRIEND_LOCATION_OFFLINE:
            return g_strdup("Offline");
        default:
        case BNET_FRIEND_LOCATION_ONLINE:
            return g_strdup("Nowhere");
        case BNET_FRIEND_LOCATION_CHANNEL:
            if (strlen(location_name) > 0) {
                return g_strdup_printf("in channel %s", location_name);
            } else {
                return g_strdup("In a private channel");
            }
        case BNET_FRIEND_LOCATION_GAME_PUBLIC:
            if (strlen(location_name) > 0) {
                return g_strdup_printf("In the public game %s", location_name);
            } else {
                return g_strdup("In a public game");
            }
        case BNET_FRIEND_LOCATION_GAME_PRIVATE:
            if (strlen(location_name) > 0) {
                return g_strdup_printf("In the private game %s", location_name);
            } else {
                return g_strdup("In a private game");
            }
        case BNET_FRIEND_LOCATION_GAME_PROTECTED:
            if (strlen(location_name) > 0) {
                return g_strdup_printf("In the password protected game %s", location_name);
            } else {
                return g_strdup("In a password protected game");
            }
    }
}

static char *
bnet_get_product_name(BnetProductID product)
{
    switch (product)
    {
        case BNET_PRODUCT_STAR:
        case BNET_GAME_TYPE_STAR:
            return "Starcraft";
        case BNET_PRODUCT_SEXP:
        case BNET_GAME_TYPE_SEXP:
            return "Starcraft Broodwar";
        case BNET_PRODUCT_W2BN:
        case BNET_GAME_TYPE_W2BN:
            return "Warcraft II";
        case BNET_PRODUCT_D2DV:
        case BNET_GAME_TYPE_D2DV:
            return "Diablo II";
        case BNET_PRODUCT_D2XP:
        case BNET_GAME_TYPE_D2XP:
            return "Diablo II Lord of Destruction";
        case BNET_PRODUCT_WAR3:
        case BNET_GAME_TYPE_WAR3:
            return "Warcraft III";
        case BNET_PRODUCT_W3XP:
        case BNET_GAME_TYPE_W3XP:
            return "Warcraft III The Frozen Throne";
        case BNET_PRODUCT_DRTL:
        case BNET_GAME_TYPE_DRTL:
            return "Diablo";
        case BNET_PRODUCT_DSHR:
        case BNET_GAME_TYPE_DSHR:
            return "Diablo Shareware";
        case BNET_PRODUCT_SSHR:
        case BNET_GAME_TYPE_SSHR:
            return "Starcraft Shareware";
        case BNET_PRODUCT_JSTR:
        case BNET_GAME_TYPE_JSTR:
            return "Starcraft Japanese";
        case BNET_PRODUCT_CHAT:
            return "Telnet Chat";
        default:
            return "Unknown";
    }
}

static gchar *
bnet_get_product_id_str(BnetProductID product)
{
    switch (product)
    {
        case BNET_GAME_TYPE_STAR: product = BNET_PRODUCT_STAR; break;
        case BNET_GAME_TYPE_SEXP: product = BNET_PRODUCT_SEXP; break;
        case BNET_GAME_TYPE_W2BN: product = BNET_PRODUCT_W2BN; break;
        case BNET_GAME_TYPE_D2DV: product = BNET_PRODUCT_D2DV; break;
        case BNET_GAME_TYPE_D2XP: product = BNET_PRODUCT_D2XP; break;
        case BNET_GAME_TYPE_WAR3: product = BNET_PRODUCT_WAR3; break;
        case BNET_GAME_TYPE_W3XP: product = BNET_PRODUCT_W3XP; break;
        case BNET_GAME_TYPE_DRTL: product = BNET_PRODUCT_DRTL; break;
        case BNET_GAME_TYPE_DSHR: product = BNET_PRODUCT_DSHR; break;
        case BNET_GAME_TYPE_SSHR: product = BNET_PRODUCT_SSHR; break;
        case BNET_GAME_TYPE_JSTR: product = BNET_PRODUCT_JSTR; break;
    }

    return bnet_clan_tag_to_string(product);
}

static GList *
bnet_status_types(PurpleAccount *account)
{
    PurpleStatusType *type;
    GList *types = NULL;

    type = purple_status_type_new(PURPLE_STATUS_AVAILABLE,
            BNET_STATUS_ONLINE, NULL, TRUE);
    types = g_list_append(types, type);

    type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
            BNET_STATUS_AWAY, NULL, TRUE, TRUE, FALSE,
            "message", "Message", purple_value_new(PURPLE_TYPE_STRING),
            NULL);
    types = g_list_append(types, type);

    type = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, 
            BNET_STATUS_DND, NULL, TRUE, TRUE, FALSE,
            "message", "Message", purple_value_new(PURPLE_TYPE_STRING),
            NULL);
    types = g_list_append(types, type);

    type = purple_status_type_new(PURPLE_STATUS_OFFLINE,
            BNET_STATUS_OFFLINE, NULL, TRUE);
    types = g_list_append(types, type);

    return types;
}

static void
bnet_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    BnetConnectionData *bnet = gc->proto_data;

    const char *username = purple_buddy_get_name(buddy);

    char *cmd = g_strdup_printf("/f a %s",
            username);
    if (bnet->emulate_telnet) {
        bnet_send_telnet_line(bnet, cmd);
    } else {
        bnet_send_CHATCOMMAND(bnet, cmd);
    }
    g_free(cmd);
}

static void
bnet_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    BnetConnectionData *bnet = gc->proto_data;

    const char *username = purple_buddy_get_name(buddy);
    BnetUser *bfi = purple_buddy_get_protocol_data(buddy);

    char *cmd;

    // the buddy wasn't on our friends list
    if (bfi == NULL) return;

    if (bfi->type == BNET_USER_TYPE_FRIEND) {
        GList *el;
        cmd = g_strdup_printf("/f r %s", username);
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, cmd);
        } else {
            bnet_send_CHATCOMMAND(bnet, cmd);
        }
        g_free(cmd);

        // remove the data from the free list
        // purple_blist_remove_buddy will call bnet_friend_info_free and
        // friend list diff will remove the link
        el = g_list_first(bnet->friends_list);
        while (el != NULL) {
            if (el->data != NULL) {
                BnetUser *bfi_link = el->data;
                if (strcmp(bfi_link->username, bfi->username) == 0) {
                    el->data = NULL;
                }
            }
            el = g_list_next(el);
        }
    }
}

static PurpleRoomlist *
bnet_roomlist_get_list(PurpleConnection *gc)
{
    BnetConnectionData *bnet = gc->proto_data;
    GList *fields = NULL;
    PurpleRoomlistField *f;
    PurpleRoomlistRoom *r;

    if (bnet->room_list)
        purple_roomlist_unref(bnet->room_list);

    bnet->room_list = purple_roomlist_new(purple_connection_get_account(gc));

    f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, "", "channel", TRUE);
    fields = g_list_append(fields, f);

    purple_roomlist_set_fields(bnet->room_list, fields);

    if (bnet->channel_list != NULL) {
        GList *room_el = g_list_first(bnet->channel_list);
        r = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM,
                (char *)room_el->data, NULL);
        purple_roomlist_room_add(bnet->room_list, r);
        while (g_list_next(room_el) != NULL) {
            room_el = g_list_next(room_el);
            r = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM,
                    (char *)room_el->data, NULL);
            purple_roomlist_room_add(bnet->room_list, r);
        }
    }

    purple_roomlist_set_in_progress(bnet->room_list, FALSE);

    return bnet->room_list;
}

static void
bnet_roomlist_cancel(PurpleRoomlist *list)
{
    PurpleConnection *gc = purple_account_get_connection(list->account);
    BnetConnectionData *bnet;

    if (gc == NULL)
        return;

    bnet = gc->proto_data;

    purple_roomlist_set_in_progress(list, FALSE);

    if (bnet->room_list == list) {
        bnet->room_list = NULL;
        purple_roomlist_unref(list);
    }
}

static void
bnet_set_status(PurpleAccount *account, PurpleStatus *status)
{   
    const char *msg = purple_status_get_attr_string(status, "message");
    const char *type = purple_status_get_name(status);
    PurpleConnection *gc = purple_account_get_connection(account);
    BnetConnectionData *bnet = gc->proto_data;

    if (purple_status_is_online(status)) {
        if (purple_status_is_available(status)) {
            // unset away and dnd
            if (bnet->is_away) {
                bnet_set_away(bnet, FALSE, NULL);
            }
            if (bnet->is_dnd) {
                bnet_set_dnd(bnet, FALSE, NULL);
            }
        } else {
            if (strcmp(type, BNET_STATUS_AWAY) == 0) {
                if (bnet->is_dnd) {
                    bnet_set_dnd(bnet, FALSE, NULL);
                }
                bnet_set_away(bnet, TRUE, msg);
            } else if (strcmp(type, BNET_STATUS_DND) == 0) {
                if (bnet->is_away) {
                    bnet_set_away(bnet, FALSE, NULL);
                }
                bnet_set_dnd(bnet, TRUE, msg);
            }
        }
    }
}

static void
bnet_set_away(BnetConnectionData *bnet, gboolean new_state, const gchar *message)
{
    char *msg;
    if (message == NULL || strlen(message) == 0) {
        msg = g_strdup("Not available");
    } else {
        msg = g_strdup(message);
    }

    bnet->setting_away_status = TRUE;
    if (new_state) {
        char *msg_s = purple_markup_strip_html(msg);
        char *cmd = g_strdup_printf("/away %s", msg);
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, cmd);
        } else {
            bnet_send_CHATCOMMAND(bnet, cmd);
        }
        g_free(msg_s);
        g_free(cmd);

        if (bnet->away_msg != NULL) {
            g_free(bnet->away_msg);
        }
        bnet->away_msg = msg;
    } else {
        char *cmd = "/away";
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, cmd);
        } else {
            bnet_send_CHATCOMMAND(bnet, cmd);
        }

        if (bnet->away_msg != NULL) {
            g_free(bnet->away_msg);
        }
        bnet->away_msg = NULL;
        g_free(msg);
    }
}

static void
bnet_set_dnd(BnetConnectionData *bnet, gboolean new_state, const gchar *message)
{
    char *msg;
    if (message == NULL || strlen(message) == 0) {
        msg = g_strdup("Not available");
    } else {
        msg = g_strdup(message);
    }

    bnet->setting_dnd_status = TRUE;
    if (new_state) {
        char *msg_s = purple_markup_strip_html(msg);
        char *cmd = g_strdup_printf("/dnd %s", msg);
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, cmd);
        } else {
            bnet_send_CHATCOMMAND(bnet, cmd);
        }
        g_free(msg_s);
        g_free(cmd);

        if (bnet->dnd_msg != NULL) {
            g_free(bnet->dnd_msg);
        }
        bnet->dnd_msg = msg;
    } else {
        char *cmd = "/dnd";
        if (bnet->emulate_telnet) {
            bnet_send_telnet_line(bnet, cmd);
        } else {
            bnet_send_CHATCOMMAND(bnet, cmd);
        }

        if (bnet->dnd_msg != NULL) {
            g_free(bnet->dnd_msg);
        }
        bnet->dnd_msg = NULL;
        g_free(msg);
    }
}

static const char *
bnet_normalize(const PurpleAccount *account, const char *in)
{
    static char out[64];

    char *o = g_ascii_strdown(in, -1);
    g_memmove((char *)out, o, strlen(o) + 1);
    g_free(o);

    return out;
}

static const char *
bnet_d2_normalize(const PurpleAccount *account, const char *in)
{
    PurpleConnection *gc = NULL;
    BnetConnectionData *bnet = NULL;
    static char o[64];
    char *d2norm = NULL;

    if (account != NULL) gc = purple_account_get_connection(account);

    if (gc != NULL) bnet = gc->proto_data;

    if (bnet != NULL && bnet_is_d2(bnet))
    {
        char *d2_star = g_strstr_len(in, 30, "*");
        if (d2_star != NULL) {
            // CHARACTER*NAME
            // CHARACTER (*NAME)
            // or *NAME
            d2norm = g_strdup(d2_star + 1);
            if (d2_star > in + 1) {
                if (*(d2_star - 1) == '(') {
                    // CHARACTER (*NAME)
                    // remove last character ")"
                    *(d2norm + strlen(d2norm) - 1) = '\0';
                }
            }
        }
    }
    if (d2norm == NULL) {
        d2norm = g_strdup(in);
    }

    g_memmove((char *)o, d2norm, strlen(d2norm) + 1);
    g_free(d2norm);
    return o;
}

// removes account numbers from accounts (Ribose#2 > Ribose; Ribose#2@Azeroth > Ribose@Azeroth)
// for SID_READUSERDATA.
static const char *
bnet_account_normalize(const PurpleAccount *account, const char *in)
{
    static char o[64];
    char *out = g_strdup(in);
    char *poundloc = NULL;
    poundloc = g_strstr_len(out, strlen(out), "#");
    if (poundloc != NULL) {
        int i = 0, j = 0;
        gboolean is_gateway = FALSE;
        for (; i < strlen(poundloc); ) {
            if (poundloc[i] == '@')
                is_gateway = TRUE;

            // Ribose\02\0
            // Ribose@Azeroth\0h\0

            if (is_gateway) {
                poundloc[j] = poundloc[i];
                j++;
            }

            i++;
        }
        poundloc[j] = poundloc[i];
    }
    g_memmove((char *)o, out, strlen(out) + 1);
    g_free(out);
    return o;
}

// removes the first @ and everything after it from the given account name
// does not remove any @ that begins the username
static const char *
bnet_gateway_normalize(const PurpleAccount *account, const char *in)
{
    static char out[64];

    char *o = g_strdup(in);
    int i;

    for (i = 0; i < 64; i++) {
        if (o[i] == '\0') {
            break;
        }
        if (i > 0 && o[i] == '@') {
            o[i] = '\0';
            break;
        }
    }
    g_memmove((char *)out, o, strlen(o) + 1);
    g_free(o);

    return out;
}

static gboolean
bnet_is_d2(const BnetConnectionData *bnet)
{
    return (bnet->product_id == BNET_PRODUCT_D2DV ||
            bnet->product_id == BNET_PRODUCT_D2XP);
}

static gboolean
bnet_is_w3(const BnetConnectionData *bnet)
{
    return (bnet->product_id == BNET_PRODUCT_WAR3 ||
            bnet->product_id == BNET_PRODUCT_W3XP);
}

static BnetVersioningSystem
bnet_get_versioningsystem(const BnetConnectionData *bnet)
{
    switch (bnet->product_id) {
        case BNET_PRODUCT_SSHR:
        case BNET_PRODUCT_JSTR:
            return BNET_VERSIONING_LEGACY;
        case BNET_PRODUCT_DRTL:
        case BNET_PRODUCT_DSHR:
        case BNET_PRODUCT_W2BN:
            return BNET_VERSIONING_LEGACY2;
        default:
            return BNET_VERSIONING_AUTH;
    }
}

static int
bnet_get_key_count(const BnetConnectionData *bnet)
{
    switch (bnet->game) {
        default:
            return 0;
        case BNET_GAME_TYPE_STAR:
        case BNET_GAME_TYPE_SEXP:
        case BNET_GAME_TYPE_W2BN:
        case BNET_GAME_TYPE_D2DV:
        case BNET_GAME_TYPE_WAR3:
            return 1;
        case BNET_GAME_TYPE_D2XP:
        case BNET_GAME_TYPE_W3XP:
            return 2;
    }
}

static GList *
bnet_actions(PurplePlugin *plugin, gpointer context)
{
    GList *list = NULL;
    PurplePluginAction *action = NULL;
    PurpleConnection *gc = NULL;
    BnetConnectionData *bnet = NULL;
    BnetClanMemberRank my_rank = 0;

    gc = context;
    bnet = gc->proto_data;

    action = purple_plugin_action_new("Set User Info...", bnet_action_set_user_data);
    list = g_list_append(list, action);

    action = purple_plugin_action_new("Show News and MOTD...", bnet_action_show_news);
    list = g_list_append(list, action);

    if (bnet->clan_info != NULL && bnet_clan_info_get_tag(bnet->clan_info) != 0) {
        my_rank = bnet_clan_info_get_my_rank(bnet->clan_info);
        if (my_rank == BNET_CLAN_RANK_SHAMAN ||
                my_rank == BNET_CLAN_RANK_CHIEFTAIN) {
            action = purple_plugin_action_new("Set Clan MOTD...", bnet_action_set_motd);
            list = g_list_append(list, action);
        }
    }

    return list;
}

static void
bnet_rename_group(PurpleConnection *gc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
    // ignore: Battle.net does not support friend list or clan list groups
}

static PurplePluginProtocolInfo prpl_info =
{
    OPT_PROTO_CHAT_TOPIC |
    OPT_PROTO_SLASH_COMMANDS_NATIVE,    /* protocol options */
    NULL,                               /* user_splits */
    NULL,                               /* account options */
    NO_BUDDY_ICONS,                     /* icon_spec */
    bnet_list_icon,                     /* list_icon */
    bnet_list_emblem,                   /* list_emblems */
    bnet_status_text,                   /* status_text */
    bnet_tooltip_text,                  /* tooltip_text */
    bnet_status_types,                  /* away_states */
    NULL,                               /* blist_node_menu */
    bnet_chat_info,                     /* chat_info */
    bnet_chat_info_defaults,            /* chat_info_defaults */
    bnet_login,                         /* login */
    bnet_close,                         /* close */
    bnet_send_whisper,                  /* send_im */
    NULL,                               /* set_info */
    NULL,                               /* send_typing */
    bnet_lookup_info,                   /* get_info */
    bnet_set_status,                    /* set_status */
    NULL,                               /* set_idle */
    bnet_account_chpw,                  /* change_passwd */
    bnet_add_buddy,                     /* add_buddy */
    NULL,                               /* add_buddies */
    bnet_remove_buddy,                  /* remove_buddy */
    NULL,                               /* remove_buddies */
    NULL,                               /* add_permit */
    NULL,                               /* add_deny */
    NULL,                               /* rem_permit */
    NULL,                               /* rem_deny */
    NULL,                               /* set_permit_deny */
    bnet_join_chat,                     /* join_chat */
    NULL,                               /* reject_chat */
    NULL,                               /* get_chat_name */
    NULL,                               /* chat_invite */
    NULL,                               /* chat_leave */
    NULL,                               /* chat_whisper */
    bnet_chat_im,                       /* chat_send */
    NULL,                               /* keepalive */
    bnet_account_register,              /* register_user */
    NULL,                               /* get_cb_info */
    NULL,                               /* get_cb_away */
    NULL,                               /* alias_buddy */
    NULL,                               /* group_buddy */
    bnet_rename_group,                  /* rename_group */
    bnet_buddy_free,                    /* buddy_free */
    NULL,                               /* convo_closed */
    bnet_normalize,                     /* normalize */
    NULL,                               /* set_buddy_icon */
    NULL,                               /* remove_group */
    NULL,                               /* get_cb_real_name */
    NULL,                               /* set_chat_topic */
    NULL,                               /* find_blist_chat */
    bnet_roomlist_get_list,             /* roomlist_get_list */
    bnet_roomlist_cancel,               /* roomlist_cancel */
    NULL,                               /* roomlist_expand_category */
    NULL,                               /* can_receive_file */
    NULL,                               /* send_file */
    NULL,                               /* new_xfer */
    NULL,                               /* offline_message */
    NULL,                               /* whiteboard_prpl_ops */
    bnet_send_raw,                      /* send_raw */
    NULL,                               /* roomlist_room_serialize */
    NULL,                               /* unregister_user */
    NULL,                               /* send_attention */
    NULL,                               /* get_attention_types */
    sizeof(PurplePluginProtocolInfo),   /* struct_size */
    NULL,                               /* get_account_text_table */
    NULL,                               /* initiate_media */
    NULL,                               /* get_media_caps */
    NULL,                               /* get_moods */
    NULL,                               /* set_public_alias */
    NULL,                               /* get_public_alias */
    NULL,                               /* add_buddy_with_invite */
    NULL,                               /* add_buddies_with_invite */
};

static PurplePluginInfo info =
{
    PURPLE_PLUGIN_MAGIC,                /* magic */
    PURPLE_MAJOR_VERSION,               /* major version */
    PURPLE_MINOR_VERSION,               /* minor version */
    PURPLE_PLUGIN_PROTOCOL,             /* type: prpl */
    NULL,                               /* ui_requirement: none */
    0,                                  /* flags: none */
    NULL,                               /* dependencies: none */
    PURPLE_PRIORITY_DEFAULT,            /* priority: normal */

    PLUGIN_ID,                          /* id */
    PLUGIN_NAME,                        /* name */
    PLUGIN_STR_VER,                     /* version */
    PLUGIN_SHORT_DESCR,                 /* summary */
    PLUGIN_DESCR,                       /* description */
    PLUGIN_AUTHOR,                      /* author */
    PLUGIN_WEBSITE,                     /* homepage */

    NULL,                               /* load */
    NULL,                               /* unload */
    NULL,                               /* destroy */

    NULL,                               /* ui_info */
    &prpl_info,                         /* extra_info */
    NULL,                               /* prefs_info */
    bnet_actions,                       /* actions */

    NULL,                               /* _purple_reserved1 */
    NULL,                               /* _purple_reserved2 */
    NULL,                               /* _purple_reserved3 */
    NULL,                               /* _purple_reserved4 */
};

static void                        
init_plugin(PurplePlugin *plugin)
{               
    PurpleAccountUserSplit *split = NULL;
    PurpleAccountOption *option = NULL;
    GList *optlist = NULL;
    PurpleKeyValuePair *kvp = NULL;
    char *prpl_name = PLUGIN_ID;
    PurpleCmdFlag flags = 0;
    struct BnetCommand *c = NULL;
    int i;

    flags |= PURPLE_CMD_FLAG_CHAT;
    flags |= PURPLE_CMD_FLAG_IM;
    flags |= PURPLE_CMD_FLAG_PRPL_ONLY;
    flags |= PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS;

    split = purple_account_user_split_new("Server", BNET_DEFAULT_SERVER, '@');
    prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

    option = purple_account_option_int_new("Port", "port", BNET_DEFAULT_PORT);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("StarCraft");
    kvp->value = g_strdup("RATS");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("StarCraft: Brood War");
    kvp->value = g_strdup("PXES");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("WarCraft II: Battle.net Edition");
    kvp->value = g_strdup("NB2W");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Diablo II");
    kvp->value = g_strdup("VD2D");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Diablo II: Lord of Destruction");
    kvp->value = g_strdup("PX2D");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("WarCraft III");
    kvp->value = g_strdup("3RAW");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("WarCraft III: The Frozen Throne");
    kvp->value = g_strdup("PX3W");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("StarCraft: Shareware");
    kvp->value = g_strdup("RHSS");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("StarCraft: Japanese");
    kvp->value = g_strdup("RTSJ");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Diablo");
    kvp->value = g_strdup("LTRD");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Diablo: Shareware");
    kvp->value = g_strdup("RHSD");
    optlist = g_list_append(optlist, kvp);

    kvp = g_new0(PurpleKeyValuePair, 1);
    kvp->key = g_strdup("Chat Client");
    kvp->value = g_strdup("TAHC");
    optlist = g_list_append(optlist, kvp);

    option = purple_account_option_list_new("Game Client", "product", optlist);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_string_new("CD Key", "key1", "");
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_string_new("Expansion CD Key", "key2", "");
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_string_new("Key Owner", "key_owner", "");
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_string_new("Logon Server", "bnlsserver", BNET_DEFAULT_BNLSSERVER);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_bool_new("Show ban messages", "showbans", TRUE);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_bool_new("Automatic join delay filtering (buggy)", "joindelay", FALSE);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_string_new("Default friends group", "grpfriends", BNET_DEFAULT_GROUP_FRIENDS);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_bool_new("Show mutual friend status-change messages", "showmutual", FALSE);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_bool_new("Show clan members on buddy list (buggy)", "showgrpclan", FALSE);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    option = purple_account_option_string_new("Default clan members group", "grpclan", BNET_DEFAULT_GROUP_CLAN);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    for (c = bnet_cmds; c && c->name; c++) {
        purple_cmd_register(c->name, c->args, PURPLE_CMD_P_PRPL, flags,
                prpl_name, bnet_handle_cmd, c->helptext, c);
    }

    i = 0;
    while (bnet_regex_store[i].regex_str != NULL) {
        GError *err = NULL;
        bnet_regex_store[i].regex = g_regex_new(bnet_regex_store[i].regex_str, G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, &err);
        if (err != NULL) {
            purple_debug_warning("bnet", "Regex creation failed: %s\n", err->message);
            g_error_free(err);
        }
        i++;
    }
}

PURPLE_INIT_PLUGIN(clbnet, init_plugin, info)

#endif

