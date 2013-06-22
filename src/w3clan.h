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

#ifndef _W3CLAN_H_
#define _W3CLAN_H_

#include <string.h>

#include "glib.h"

#define BNET_USER_TYPE_CLANMEMBER   0x04

typedef guint32 BnetClanTag;

typedef enum {
    BNET_CLAN_RANK_INITIATE  = 0,
    BNET_CLAN_RANK_PEON      = 1,
    BNET_CLAN_RANK_GRUNT     = 2,
    BNET_CLAN_RANK_SHAMAN    = 3,
    BNET_CLAN_RANK_CHIEFTAIN = 4,
} BnetClanMemberRank;

typedef guint8 BnetClanResponseCode;
#define BNET_CLAN_RESPONSE_SUCCESS          0x00
#define BNET_CLAN_RESPONSE_NAMEINUSE        0x01
#define BNET_CLAN_RESPONSE_TOOSOON          0x02
#define BNET_CLAN_RESPONSE_NOTENOUGHMEMBERS 0x03
#define BNET_CLAN_RESPONSE_DECLINE          0x04
#define BNET_CLAN_RESPONSE_UNAVAILABLE      0x05
#define BNET_CLAN_RESPONSE_ACCEPT           0x06
#define BNET_CLAN_RESPONSE_NOTAUTHORIZED    0x07
#define BNET_CLAN_RESPONSE_NOTALLOWED       0x08
#define BNET_CLAN_RESPONSE_FULL             0x09
#define BNET_CLAN_RESPONSE_BADTAG           0x0a
#define BNET_CLAN_RESPONSE_BADNAME          0x0b
#define BNET_CLAN_RESPONSE_USERNOTFOUND     0x0c

typedef enum {
    BNET_CLAN_STATUS_OFFLINE = 0,
    BNET_CLAN_STATUS_ONLINE  = 1,
} BnetClanMemberStatus;

typedef struct _BnetClanInfo BnetClanInfo;
typedef struct _BnetClanMember BnetClanMember;

gchar *bnet_clan_tag_to_string(const BnetClanTag tag);
gboolean bnet_clan_is_clan_channel(const BnetClanInfo *info, const char *channel_name);
BnetClanTag bnet_clan_string_to_tag(const gchar *tag_string);

guint32 bnet_clan_packet_register(BnetClanInfo *info, const guint8 packet_id, gpointer data);
gpointer bnet_clan_packet_unregister(BnetClanInfo *info, const guint8 packet_id, const guint32 cookie);

BnetClanInfo *bnet_clan_info_new(void);
void bnet_clan_info_join_clan(BnetClanInfo *info, BnetClanTag tag, BnetClanMemberRank rank);
void bnet_clan_info_leave_clan(BnetClanInfo *info);
void bnet_clan_info_free(BnetClanInfo *info);
BnetClanTag bnet_clan_info_get_tag(const BnetClanInfo *info);
BnetClanMemberRank bnet_clan_info_get_my_rank(const BnetClanInfo *info);
gchar *bnet_clan_info_get_motd(const BnetClanInfo *info);
void bnet_clan_info_set_motd(BnetClanInfo *info, gchar *motd);
void bnet_clan_info_set_members(BnetClanInfo *info, GList *members);
const BnetClanMember *bnet_clan_info_get_member(const BnetClanInfo *info, gchar *name);

BnetClanMember *bnet_clan_member_new(gchar *name, BnetClanMemberRank rank, BnetClanMemberStatus status, gchar *location);
gchar *bnet_clan_member_get_name(const BnetClanMember *member);
gchar *bnet_clan_member_get_location(const BnetClanMember *member);
void bnet_clan_member_set_location(BnetClanMember *member, gchar *location);
BnetClanMemberRank bnet_clan_member_get_rank(const BnetClanMember *member);
void bnet_clan_member_set_rank(BnetClanMember *member, BnetClanMemberRank rank);
BnetClanMemberStatus bnet_clan_member_get_status(const BnetClanMember *member);
void bnet_clan_member_set_status(BnetClanMember *member, BnetClanMemberStatus status);
void bnet_clan_member_free(BnetClanMember *member);

#endif
