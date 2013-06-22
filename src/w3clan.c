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

#ifndef _W3CLAN_C_
#define _W3CLAN_C_

#include "w3clan.h"

static gboolean bnet_clan_packet_keyequal(gconstpointer a, gconstpointer b);
static guint32 bnet_clan_packet_keyhash(gconstpointer data);
static void bnet_clan_packet_keyfree(gpointer data);

struct BnetClanPacketKey {
    guint8 packet_id;
    guint32 cookie;
};

struct _BnetClanMember {
    // type = 
    guint32 type;
    gchar *name;
    BnetClanMemberRank rank;
    BnetClanMemberStatus status;
    gchar *location;

    guint64 join_date;
};

struct _BnetClanInfo {
    // we can now init without being in a clan, for the cookie list (SID_W3PROFILE, SID_W3GENERAL, SID_CLANMEMBERINFO)
    gboolean in_clan;
    // clan tag -- 0 if in_clan = FALSE
    BnetClanTag tag;
    // clan name -- NULL if in_clan = FALSE
    gchar *name;
    // clan MOTD -- NULL if in_clan = FALSE
    gchar *motd;
    // my rank -- -1 if in_clan = FALSE
    BnetClanMemberRank my_rank;
    // GList<BnetClanMember> -- NULL if not received
    GList *members;
    // pending packets to cookie mapping -- not NULL
    GHashTable *cookie_list;
};

/*
 * Converts DWORD to tag-string
 * '\0ToB' -> "BoT\0"
 * 'RATS' -> "STAR'
 */
gchar *
bnet_clan_tag_to_string(const BnetClanTag tag)
{
    gchar *ret;
    union {
        gchar as_str[4];
        BnetClanTag as_int;
    } data;
    int offset = 0;

    if (tag == 0) {
        return g_strdup("");
    } else {
        while (!((tag >> (offset << 3)) & 0xff)) {
            offset++;
        }
    }

    data.as_int = tag;
    ret = g_malloc0(5);
    g_memmove(ret, data.as_str + offset, 4 - offset);
    g_strreverse(ret);
    return ret;
}

/*
 * Converts tag-like string to DWORD
 * "STAR\0" -> 'RATS'
 * "BoT\0" -> '\0ToB'
 */
BnetClanTag
bnet_clan_string_to_tag(const gchar *tag_string)
{
    union {
        gchar as_str[5];
        BnetClanTag as_int;
    } data;
    data.as_int = (BnetClanTag)0;
    g_memmove(data.as_str, tag_string, MIN(strlen(tag_string), 4));
    return data.as_int;
}

const gchar *
bnet_clan_rank_to_string(const BnetClanMemberRank rank)
{
    switch (rank) {
        case BNET_CLAN_RANK_CHIEFTAIN:
            return "Chieftain";
        case BNET_CLAN_RANK_SHAMAN:
            return "Shaman";
        case BNET_CLAN_RANK_GRUNT:
            return "Grunt";
        case BNET_CLAN_RANK_PEON:
            return "Peon";
        case BNET_CLAN_RANK_INITIATE:
            return "Peon (7-day probation)";
        default:
            return "Unknown";
    }
}

gboolean
bnet_clan_is_clan_channel(const BnetClanInfo *info, const char *channel_name_a)
{
    gchar *tag_string = bnet_clan_tag_to_string(((struct _BnetClanInfo *)info)->tag);
    gchar *channel_name_b = g_strdup_printf("clan %s", tag_string);
    gchar *channel_name_lower_a = g_ascii_strdown(channel_name_a, -1);
    gchar *channel_name_lower_b = g_ascii_strdown(channel_name_b, -1);
    
    gboolean is_equal = g_strcmp0(channel_name_lower_a, channel_name_lower_b) == 0;
    
    g_free(tag_string);
    g_free(channel_name_b);
    g_free(channel_name_lower_a);
    g_free(channel_name_lower_b);
    
    return is_equal;
}

guint32
bnet_clan_packet_register(BnetClanInfo *info, const guint8 packet_id, gpointer data)
{
    static guint32 cookie = 1;
    
    struct BnetClanPacketKey *key = NULL;
    
    cookie++;
    
    key = g_new(struct BnetClanPacketKey, 1);
    key->packet_id = packet_id;
    key->cookie = cookie;
    
    g_hash_table_insert(((struct _BnetClanInfo *)info)->cookie_list, key, data);
    return cookie;
}

gpointer
bnet_clan_packet_unregister(BnetClanInfo *info, const guint8 packet_id, const guint32 cookie)
{
    gpointer ret;
    struct BnetClanPacketKey *key = NULL;
    
    key = g_new(struct BnetClanPacketKey, 1);
    key->packet_id = packet_id;
    key->cookie = cookie;
    
    ret = g_hash_table_lookup(((struct _BnetClanInfo *)info)->cookie_list, key);
    if (ret != NULL) {
        g_hash_table_remove(((struct _BnetClanInfo *)info)->cookie_list, key);
    }
    g_free(key);
    return ret;
}

BnetClanInfo *
bnet_clan_info_new(void)
{
    struct _BnetClanInfo *bcli = g_new0(struct _BnetClanInfo, 1);
    bcli->cookie_list = g_hash_table_new_full(
                        (GHashFunc)bnet_clan_packet_keyhash,
                        (GEqualFunc)bnet_clan_packet_keyequal,
                        (GDestroyNotify)bnet_clan_packet_keyfree,
                        NULL);
    bcli->in_clan = FALSE;
    return (BnetClanInfo *) bcli;
}

void
bnet_clan_info_join_clan(BnetClanInfo *info, BnetClanTag tag, BnetClanMemberRank rank)
{
    if (info != NULL) {
        struct _BnetClanInfo *bcli = (struct _BnetClanInfo *)info;
        bcli->in_clan = TRUE;
        bcli->tag = tag;
        bcli->my_rank = rank;
    }
}

void
bnet_clan_info_leave_clan(BnetClanInfo *info)
{
    if (info != NULL) {
        struct _BnetClanInfo *bcli = (struct _BnetClanInfo *)info;
        bcli->in_clan = FALSE;
        if (bcli->motd != NULL) {
            g_free(bcli->motd);
        }
        bcli->motd = NULL;
        if (bcli->members != NULL) {
            g_list_free_full(bcli->members, (GDestroyNotify)bnet_clan_member_free);
        }
        bcli->members = NULL;
    }
}
    
void
bnet_clan_info_free(BnetClanInfo *info, gboolean free_members)
{
    if (info != NULL) {
        struct _BnetClanInfo *bcli = (struct _BnetClanInfo *)info;
        g_hash_table_destroy(bcli->cookie_list);
        if (bcli->motd != NULL) {
            g_free(bcli->motd);
        }
        if (free_members && bcli->members != NULL) {
            g_list_free_full(bcli->members, (GDestroyNotify)bnet_clan_member_free);
        }
        g_free(info);
    }
}

BnetClanTag
bnet_clan_info_get_tag(const BnetClanInfo *info)
{
    return ((struct _BnetClanInfo *)info)->tag;
}

BnetClanMemberRank
bnet_clan_info_get_my_rank(const BnetClanInfo *info)
{
    return ((struct _BnetClanInfo *)info)->my_rank;
}

gchar *
bnet_clan_info_get_motd(const BnetClanInfo *info)
{
    return ((struct _BnetClanInfo *)info)->motd;
}

void
bnet_clan_info_set_motd(BnetClanInfo *info, gchar *motd)
{
    if (((struct _BnetClanInfo *)info)->motd != NULL) {
        g_free(((struct _BnetClanInfo *)info)->motd);
    }
    ((struct _BnetClanInfo *)info)->motd = motd;
}

gchar *
bnet_clan_info_get_name(const BnetClanInfo *info)
{
    return ((struct _BnetClanInfo *)info)->name;
}

void
bnet_clan_info_set_name(BnetClanInfo *info, gchar *name)
{
    if (((struct _BnetClanInfo *)info)->name != NULL) {
        g_free(((struct _BnetClanInfo *)info)->name);
    }
    ((struct _BnetClanInfo *)info)->name = name;
}

void
bnet_clan_info_set_members(BnetClanInfo *info, GList *members, gboolean free_old_list)
{
    struct _BnetClanInfo *bcli = (struct _BnetClanInfo *)info;
    if (free_old_list) {
        g_list_free_full(bcli->members, (GDestroyNotify)bnet_clan_member_free);
    }
    bcli->members = members;
}

BnetClanMember *
bnet_clan_info_get_member(const BnetClanInfo *info, gchar *name)
{
    struct _BnetClanInfo *bcli = (struct _BnetClanInfo *)info;
    GList *el = NULL;
    el = g_list_first(bcli->members);
    while (el != NULL) {
        struct _BnetClanMember *member = el->data;
        if (g_ascii_strcasecmp(name, member->name) == 0) {
            return (BnetClanMember *)member;
        }
        el = g_list_next(el);
    }
    return NULL;
}

BnetClanMember *
bnet_clan_member_new(gchar *name, BnetClanMemberRank rank, BnetClanMemberStatus status, gchar *location)
{
    struct _BnetClanMember *ret = g_new0(struct _BnetClanMember, 1);
    ret->type = BNET_USER_TYPE_CLANMEMBER;
    ret->name = name;
    ret->rank = rank;
    ret->status = status;
    ret->location = location;
    return (BnetClanMember *)ret;
}

gchar *
bnet_clan_member_get_name(const BnetClanMember *member)
{
    return member->name;
}

gchar *
bnet_clan_member_get_location(const BnetClanMember *member)
{
    return member->location;
}

void
bnet_clan_member_set_location(BnetClanMember *member, gchar *location)
{
    if (member->location != NULL) {
        g_free(member->location);
    }
    member->location = location;
}

BnetClanMemberRank
bnet_clan_member_get_rank(const BnetClanMember *member)
{
    return member->rank;
}

void
bnet_clan_member_set_rank(BnetClanMember *member, BnetClanMemberRank rank)
{
    member->rank = rank;
}

BnetClanMemberStatus
bnet_clan_member_get_status(const BnetClanMember *member)
{
    return member->status;
}

void
bnet_clan_member_set_status(BnetClanMember *member, BnetClanMemberStatus status)
{
    member->status = status;
}

guint64
bnet_clan_member_get_joindate(const BnetClanMember *member)
{
    return member->join_date;
}

void
bnet_clan_member_set_joindate(BnetClanMember *member, guint64 joindate)
{
    member->join_date = joindate;
}

void
bnet_clan_member_free(BnetClanMember *member)
{
    if (member->name != NULL) {
        g_free(member->name);
    }
    if (member->location != NULL) {
        g_free(member->location);
    }
    g_free(member);
}

static gboolean
bnet_clan_packet_keyequal(gconstpointer a, gconstpointer b)
{
    const struct BnetClanPacketKey *key_a = a;
    const struct BnetClanPacketKey *key_b = b;
    return key_a->packet_id == key_b->packet_id &&
           key_a->cookie    == key_b->cookie;
}

static guint32
bnet_clan_packet_keyhash(gconstpointer data)
{
    const struct BnetClanPacketKey *key = data;
    gint32 i32 = key->cookie ^ key->packet_id;
    return g_int_hash(&i32);
}

static void
bnet_clan_packet_keyfree(gpointer data)
{
    g_free(data);
}

#endif
