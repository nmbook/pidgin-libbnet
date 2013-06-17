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
};

struct _BnetClanInfo {
    // clan tag
    BnetClanTag tag;
    
    // clan name
    gchar *name;
    
    // clan MOTD
    gchar *motd;
    
    // my rank
    BnetClanMemberRank my_rank;
    
    // GList<BnetClanMember>
    GList *members;
    
    // pending packets to cookie mapping
    GHashTable *cookie_list;
};

gchar *
bnet_clan_tag_to_string(const BnetClanTag tag)
{
    union {
        gchar as_str[4];
        BnetClanTag as_int;
    } data;
    data.as_int = tag;
    gchar *ret = g_malloc0(5);
    ret[0] = data.as_str[3];
    ret[1] = data.as_str[2];
    ret[2] = data.as_str[1];
    ret[3] = data.as_str[0];
    ret[4] = '\0';
    return ret;
}

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
    static guint32 cookie = 0;
    
    struct BnetClanPacketKey *key = NULL;
    
    cookie++;
    
    // this means we haven't init'd yet
    // we don't init till we log in or receive SID_CLANINFO
    if (info == NULL) {
        return 0;
    }
    
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
    
    if (info == NULL) {
        return 0;
    }
    
    key = g_new(struct BnetClanPacketKey, 1);
    key->packet_id = packet_id;
    key->cookie = cookie;
    
    ret = g_hash_table_lookup(((struct _BnetClanInfo *)info)->cookie_list, key);
    if (ret != NULL) {
        g_hash_table_remove(((struct _BnetClanInfo *)info)->cookie_list, key);
    }
    return ret;
}

BnetClanInfo *
bnet_clan_info_new(BnetClanTag tag, BnetClanMemberRank rank)
{
    struct _BnetClanInfo *bcli = g_new0(struct _BnetClanInfo, 1);
    bcli->cookie_list = g_hash_table_new_full(
                        (GHashFunc)bnet_clan_packet_keyhash,
                        (GEqualFunc)bnet_clan_packet_keyequal,
                        (GDestroyNotify)bnet_clan_packet_keyfree,
                        NULL);
    bcli->tag = tag;
    bcli->my_rank = rank;
    return (BnetClanInfo *) bcli;
}
    
void
bnet_clan_info_free(BnetClanInfo *info)
{
    if (info != NULL) {
        g_hash_table_destroy(((struct _BnetClanInfo *)info)->cookie_list);
        if (((struct _BnetClanInfo *)info)->motd != NULL) {
            g_free(((struct _BnetClanInfo *)info)->motd);
        }
        g_free(info);
    }
}

BnetClanTag
bnet_clan_info_get_tag(BnetClanInfo *info)
{
    return ((struct _BnetClanInfo *)info)->tag;
}

BnetClanMemberRank
bnet_clan_info_get_my_rank(BnetClanInfo *info)
{
    return ((struct _BnetClanInfo *)info)->my_rank;
}

gchar *
bnet_clan_info_get_motd(BnetClanInfo *info)
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
bnet_clan_member_get_name(BnetClanMember *member)
{
    return member->name;
}

gchar *
bnet_clan_member_get_location(BnetClanMember *member)
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
bnet_clan_member_get_rank(BnetClanMember *member)
{
    return member->rank;
}

void
bnet_clan_member_set_rank(BnetClanMember *member, BnetClanMemberRank rank)
{
    member->rank = rank;
}

BnetClanMemberStatus
bnet_clan_member_get_status(BnetClanMember *member)
{
    return member->status;
}

void
bnet_clan_member_set_status(BnetClanMember *member, BnetClanMemberStatus status)
{
    member->status = status;
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
