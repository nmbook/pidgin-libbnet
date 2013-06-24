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

#ifndef _BUFFERER_H_
#define _BUFFERER_H_

// libraries
#include <glib.h>

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include "internal.h"
#endif
#include "debug.h"

// sizes
#define BNET_SIZE_FILETIME 8
#define BNET_SIZE_DWORD 4
#define BNET_SIZE_WORD 2
#define BNET_SIZE_BYTE 1
#define BNET_SIZE_CSTRING -1

// packet buffer grow size
#define BNET_BUFFER_GROW_SIZE 256

// FF byte
#define BNET_IDENT_FLAG 0xFF

// header sizes
#define BNET_PACKET_BNCS  4
#define BNET_PACKET_BNLS  3
#define BNET_PACKET_D2MCP 3
#define BNET_PACKET_RAW   2

typedef struct {
    gchar *data;
    guint16 len;
    guint16 pos;
    gboolean allocd;
} BnetPacket;

void bnet_packet_free(BnetPacket *bnet_packet);

gboolean bnet_packet_insert(BnetPacket *bnet_packet, gconstpointer data, const gsize length);

BnetPacket *bnet_packet_refer(const gchar *start, const gsize length);
BnetPacket *bnet_packet_refer_bnls(const gchar *start, const gsize length);
#define bnet_packet_refer_d2mcp bnet_packet_refer_bnls
BnetPacket *bnet_packet_deserialize(const gchar *start);

gboolean bnet_packet_can_read(BnetPacket *bnet_packet, const gsize size);
void *bnet_packet_read(BnetPacket *bnet_packet, const gsize size);
char *bnet_packet_read_cstring(BnetPacket *bnet_packet);
guint64 bnet_packet_read_qword(BnetPacket *bnet_packet);
guint32 bnet_packet_read_dword(BnetPacket *bnet_packet);
guint16 bnet_packet_read_word(BnetPacket *bnet_packet);
guint8 bnet_packet_read_byte(BnetPacket *bnet_packet);

BnetPacket *bnet_packet_create(const gsize header_length);

int bnet_packet_send(BnetPacket *bnet_packet, const guint8 id, const int fd);
int bnet_packet_send_bnls(BnetPacket *bnet_packet, const guint8 id, const int fd);
#define bnet_packet_send_d2mcp bnet_packet_send_bnls
gchar *bnet_packet_serialize(BnetPacket *bnet_packet);

char *bnet_packet_debug(const BnetPacket *bnet_packet);
void clear_line(char *line, int size);
char * ascii_char(char *position, int c);
char * hex_char(char *position, int c);

#endif
