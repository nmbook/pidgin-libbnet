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

#ifndef _PACKETS_H_
#define _PACKETS_H_

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

// buffer size
#define BNET_INITIAL_BUFSIZE 512

// sizes
#define BNET_SIZE_FILETIME 8
#define BNET_SIZE_DWORD 4
#define BNET_SIZE_WORD 2
#define BNET_SIZE_BYTE 1

// FF byte
#define BNET_IDENT_FLAG 0xFF

// header sizes
#define BNET_PACKET_BNCS 4
#define BNET_PACKET_BNLS 3

// bncs packet ids
typedef enum {
    BNET_SID_NULL                    = 0x00,
    BNET_SID_ENTERCHAT               = 0x0A,
    BNET_SID_GETCHANNELLIST          = 0x0B,
    BNET_SID_JOINCHANNEL             = 0x0C,
    BNET_SID_CHATCOMMAND             = 0x0E,
    BNET_SID_CHATEVENT               = 0x0F,
    BNET_SID_LEAVECHAT               = 0x10,
    BNET_SID_MESSAGEBOX              = 0x19,
    BNET_SID_PING                    = 0x25,
    BNET_SID_READUSERDATA            = 0x26,
    BNET_SID_WRITEUSERDATA           = 0x27,
    BNET_SID_LOGONRESPONSE2          = 0x3A,
    BNET_SID_CREATEACCOUNT2          = 0x3D,
    BNET_SID_AUTH_INFO               = 0x50,
    BNET_SID_AUTH_CHECK              = 0x51,
    BNET_SID_AUTH_ACCOUNTCREATE      = 0x52,
    BNET_SID_AUTH_ACCOUNTLOGON       = 0x53,
    BNET_SID_AUTH_ACCOUNTLOGONPROOF  = 0x54,
    BNET_SID_AUTH_ACCOUNTCHANGE      = 0x55,
    BNET_SID_AUTH_ACCOUNTCHANGEPROOF = 0x56,
    BNET_SID_FRIENDSLIST             = 0x65,
    BNET_SID_FRIENDSUPDATE           = 0x66,
    BNET_SID_FRIENDSADD              = 0x67,
    BNET_SID_FRIENDSREMOVE           = 0x68,
    BNET_SID_FRIENDSPOSITION         = 0x69,
    BNET_SID_CLANCREATIONINVITATION  = 0x72,
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
#define BNET_CREATEACC2_EXISTS           BNET_AUTH_ACCOUNT_EXISTS
#define BNET_CREATEACC2_NOTENOUGHALPHA   0x06

// FILETIMEs
#define FT_SECOND ((guint64) 10000000)
#define FT_MINUTE (60 * FT_SECOND)
#define FT_HOUR   (60 * FT_MINUTE)
#define FT_DAY    (24 * FT_HOUR)
#define MO_JAN 0
#define MO_FEB 1
#define MO_MAR 2
#define MO_APR 3
#define MO_MAY 4
#define MO_JUN 5
#define MO_JUL 6
#define MO_AUG 7
#define MO_SEP 8
#define MO_OCT 9
#define MO_NOV 10
#define MO_DEC 11

typedef struct {
    guint8 *data;
    guint16 len;
    guint16 pos;
    gboolean allocd;
} BnetPacket;

typedef struct {
    guint32 dwLowDateTime;
    guint32 dwHighDateTime;
} WINDOWS_FILETIME;

void bnet_packet_free(BnetPacket *bnet_packet);
gboolean bnet_packet_insert(BnetPacket *bnet_packet, gconstpointer data, const gsize length);
BnetPacket *bnet_packet_refer(const guint8 *start, const gsize length);
BnetPacket *bnet_packet_refer_bnls(const guint8 *start, const gsize length);
void *bnet_packet_read(BnetPacket *bnet_packet, const gsize size);
char *bnet_packet_read_cstring(BnetPacket *bnet_packet);
guint64 bnet_packet_read_qword(BnetPacket *bnet_packet);
guint32 bnet_packet_read_dword(BnetPacket *bnet_packet);
guint16 bnet_packet_read_word(BnetPacket *bnet_packet);
guint8 bnet_packet_read_byte(BnetPacket *bnet_packet);
BnetPacket *bnet_packet_create(const gsize header_length);
int bnet_packet_send(BnetPacket *bnet_packet, const guint8 id, const int fd);
int bnet_packet_send_bnls(BnetPacket *bnet_packet, const guint8 id, const int fd);
char *bnet_packet_debug(BnetPacket *bnet_packet);
void clear_line(char *line, int size);
char * ascii_char(char *position, int c);
char * hex_char(char *position, int c);

#endif
