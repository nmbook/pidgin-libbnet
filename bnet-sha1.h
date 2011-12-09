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
 *
 *
 *
 *  Author: Hdx
 *
 *  sha1.h
 *
 *  Description:
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 *  Notes:
 *    I took this file from BNCSUtil's source, Why? Lazyness. I have 
 *    modified it a bit to support the 3 versions but most of its 
 *    from him. <3
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#include <glib.h>
//#include Mstdint.h"

#ifndef _SHA_enum_
#define _SHA_enum_
typedef enum {
    SHA1_RESULT_SUCCESS = 0,
    SHA1_RESULT_NULL,            /* Null pointer parameter */
    SHA1_RESULT_INPUT_TOO_LONG,    /* input data too long */
    SHA1_RESULT_STATE_ERROR       /* called Input after Result */
} sha1_result;
#endif

#define SHA1_HASH_SIZE 20

typedef enum {
    SHA1_TYPE_NORMAL, /* used in most b.net things */
    SHA1_TYPE_BROKEN, /* used by the Old Logon System */
    SHA1_TYPE_LOCKDOWN /* used in the lockdown version check */
} sha1_type;

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct {
    guint32 intermediate_hash[SHA1_HASH_SIZE / 4]; /* Message Digest                   */
    guint32 length_low;                            /* Message length in bits           */
    guint32 length_high;                           /* Message length in bits           */
    gint16 message_block_index;                   /* Index into message block array   */
    guint8 message_block[64];                     /* 512-bit message blocks           */
    guint8 computed;                              /* Is the digest computed?          */
    guint8 corrupted;                             /* Is the message digest corrupted? */
    sha1_type version;                               /* What version of SHA1 is this?    */
} sha1_context;

/* Function Prototypes */

sha1_result sha1_reset(sha1_context *);
sha1_result sha1_input(sha1_context *, const guint8 *, guint32);
sha1_result sha1_digest(sha1_context *, guint8 *);
guint32 sha1_checksum(guint8 *data, guint32 length, guint32 version);

#endif
