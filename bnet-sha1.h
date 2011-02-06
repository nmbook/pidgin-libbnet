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

#include <ctype.h>
#include "stdint.h"

#ifndef _SHA_enum_
#define _SHA_enum_
enum{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};
#endif

#define SHA1_HASH_SIZE 20

typedef enum{
  SHA1,
  xSHA1,
  lSHA1,
  wSHA1,
  MAX = 0xffffffff
}SHA1_t;
/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */

typedef struct sha1_context{
  uint32_t      intermediate_hash[SHA1_HASH_SIZE / 4]; /* Message Digest                   */
  uint32_t      length_low;                            /* Message length in bits           */
  uint32_t      length_high;                           /* Message length in bits           */
  int_least16_t message_block_index;                   /* Index into message block array   */
  uint8_t       message_block[64];                     /* 512-bit message blocks           */
  uint8_t       computed;                              /* Is the digest computed?          */
  uint8_t       corrupted;                             /* Is the message digest corrupted? */
  SHA1_t        version;                               /* What version of SHA1 is this?    */
} sha1_context;

/* Function Prototypes */

int sha1_reset(sha1_context *);
int sha1_input(sha1_context *, const uint8_t *, uint32_t);
int sha1_digest(sha1_context *, uint8_t *);
uint32_t sha1_checksum(uint8_t *data, uint32_t length, uint32_t version);

#endif
