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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 *
 * Converted from C++ to C for use with this plugin.
 *
 * BNCSutil
 * Battle.Net Utility Library
 *
 * Copyright (C) 2004-2006 Eric Naeseth
 *
 * CD-Key Decoder Implementation
 * September 29, 2004
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * A copy of the GNU Lesser General Public License is included in the BNCSutil
 * distribution in the file COPYING.  If you did not receive this copy,
 * write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA  02111-1307  USA
 */

//#include <bncsutil/mutil.h>
//#include <bncsutil/cdkeydecoder.h>
//#include <bncsutil/keytables.h> // w2/d2 and w3 tables
//#include <bncsutil/bsha1.h> // Broken SHA-1
//#include <bncsutil/sha1.h> // US Secure Hash Algorithm (for W3)

#ifndef _KEY_DECODE_H_
#define _KEY_DECODE_H_

// libraries
#include <glib.h>

#include <ctype.h> // for isdigit(), isalnum(), and toupper()
#include <string.h> // for memcpy()
#include <stdio.h> // for sscanf()
#ifdef _WIN32
#include "internal.h"
#endif

#include "bufferer.h"
#include "sha1.h"

#define SWAP2(num) ((((num) >> 8) & 0x00FF) | (((num) << 8) & 0xFF00))
#define SWAP4(num) ((((num) >> 24) & 0x000000FF) | (((num) >> 8) & 0x0000FF00) | (((num) << 8) & 0x00FF0000) | (((num) << 24) & 0xFF000000))
#define SWAP8(x)                                                                                                           \
        (uint64_t)((((uint64_t)(x) & 0xff) << 56) |                                                \
            ((uint64_t)(x) & 0xff00ULL) << 40 |                        \
            ((uint64_t)(x) & 0xff0000ULL) << 24 |                      \
            ((uint64_t)(x) & 0xff000000ULL) << 8 |                     \
            ((uint64_t)(x) & 0xff00000000ULL) >> 8 |                   \
            ((uint64_t)(x) & 0xff0000000000ULL) >> 24 |                \
            ((uint64_t)(x) & 0xff000000000000ULL) >> 40 |              \
            ((uint64_t)(x) & 0xff00000000000000ULL) >> 56)

#if BIGENDIAN
#define LSB2(num) SWAP2(num)
#define LSB4(num) SWAP4(num)
#define MSB2(num) (num)
#define MSB4(num) (num)
#else /* (little endian) */
#define LSB2(num) (num)
#define LSB4(num) (num)
#define MSB2(num) SWAP2(num)
#define MSB4(num) SWAP4(num)
#endif /* (endianness) */

#define DEBUG 0

typedef struct {
    guint32 length;
    guint32 product_value;
    guint32 public_value;
    guint32 private_value;
    guint8 key_hash[SHA1_HASH_SIZE];
} BnetKey;

typedef enum {
    CDKEY_TYPE_SC = 13,
    CDKEY_TYPE_W2D2 = 16,
    CDKEY_TYPE_W3 = 26,
    CDKEY_TYPE_UNKNOWN = 0
} CDKeyType;

/**
 * Decoder "context"
 */
typedef struct {
    char* cdkey;
    gboolean initialized;
    gboolean keyOK;
    gsize keyLen;
    guint8 *keyHash;
    gsize hashLen;
    CDKeyType keyType;
    guint64 value1;
    guint64 value2;
    guint64 product;
    char* w3value2;
} CDKeyDecoder;

gboolean bnet_key_decode(BnetKey keys[2], int key_count,
         guint32 client_cookie, guint32 server_cookie,
         const char *key1_string, const char *key2_string);
gboolean bnet_key_decode_legacy_verify_only(char *key,
         guint32 client_cookie, guint32 server_cookie,
         const char *key1_string);
gboolean bnet_key_decode_legacy(BnetKey *key,
         guint32 client_cookie, guint32 server_cookie,
         const char *key1_string);
void bnet_key_free(CDKeyDecoder *ctx);
CDKeyDecoder *bnet_key_create_context(const char *cdkey);
gboolean bnet_is_key_valid(CDKeyDecoder *ctx);
int bnet_key_get_val2_length(CDKeyDecoder *ctx);
guint32 bnet_key_get_product(CDKeyDecoder *ctx);
guint32 bnet_key_get_val1(CDKeyDecoder *ctx);
guint32 bnet_key_get_val2(CDKeyDecoder *ctx);
guint32 bnet_key_get_long_val2(CDKeyDecoder *ctx, char* out);
gsize bnet_key_calculate_hash_legacy(CDKeyDecoder *ctx, const guint32 clientToken,
      const guint32 serverToken);
gsize bnet_key_calculate_hash(CDKeyDecoder *ctx, guint32 clientToken,
      guint32 serverToken);
gsize bnet_key_get_hash(CDKeyDecoder *ctx, guint8* outputBuffer);
gboolean process_sc(CDKeyDecoder *ctx);
gboolean process_w2d2(CDKeyDecoder *ctx);
gboolean process_w3(CDKeyDecoder *ctx);
void mult(int r, const int x, int* a, int dcByte);
void decodeKeyTable(int* keyTable);
char getHexValue(int v);
int getNumValue(char c);

#define W3_KEYLEN 26
#define W3_BUFLEN (W3_KEYLEN << 1)

#endif
