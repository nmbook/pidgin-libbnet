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
 * Converted from C++ to C for use in Pidgin
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

#ifndef _KEY_DECODE_C_
#define _KEY_DECODE_C_

#include "keydecode.h"

// key tables
static const unsigned char w2Map[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0xFF, 0x01, 0xFF, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0xFF, 0x0D, 0x0E, 0xFF, 0x0F, 0x10, 0xFF, 0x11, 0xFF, 0x12, 0xFF,
    0x13, 0xFF, 0x14, 0x15, 0x16, 0xFF, 0x17, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0xFF, 0x0D, 0x0E,
    0xFF, 0x0F, 0x10, 0xFF, 0x11, 0xFF, 0x12, 0xFF, 0x13, 0xFF, 0x14, 0x15,
    0x16, 0xFF, 0x17, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char w3KeyMap[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0xFF, 0x01, 0xFF, 0x02, 0x03, 0x04, 0x05, 0xFF,      
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0xFF, 0x0D, 0x0E, 0xFF, 0x0F, 0x10, 0xFF, 0x11, 0xFF, 0x12,
    0xFF, 0x13, 0xFF, 0x14, 0x15, 0x16, 0x17, 0x18, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0xFF, 0x0D,
    0x0E, 0xFF, 0x0F, 0x10, 0xFF, 0x11, 0xFF, 0x12, 0xFF, 0x13, 0xFF, 0x14,
    0x15, 0x16, 0x17, 0x18, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char w3TranslateMap[] = {
    0x09, 0x04, 0x07, 0x0F, 0x0D, 0x0A, 0x03, 0x0B, 0x01, 0x02, 0x0C, 0x08,
    0x06, 0x0E, 0x05, 0x00, 0x09, 0x0B, 0x05, 0x04, 0x08, 0x0F, 0x01, 0x0E,
    0x07, 0x00, 0x03, 0x02, 0x0A, 0x06, 0x0D, 0x0C, 0x0C, 0x0E, 0x01, 0x04,
    0x09, 0x0F, 0x0A, 0x0B, 0x0D, 0x06, 0x00, 0x08, 0x07, 0x02, 0x05, 0x03,
    0x0B, 0x02, 0x05, 0x0E, 0x0D, 0x03, 0x09, 0x00, 0x01, 0x0F, 0x07, 0x0C,
    0x0A, 0x06, 0x04, 0x08, 0x06, 0x02, 0x04, 0x05, 0x0B, 0x08, 0x0C, 0x0E,
    0x0D, 0x0F, 0x07, 0x01, 0x0A, 0x00, 0x03, 0x09, 0x05, 0x04, 0x0E, 0x0C,
    0x07, 0x06, 0x0D, 0x0A, 0x0F, 0x02, 0x09, 0x01, 0x00, 0x0B, 0x08, 0x03,
    0x0C, 0x07, 0x08, 0x0F, 0x0B, 0x00, 0x05, 0x09, 0x0D, 0x0A, 0x06, 0x0E,
    0x02, 0x04, 0x03, 0x01, 0x03, 0x0A, 0x0E, 0x08, 0x01, 0x0B, 0x05, 0x04,
    0x02, 0x0F, 0x0D, 0x0C, 0x06, 0x07, 0x09, 0x00, 0x0C, 0x0D, 0x01, 0x0F,
    0x08, 0x0E, 0x05, 0x0B, 0x03, 0x0A, 0x09, 0x00, 0x07, 0x02, 0x04, 0x06,
    0x0D, 0x0A, 0x07, 0x0E, 0x01, 0x06, 0x0B, 0x08, 0x0F, 0x0C, 0x05, 0x02,
    0x03, 0x00, 0x04, 0x09, 0x03, 0x0E, 0x07, 0x05, 0x0B, 0x0F, 0x08, 0x0C,
    0x01, 0x0A, 0x04, 0x0D, 0x00, 0x06, 0x09, 0x02, 0x0B, 0x06, 0x09, 0x04,
    0x01, 0x08, 0x0A, 0x0D, 0x07, 0x0E, 0x00, 0x0C, 0x0F, 0x02, 0x03, 0x05,
    0x0C, 0x07, 0x08, 0x0D, 0x03, 0x0B, 0x00, 0x0E, 0x06, 0x0F, 0x09, 0x04,
    0x0A, 0x01, 0x05, 0x02, 0x0C, 0x06, 0x0D, 0x09, 0x0B, 0x00, 0x01, 0x02,
    0x0F, 0x07, 0x03, 0x04, 0x0A, 0x0E, 0x08, 0x05, 0x03, 0x06, 0x01, 0x05,
    0x0B, 0x0C, 0x08, 0x00, 0x0F, 0x0E, 0x09, 0x04, 0x07, 0x0A, 0x0D, 0x02,
    0x0A, 0x07, 0x0B, 0x0F, 0x02, 0x08, 0x00, 0x0D, 0x0E, 0x0C, 0x01, 0x06,
    0x09, 0x03, 0x05, 0x04, 0x0A, 0x0B, 0x0D, 0x04, 0x03, 0x08, 0x05, 0x09,
    0x01, 0x00, 0x0F, 0x0C, 0x07, 0x0E, 0x02, 0x06, 0x0B, 0x04, 0x0D, 0x0F,
    0x01, 0x06, 0x03, 0x0E, 0x07, 0x0A, 0x0C, 0x08, 0x09, 0x02, 0x05, 0x00,
    0x09, 0x06, 0x07, 0x00, 0x01, 0x0A, 0x0D, 0x02, 0x03, 0x0E, 0x0F, 0x0C,
    0x05, 0x0B, 0x04, 0x08, 0x0D, 0x0E, 0x05, 0x06, 0x01, 0x09, 0x08, 0x0C,
    0x02, 0x0F, 0x03, 0x07, 0x0B, 0x04, 0x00, 0x0A, 0x09, 0x0F, 0x04, 0x00,
    0x01, 0x06, 0x0A, 0x0E, 0x02, 0x03, 0x07, 0x0D, 0x05, 0x0B, 0x08, 0x0C,
    0x03, 0x0E, 0x01, 0x0A, 0x02, 0x0C, 0x08, 0x04, 0x0B, 0x07, 0x0D, 0x00,
    0x0F, 0x06, 0x09, 0x05, 0x07, 0x02, 0x0C, 0x06, 0x0A, 0x08, 0x0B, 0x00,
    0x0F, 0x04, 0x03, 0x0E, 0x09, 0x01, 0x0D, 0x05, 0x0C, 0x04, 0x05, 0x09,
    0x0A, 0x02, 0x08, 0x0D, 0x03, 0x0F, 0x01, 0x0E, 0x06, 0x07, 0x0B, 0x00,
    0x0A, 0x08, 0x0E, 0x0D, 0x09, 0x0F, 0x03, 0x00, 0x04, 0x06, 0x01, 0x0C,
    0x07, 0x0B, 0x02, 0x05, 0x03, 0x0C, 0x04, 0x0A, 0x02, 0x0F, 0x0D, 0x0E,
    0x07, 0x00, 0x05, 0x08, 0x01, 0x06, 0x0B, 0x09, 0x0A, 0x0C, 0x01, 0x00,
    0x09, 0x0E, 0x0D, 0x0B, 0x03, 0x07, 0x0F, 0x08, 0x05, 0x02, 0x04, 0x06,
    0x0E, 0x0A, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0C, 0x02, 0x0F, 0x00, 0x0D,
    0x03, 0x0B, 0x04, 0x09, 0x03, 0x08, 0x0E, 0x00, 0x07, 0x09, 0x0F, 0x0C,
    0x01, 0x06, 0x0D, 0x02, 0x05, 0x0A, 0x0B, 0x04, 0x03, 0x0A, 0x0C, 0x04,
    0x0D, 0x0B, 0x09, 0x0E, 0x0F, 0x06, 0x01, 0x07, 0x02, 0x00, 0x05, 0x08
};
 
gboolean bnet_key_decode(BnetKey *keys, int key_count,
     guint32 client_cookie, guint32 server_cookie,
     const char *key1_string, const char *key2_string)
{
    char key1[27];
    char key2[27];
    
    int i, j;
    for (i = 0, j = 0; i < strlen(key1_string) && j < 26; i++) {
        if (isalnum(key1_string[i])) {
            key1[j] = toupper(key1_string[i]);
            j++;
        }
    }
    key1[j] = '\0';
    for (i = 0, j = 0; i < strlen(key2_string) && j < 26; i++) {
        if (isalnum(key2_string[i])) {
            key2[j] = toupper(key2_string[i]);
            j++;
        }
    }
    key2[j] = '\0';
    
    if (key_count > 0) {
        CDKeyDecoder *ctx = bnet_key_create_context(key1);
        if (bnet_is_key_valid(ctx)) {
            keys[0].length = strlen(key1);
            keys[0].product_value = bnet_key_get_product(ctx);
            keys[0].public_value = bnet_key_get_val1(ctx);
            keys[0].private_value = 0;
            bnet_key_calculate_hash(ctx, client_cookie, server_cookie);
            bnet_key_get_hash(ctx, (guint8 *)(&(keys[0].key_hash)));
            bnet_key_free(ctx);
        } else {
            keys[0].length = 0;
            return FALSE;
        }
    }
    
    if (key_count > 1) {
        CDKeyDecoder *ctx = bnet_key_create_context(key2);
        if (bnet_is_key_valid(ctx)) {
            keys[1].length = strlen(key2);
            keys[1].product_value = bnet_key_get_product(ctx);
            keys[1].public_value = bnet_key_get_val1(ctx);
            keys[1].private_value = 0;
            bnet_key_calculate_hash(ctx, client_cookie, server_cookie);
            bnet_key_get_hash(ctx, (guint8 *)(&(keys[1].key_hash)));
            bnet_key_free(ctx);
        } else {
            keys[1].length = 0;
            return FALSE;
        }
    }
    
    return TRUE;
}

void bnet_key_free(CDKeyDecoder *ctx)
{
    if (ctx->cdkey != NULL)
        g_free(ctx->cdkey);
    if (ctx->keyHash != NULL)
        g_free(ctx->keyHash);
    if (ctx->w3value2 != NULL)
        g_free(ctx->w3value2);
    g_free(ctx);
}

/**
 * Creates a new CD-key decoder object, using the specified key.
 * keyLength should be the length of the key, NOT INCLUDING the
 * null-terminator.  Applications should use isKeyValid after using
 * this constructor to check the validity of the provided key.
 */
CDKeyDecoder *bnet_key_create_context(const char *cdkey)
{
    CDKeyDecoder *ctx = g_new0(CDKeyDecoder, 1);
    
    guint i;
    gsize keyLength = strlen(cdkey);
    
    ctx->initialized = FALSE;
        ctx->product = 0;
        ctx->value1 = 0;
        ctx->value2 = 0;
    ctx->keyOK = FALSE;
    ctx->hashLen = 0;
        ctx->cdkey = (char*) 0;
        ctx->w3value2 = (char*) 0;
        //ctx->keyHash = (guint8 *)0;
    
    if (keyLength <= 0) return ctx;
    
    // Initial sanity check
    if (keyLength == 13) {
        // StarCraft key
        for (i = 0; i < keyLength; i++) {
            if (!isdigit(cdkey[i])) return ctx;
        }
        ctx->keyType = CDKEY_TYPE_SC;
#if DEBUG
                                bncsutil_debug_message_a(
                                        "Created CD key decoder with STAR key %s.", cdKey
                                );
#endif
    } else {
        // D2/W2/W3 key
        for (i = 0; i < keyLength; i++) {
            if (!isalnum(cdkey[i])) return ctx;
        }
        switch (keyLength) {
            case 16:
                ctx->keyType = CDKEY_TYPE_W2D2;
#if DEBUG
                                bncsutil_debug_message_a(
                                        "Created CD key decoder with W2/D2 key %s.", cdKey
                                );
#endif
                break;
            case 26:
                ctx->keyType = CDKEY_TYPE_W3;
#if DEBUG
                                bncsutil_debug_message_a(
                                        "Created CD key decoder with WAR3 key %s.", cdKey
                                );
#endif
                break;
            default:
                ctx->keyType = CDKEY_TYPE_UNKNOWN;
#if DEBUG
                                bncsutil_debug_message_a(
                                        "Created CD key decoder with unrecognized key %s.", cdKey
                                );
#endif
                return ctx;
        }
    }
    
    ctx->cdkey = g_new0(char, keyLength + 1);
    ctx->initialized = TRUE;
    ctx->keyLen = keyLength;
    strcpy(ctx->cdkey, cdkey);
    
    switch (ctx->keyType) {
        case CDKEY_TYPE_SC:
            ctx->keyOK = process_sc(ctx);
#if DEBUG
                        bncsutil_debug_message_a("%s: ok=%d; product=%d; public=%d; "
                                "private=%d", cdkey, keyOK, getProduct(), getVal1(), getVal2());
#endif
            break;
        case CDKEY_TYPE_W2D2:
            ctx->keyOK = process_w2d2(ctx);
#if DEBUG
                        bncsutil_debug_message_a("%s: ok=%d; product=%d; public=%d; "
                                "private=%d", cdkey, keyOK, getProduct(), getVal1(), getVal2());
#endif
            break;
        case CDKEY_TYPE_W3:
            ctx->keyOK = process_w3(ctx);
#if DEBUG
                        bncsutil_debug_message_a("%s: ok=%d; product=%d; public=%d; ",
                                cdkey, keyOK, getProduct(), getVal1());
#endif
            break;
        default:
            return ctx;
    }
    
    return ctx;
}
/*
CDKeyDecoder::~CDKeyDecoder() {
    if (initialized && cdkey != NULL)
        delete [] cdkey;
    if (hashLen > 0 && keyHash != NULL)
        delete [] keyHash;
        if (w3value2)
                delete [] w3value2;
}*/

gboolean bnet_is_key_valid(CDKeyDecoder *ctx)
{
    return (ctx->initialized && ctx->keyOK) ? TRUE : FALSE;
}

int bnet_key_get_val2_length(CDKeyDecoder *ctx)
{
    return (ctx->keyType == CDKEY_TYPE_W3) ? 10 : 4;
}

guint32 bnet_key_get_product(CDKeyDecoder *ctx)
{
        switch (ctx->keyType) {
                case CDKEY_TYPE_SC:
                case CDKEY_TYPE_W2D2:
                        return (guint32) LSB4(ctx->product);
                case CDKEY_TYPE_W3:
                        return (guint32) MSB4(ctx->product);
                default:
                        return (guint32) -1;
        }
}

guint32 bnet_key_get_val1(CDKeyDecoder *ctx)
{
    switch (ctx->keyType) {
                case CDKEY_TYPE_SC:
                case CDKEY_TYPE_W2D2:
                        return (guint32) LSB4(ctx->value1);
                case CDKEY_TYPE_W3:
                        return (guint32) MSB4(ctx->value1);
                default:
                        return (guint32) -1;
        }
}

guint32 bnet_key_get_val2(CDKeyDecoder *ctx)
{
    return (guint32) LSB4(ctx->value2);
}

guint32 bnet_key_get_long_val2(CDKeyDecoder *ctx, char* out)
{
    if (ctx->w3value2 != NULL && ctx->keyType == CDKEY_TYPE_W3) {
        memcpy(out, ctx->w3value2, 10);
        return 10;
    } else {
        return 0;
    }
}

/**
 * Calculates the CD-Key hash for use in SID_AUTH_CHECK (0x51)
 * Returns the length of the generated hash; call getHash and pass
 * it a character array that is at least this size.  Returns 0 on failure.
 *
 * Note that clientToken and serverToken will be added to the buffer and
 * hashed as-is, regardless of system endianness.  It is assumed that
 * the program's extraction of the server token does not change its
 * endianness, and since the client token is generated by the client,
 * endianness is not a factor.
 */
gsize bnet_key_calculate_hash(CDKeyDecoder *ctx, const guint32 clientToken,
    const guint32 serverToken)
{
    if (!ctx->initialized || !ctx->keyOK) return 0;
    ctx->hashLen = 0;
    
    switch (ctx->keyType) {
        case CDKEY_TYPE_SC:
        case CDKEY_TYPE_W2D2:
        {
            guint32 product = (guint32) bnet_key_get_product(ctx);
            guint32 value1 = (guint32) bnet_key_get_val1(ctx);
            guint32 zero = 0;
            guint32 value2 = (guint32) bnet_key_get_val2(ctx);
            
            sha1_context sha;
            guint8 res[SHA1_HASH_SIZE];
            sha.version = SHA1_TYPE_BROKEN;
            sha1_reset(&sha);
            sha1_input(&sha, (guint8 *)(&clientToken), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&serverToken), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&product), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&value1), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&zero), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&value2), BNET_SIZE_DWORD);
            sha1_digest(&sha, res);
            ctx->keyHash = g_malloc0(SHA1_HASH_SIZE);
            g_memmove(ctx->keyHash, res, SHA1_HASH_SIZE);
            ctx->hashLen = SHA1_HASH_SIZE;

#if DEBUG
                        bncsutil_debug_message_a("%s: Hash calculated.", cdkey);
                        bncsutil_debug_dump(keyHash, SHA1_HASH_SIZE);
#endif

            return SHA1_HASH_SIZE;
        }
        case CDKEY_TYPE_W3:
        {
            guint32 product = (guint32) bnet_key_get_product(ctx);
            guint32 value1 = (guint32) bnet_key_get_val1(ctx);
            //guint32 zero = 0;
            unsigned char *value2x = g_malloc0(10);
            sha1_context sha;
            guint8 res[SHA1_HASH_SIZE];
            
            bnet_key_get_long_val2(ctx, (char *)value2x);
            
            sha.version = SHA1_TYPE_NORMAL;
            sha1_reset(&sha);
            sha1_input(&sha, (guint8 *)(&clientToken), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&serverToken), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&product), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(&value1), BNET_SIZE_DWORD);
            //sha1_input(&sha, (guint8 *)(&zero), BNET_SIZE_DWORD);
            sha1_input(&sha, (guint8 *)(value2x), 10);
            sha1_digest(&sha, res);
            ctx->keyHash = g_malloc0(SHA1_HASH_SIZE);
            g_memmove(ctx->keyHash, res, SHA1_HASH_SIZE);
            ctx->hashLen = SHA1_HASH_SIZE;
                        
#if DEBUG
                        bncsutil_debug_message_a("%s: Hash calculated.", cdkey);
                        bncsutil_debug_dump(keyHash, SHA1_HASH_SIZE);
#endif
            
            g_free(value2x);

            return SHA1_HASH_SIZE;
        }
        default:
            return 0;
    }
}

/**
 * Places the calculated CD-key hash in outputBuffer.  You must call
 * calculateHash before getHash.  Returns the length of the hash
 * that was copied to outputBuffer, or 0 on failure.
 */
gsize bnet_key_get_hash(CDKeyDecoder *ctx, guint8* outputBuffer)
{
    if (ctx->hashLen == 0 || !ctx->keyHash || !outputBuffer)
                return 0;
    g_memmove(outputBuffer, ctx->keyHash, ctx->hashLen);
    return ctx->hashLen;
}

/*
void CDKeyDecoder::swapChars(char* string, int a, int b) {
    char temp;
    temp = string[a];
    string[a] = string[b];
    string[b] = temp;
}
*/

gboolean process_sc(CDKeyDecoder *ctx)
{
    int accum, pos, i;
    char temp;
    int hashKey = 0x13AC9741;
    char cdkey[14];
    
    strcpy(cdkey, ctx->cdkey);
    
    // Verification
    accum = 3;
    for (i = 0; i < (int) (ctx->keyLen - 1); i++) {
        accum += ((tolower(cdkey[i]) - '0') ^ (accum * 2));
    }
    
        if ((accum % 10) != (cdkey[12] - '0')) {
#if DEBUG
                bncsutil_debug_message_a("error: %s is not a valid StarCraft key", cdkey);
#endif
        return 0;
        }
    
    // Shuffling
    pos = 0x0B;
    for (i = 0xC2; i >= 7; i -= 0x11) {
        temp = cdkey[pos];
        cdkey[pos] = cdkey[i % 0x0C];
        cdkey[i % 0x0C] = temp;
        pos--;
    }
    
    // Final Value
    for (i = (int) (ctx->keyLen - 2); i >= 0; i--) {
        temp = toupper(cdkey[i]);
        cdkey[i] = temp;
        if (temp <= '7') {
            cdkey[i] ^= (char) (hashKey & 7);
            hashKey >>= 3;
        } else if (temp < 'A') {
            cdkey[i] ^= ((char) i & 1);
        }
    }
    
    // Final Calculations
    sscanf(cdkey, "%2ld%7ld%3ld", (long int *)&ctx->product, (long int *)&ctx->value1, (long int *)&ctx->value2);
    
    return 1;
}

gboolean process_w2d2(CDKeyDecoder *ctx)
{
    unsigned long r, n, n2, v, v2, checksum;
    int i, j;
    unsigned char c1, c2, c;
    char cdkey[17];

    strcpy(cdkey, ctx->cdkey);
    
    r = 1;
    checksum = 0;
    for (i = 0; i < 16; i += 2) {
        c1 = w2Map[(int) cdkey[i]];
        n = c1 * 3;
        c2 = w2Map[(int) cdkey[i + 1]];
        n = c2 + n * 8;
        
        if (n >= 0x100) {
            n -= 0x100;
            checksum |= r;
        }
        // !
        n2 = n >> 4;
        // !
        cdkey[i] = getHexValue(n2);
        cdkey[i + 1] = getHexValue(n);
        r <<= 1;
    }
    
    v = 3;
    for (i = 0; i < 16; i++) {
        c = cdkey[i];
        n = getNumValue(c);
        n2 = v * 2;
        n ^= n2;
        v += n;
    }
    v &= 0xFF;
    
    if (v != checksum) {
        return 0;
    }
    
    n = 0;
    for (j = 15; j >= 0; j--) {
        c = cdkey[j];
        if (j > 8) {
            n = (j - 9);
        } else {
            n = (0xF - (8 - j));
        }
        n &= 0xF;
        c2 = cdkey[n];
        cdkey[j] = c2;
        cdkey[n] = c;
    }
    v2 = 0x13AC9741;
    for (j = 15; j >= 0; j--) {
        c = toupper(cdkey[j]);
        cdkey[j] = c;
        if (c <= '7') {
            v = v2;
            c2 = (((char) (v & 0xFF)) & 7) ^ c;
            v >>= 3;
            cdkey[j] = (char) c2;
            v2 = v;
        } else if (c < 'A') {
            cdkey[j] = (((char) j) & 1) ^ c;
        }
    }

    // Final Calculations
    sscanf(cdkey, "%2lx%6lx%8lx", (long int *)&ctx->product, (long int *)&ctx->value1, (long int *) &ctx->value2);
    return 1;
}

gboolean process_w3(CDKeyDecoder *ctx)
{
    char table[W3_BUFLEN];
    int values[4];
    int a, b;
    int i;
    char decode;
    
    a = 0;
    b = 0x21;
    
    memset(table, 0, W3_BUFLEN);
    memset(values, 0, (sizeof(int) * 4));
    
    for (i = 0; ((unsigned int) i) < ctx->keyLen; i++) {
        ctx->cdkey[i] = toupper(ctx->cdkey[i]);
        a = (b + 0x07B5) % W3_BUFLEN;
        b = (a + 0x07B5) % W3_BUFLEN;
        decode = w3KeyMap[(int)ctx->cdkey[i]];
        table[a] = (decode / 5);
        table[b] = (decode % 5);
    }
    
    // Mult
    i = W3_BUFLEN;
    do {
        mult(4, 5, values + 3, table[i - 1]);
    } while (--i);
    
    decodeKeyTable(values);
        
        // 00 00 38 08 f0 64 18 6c 79 14 14 8E B9 49 1D BB
        //          --------
        //            val1

        ctx->product = values[0] >> 0xA;
        ctx->product = SWAP4(ctx->product);
#if LITTLEENDIAN
        for (i = 0; i < 4; i++) {
                values[i] = MSB4(values[i]);
        }
#endif

        ctx->value1 = LSB4(*(guint32 *) (((char*) values) + 2)) & 0xFFFFFF03;
        
        ctx->w3value2 = g_malloc0(10);
#if LITTLEENDIAN
        *((guint16 *) ctx->w3value2) = MSB2(*((guint16 *) (((char*) values) + 6)));
        *((guint32 *) ((char*) ctx->w3value2 + 2)) = MSB4(*((guint32 *) (((char*) values) + 8)));
        *((guint32 *) ((char*) ctx->w3value2 + 6)) = MSB4(*((guint32 *) (((char*) values) + 12)));
#else
        *((guint16 *) ctx->w3value2) = LSB2(*((guint16 *) (((char*) values) + 6)));
        *((guint32 *) ((char*) ctx->w3value2 + 2)) = LSB4(*((guint32 *) (((char*) values) + 8)));
        *((guint32 *) ((char*) ctx->w3value2 + 6)) = LSB4(*((guint32 *) (((char*) values) + 12)));
#endif
        return 1;
}

void mult(int r, const int x, int* a, int dcByte)
{
    while (r--) {
        int64_t edxeax = ((int64_t) (*a & 0x00000000FFFFFFFFl))
            * ((int64_t) (x & 0x00000000FFFFFFFFl));
        *a-- = dcByte + (int32_t) edxeax;
        dcByte = (int32_t) (edxeax >> 32);
    }
}

void decodeKeyTable(int* keyTable)
{
    unsigned int eax, ebx, ecx, edx, edi, esi, ebp;
    unsigned int varC, var4, var8;
    unsigned int copy[4];
    unsigned char* scopy;
    int* ckt;
    int ckt_temp;
    int i = 464;
    var8 = 29;
    
    // pass 1
    do {
        int j;
        esi = (var8 & 7) << 2;
        var4 = var8 >> 3;
        //varC = (keyTable[3 - var4] & (0xF << esi)) >> esi;
        varC = keyTable[3 - var4];
        varC &= (0xF << esi);
        varC = varC >> esi;
        
        if (i < 464) {
            for (j = 29; (unsigned int) j > var8; j--) {
                /*
                ecx = (j & 7) << 2;
                ebp = (keyTable[0x3 - (j >> 3)] & (0xF << ecx)) >> ecx;
                varC = w3TranslateMap[ebp ^ w3TranslateMap[varC + i] + i];
                */
                ecx = (j & 7) << 2;
                //ebp = (keyTable[0x3 - (j >> 3)] & (0xF << ecx)) >> ecx;
                ebp = (keyTable[0x3 - (j >> 3)]);
                ebp &= (0xF << ecx);
                ebp = ebp >> ecx;
                varC = w3TranslateMap[ebp ^ (w3TranslateMap[varC + i] + i)];
            }
        }
        
        j = --var8;
        while (j >= 0) {
            ecx = (j & 7) << 2;
            //ebp = (keyTable[0x3 - (j >> 3)] & (0xF << ecx)) >> ecx;
            ebp = (keyTable[0x3 - (j >> 3)]);
            ebp &= (0xF << ecx);
            ebp = ebp >> ecx;
            varC = w3TranslateMap[ebp ^ (w3TranslateMap[varC + i] + i)];
            j--;
        }
        
        j = 3 - var4;
        ebx = (w3TranslateMap[varC + i] & 0xF) << esi;
        keyTable[j] = (ebx | (~(0xF << esi) & ((int) keyTable[j])));
    } while ((i -= 16) >= 0);
    
    // pass 2
    eax = 0;
    edx = 0;
    ecx = 0;
    edi = 0;
    esi = 0;
    ebp = 0;
    
    for (i = 0; i < 4; i++) {
        copy[i] = LSB4(keyTable[i]);
    }
    scopy = (unsigned char*) copy;
    
    for (edi = 0; edi < 120; edi++) {
        unsigned int location = 12;
        eax = edi & 0x1F;
        ecx = esi & 0x1F;
        edx = 3 - (edi >> 5);
        
        location -= ((esi >> 5) << 2);
        ebp = *(int*) (scopy + location);
        ebp = LSB4(ebp);
        
        //ebp = (ebp & (1 << ecx)) >> ecx;
        ebp &= (1 << ecx);
        ebp = ebp >> ecx;
        
        //keyTable[edx] = ((ebp & 1) << eax) | (~(1 << eax) & keyTable[edx]);
        ckt = (keyTable + edx);
        ckt_temp = *ckt;
        *ckt = ebp & 1;
        *ckt = *ckt << eax;
        *ckt |= (~(1 << eax) & ckt_temp);
        esi += 0xB;
        if (esi >= 120)
            esi -= 120;
    }
}

char getHexValue(int v)
{
    v &= 0xF;
    return (v < 10) ? (v + 0x30) : (v + 0x37);
}

int getNumValue(char c)
{
    c = toupper(c);
    return (isdigit(c)) ? (c - 0x30) : (c - 0x37);
}

#endif
