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
 *
 *
 * This is converted from nls.c from BNCSutil library:
 * - changed "nls" to "srp" since nls = "new logon system" and could be confused with BNLS ("Battle.net logon server")
 *   even though BNLS supports "nls", in our case we are doing it locally; thus I call it "srp" since that is the protocol that is actually implemented
 * - changed to use our SHA-1 functions.
 *
 * BNCSutil
 * Battle.Net Utility Library
 *
 * Copyright (C) 2004-2006 Eric Naeseth
 *
 * New Logon System (SRP) Implementation
 * February 13, 2005
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

//#include <bncsutil/nls.h>
//#include <bncsutil/sha1.h>
//#include <stdio.h>
//#include <ctype.h>
//#include <string.h>
//#include <stdlib.h>
#ifndef _SRP_C_
#define _SRP_C_

#include "srp.h"

/*#ifdef MOS_WINDOWS
#  include <windows.h>
#  if DEBUG
#    define nls_dbg(msg) bncsutil_debug_message(msg)
#  else
#    define nls_dbg(msg)
#  endif
#else
#  define nls_dbg(msg)
#  include <time.h>
#endif*/

/* Raw large integer constants. */
static const gchar srp_I[] = {
    0x6c, 0xe, 0x97, 0xed, 0xa, 0xf9, 0x6b, 0xab, 0xb1, 0x58, 0x89, 0xeb,
    0x8b, 0xba, 0x25, 0xa4, 0xf0, 0x8c, 0x1, 0xf8
};

static const gchar srp_sig_n[] = {
    0xD5, 0xA3, 0xD6, 0xAB, 0x0F, 0x0D, 0xC5, 0x0F, 0xC3, 0xFA, 0x6E, 0x78,
    0x9D, 0x0B, 0xE3, 0x32, 0xB0, 0xFA, 0x20, 0xE8, 0x42, 0x19, 0xB4, 0xA1,
    0x3A, 0x3B, 0xCD, 0x0E, 0x8F, 0xB5, 0x56, 0xB5, 0xDC, 0xE5, 0xC1, 0xFC,
    0x2D, 0xBA, 0x56, 0x35, 0x29, 0x0F, 0x48, 0x0B, 0x15, 0x5A, 0x39, 0xFC,
    0x88, 0x07, 0x43, 0x9E, 0xCB, 0xF3, 0xB8, 0x73, 0xC9, 0xE1, 0x77, 0xD5,
    0xA1, 0x06, 0xA6, 0x20, 0xD0, 0x82, 0xC5, 0x2D, 0x4D, 0xD3, 0x25, 0xF4,
    0xFD, 0x26, 0xFC, 0xE4, 0xC2, 0x00, 0xDD, 0x98, 0x2A, 0xF4, 0x3D, 0x5E,
    0x08, 0x8A, 0xD3, 0x20, 0x41, 0x84, 0x32, 0x69, 0x8E, 0x8A, 0x34, 0x76,
    0xEA, 0x16, 0x8E, 0x66, 0x40, 0xD9, 0x32, 0xB0, 0x2D, 0xF5, 0xBD, 0xE7,
    0x57, 0x51, 0x78, 0x96, 0xC2, 0xED, 0x40, 0x41, 0xCC, 0x54, 0x9D, 0xFD,
    0xB6, 0x8D, 0xC2, 0xBA, 0x7F, 0x69, 0x8D, 0xCF
};

/* Private-use function prototypes. */

static guint32 srp_pre_seed(void);
static void srp_get_x(srp_t *srp, mpz_t x_c, const gchar *raw_salt);
static void srp_get_v_mpz(srp_t *srp, mpz_t v, mpz_t x);
static guint32 srp_get_u(const gchar *B);

/* Function definitons */

srp_t *srp_init(const gchar *username, const gchar *password)
{
    return srp_init_l(username, (guint32) strlen(username),
                password, (guint32) strlen(password));
}

srp_t *srp_init_l(const gchar *username, guint32 username_length,
        const gchar *password, guint32 password_length)
{
    guint16 i;
    gchar *d; /* destination */
    gchar *du; /* destination; uppercase */
    const gchar *o; /* original */
    srp_t *srp;
    
    srp = g_new0(srp_t, 1);
    if (!srp)
        return NULL;
    
    srp->username_len = username_length;
    srp->password_len = password_length;
    
    srp->username = (gchar *) g_malloc(srp->username_len + 1);
    srp->username_upper = (gchar *) g_malloc(srp->username_len + 1);
    srp->password_upper = (gchar *) g_malloc(srp->password_len + 1);
    if (!srp->username || !srp->username_upper || !srp->password_upper) {
        g_free(srp);
        return NULL;
    }
    
    d = (gchar *) srp->username;
    du = (gchar *) srp->username_upper;
    o = username;
    for (i = 0; i < srp->username_len; i++) {
        *d = *o;
        *du = (gchar) g_ascii_toupper(*o);
        d++;
        du++;
        o++;
    }
    
    d = (gchar *) srp->password_upper;
    o = password;
    for (i = 0; i < srp->password_len; i++) {
        *d = (gchar) g_ascii_toupper(*o);
        d++;
        o++;
    }
    
    *((gchar *) srp->username + username_length) = 0;
    *((gchar *) srp->username_upper + username_length) = 0;
    *((gchar *) srp->password_upper + password_length) = 0;
    
    mpz_init_set_str(srp->n, SRP_VAR_N_STR, 16);
    
    gmp_randinit_default(srp->rand);
    gmp_randseed_ui(srp->rand, srp_pre_seed());
    mpz_init2(srp->a, 256);
    mpz_urandomm(srp->a, srp->rand, srp->n); /* generates the private key */

    /* The following line replaces preceding 2 lines during testing. */
    /*mpz_init_set_str(srp->a, "1234", 10); */

    srp->A = NULL;
    srp->S = NULL;
    srp->K = NULL;
    srp->M1 = NULL;
    srp->M2 = NULL;
    srp->salt = NULL;
    srp->B = NULL;
    
    return srp;
}

void srp_free(srp_t *srp)
{
    mpz_clear(srp->a);
    mpz_clear(srp->n);

    gmp_randclear(srp->rand);

    g_free(srp->username);
    g_free(srp->username_upper);
    g_free(srp->password_upper);

    if (srp->A)
        g_free(srp->A);
    if (srp->S)
        g_free(srp->S);
    if (srp->K)
        g_free(srp->K);
    if (srp->M1)
        g_free(srp->M1);
    if (srp->M2)
        g_free(srp->M2);
    if (srp->salt)
        g_free(srp->salt);
    if (srp->B)
        g_free(srp->B);

    g_free(srp);
}

srp_t *srp_reinit(srp_t *srp, const gchar *username,
        const gchar *password)
{
        return srp_reinit_l(srp, username, (guint32) strlen(username),
                password, (guint32) strlen(password));
}

srp_t *srp_reinit_l(srp_t *srp, const gchar *username,
        guint32 username_length, const gchar *password,
        guint32 password_length)
{
    guint16 i;
    gchar *d; /* destination */
    gchar *du;
    const gchar *o; /* original */

    if (srp->A)
        g_free(srp->A);
    if (srp->S)
        g_free(srp->S);
    if (srp->K)
        g_free(srp->K);
    if (srp->M1)
        g_free(srp->M1);
    if (srp->M2)
        g_free(srp->M2);

    srp->username_len = username_length;
    srp->password_len = password_length;
    
    srp->username = (gchar *) g_realloc(srp->username,
            srp->username_len + 1);
    if (!srp->username) {
        g_free(srp);
        return NULL;
    }
    srp->username_upper = (gchar *) g_realloc(srp->username_upper,
            srp->username_len + 1);
    if (!srp->username_upper) {
        g_free(srp->username);
        g_free(srp);
        return NULL;
    }
    srp->password_upper = (gchar *) g_realloc(srp->password_upper,
                srp->password_len + 1);
    if (!srp->password_upper) {
        g_free(srp->username);
        g_free(srp->username_upper);
        g_free(srp);
        return NULL;
    }
    
    d = (gchar *) srp->username;
    du = (gchar *) srp->username_upper;
    o = username;
    for (i = 0; i < srp->username_len; i++) {
        *d = *o;
        *du = (gchar) g_ascii_toupper(*o);
        d++;
        du++;
        o++;
    }
    
    d = (gchar *) srp->password_upper;
    o = password;
    for (i = 0; i < srp->password_len; i++) {
        *d = (gchar) g_ascii_toupper(*o);
        d++;
        o++;
    }
    
    *((gchar *) srp->username + username_length) = 0;
    *((gchar *) srp->username_upper + username_length) = 0;
    *((gchar *) srp->password_upper + password_length) = 0;

    mpz_urandomm(srp->a, srp->rand, srp->n); /* generates the private key */

    srp->A = NULL;
    srp->S = NULL;
    srp->K = NULL;
    srp->M1 = NULL;
    srp->M2 = NULL;

    return srp;
}

void srp_get_S(srp_t *srp, gchar *out, const gchar *B, const gchar *salt)
{
    mpz_t temp;
    mpz_t S_base, S_exp;
    mpz_t x;
    mpz_t v;
    
    if (!srp)
        return;

    if (srp->S) {
        memcpy(out, srp->S, 32);
        return;
    }
    
    mpz_init2(temp, 256);
    mpz_import(temp, 32, -1, 1, 0, 0, B);
    
    srp_get_x(srp, x, salt);
    srp_get_v_mpz(srp, v, x);
    
    mpz_init_set(S_base, srp->n);
    mpz_add(S_base, S_base, temp);
    mpz_sub(S_base, S_base, v);
    mpz_mod(S_base, S_base, srp->n);
    
    mpz_init_set(S_exp, x);
    mpz_mul_ui(S_exp, S_exp, srp_get_u(B));
    mpz_add(S_exp, S_exp, srp->a);
    
    mpz_clear(x);
    mpz_clear(v);
    mpz_clear(temp);
    
    mpz_init(temp);
    mpz_powm(temp, S_base, S_exp, srp->n);
    mpz_clear(S_base);
    mpz_clear(S_exp);
    mpz_export(out, (size_t *) 0, -1, 1, 0, 0, temp);
    mpz_clear(temp);

    srp->S = (gchar *) g_malloc(32);
    if (srp->S)
        g_memmove(srp->S, out, 32);
}

guint32 srp_generate_salt_and_v(srp_t *srp, gchar *out)
{
    mpz_t s; /* salt */
    mpz_t v;
    mpz_t x;

    if (!srp)
        return 0;
    
    mpz_init2(s, 256);
    mpz_urandomb(s, srp->rand, 256);
    mpz_export(out, (size_t *) 0, -1, 1, 0, 0, s);
    /*memset(buf, 0, 32);*/
    
    srp_get_x(srp, x, out);
    srp_get_v_mpz(srp, v, x);
    mpz_export(out + 32, (size_t *) 0, -1, 1, 0, 0, v);
    
    mpz_clear(x);
    mpz_clear(v);
    mpz_clear(s);
    
    return 64;
}

void srp_get_v(srp_t *srp, gchar *out, const gchar *salt)
{
    mpz_t g;
    mpz_t v;
    mpz_t x;
    
    if (!srp)
        return;
    
    mpz_init_set_ui(g, SRP_VAR_g);
    mpz_init(v);
    srp_get_x(srp, x, salt);
    
    mpz_powm(v, g, x, srp->n);
    
    mpz_export(out, (size_t *) 0, -1, 1, 0, 0, v);
    mpz_clear(v);
    mpz_clear(g);
    mpz_clear(x);
}


void srp_get_A(srp_t *srp, gchar *out)
{
    mpz_t g;
    mpz_t A;
    size_t o;
    
    if (!srp)
        return;

    if (srp->A) {
        g_memmove(out, srp->A, 32);
        return;
    }
    
    mpz_init_set_ui(g, SRP_VAR_g);
    mpz_init2(A, 256);
    
    mpz_powm(A, g, srp->a, srp->n);
    mpz_export(out, &o, -1, 1, 0, 0, A);
    
    mpz_clear(A);
    mpz_clear(g);

    srp->A = (gchar *) g_malloc(32);
    if (srp->A)
        memcpy(srp->A, out, 32);
}


void srp_get_K(srp_t *srp, gchar *out, const gchar *S)
{
    gchar odd[16], even[16];
    guint8 odd_hash[SHA1_HASH_SIZE], even_hash[SHA1_HASH_SIZE];
    
    gchar *Sp = (gchar *) S;
    gchar *op = odd;
    gchar *ep = even;
    guint16 i;
    
    sha1_context ctx;

    ctx.version = SHA1_TYPE_NORMAL;
    
    if (!srp)
        return;

    if (srp->K) {
        g_memmove(out, srp->K, 40);
        return;
    }
    
    for (i = 0; i < 16; i++) {
        *(op++) = *(Sp++);
        *(ep++) = *(Sp++);
    }
    
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) odd, 16);
    sha1_digest(&ctx, odd_hash);
    
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) even, 16);
    sha1_digest(&ctx, even_hash);
    
    Sp = out;
    op = (gchar *) odd_hash;
    ep = (gchar *) even_hash;
    for (i = 0; i < 20; i++) {
        *(Sp++) = *(op++);
        *(Sp++) = *(ep++);
    }

    srp->K = (gchar *) g_malloc(40);
    if (srp->K)
        g_memmove(srp->K, out, 40);
}

void srp_get_M1(srp_t *srp, gchar *out, const gchar *B, const gchar *salt)
{
    sha1_context ctx;
    guint8 username_hash[SHA1_HASH_SIZE];
    gchar A[32];
    gchar S[32];
    gchar K[40];

    ctx.version = SHA1_TYPE_NORMAL;
    
    if (!srp)
        return;

    if (srp->M1) {
        purple_debug_info("bnet", "SRP: srp_get_M1() using cached M[1] value.");
        memcpy(out, srp->M1, 20);
        return;
    }

    /* calculate SHA-1 hash of username */
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) srp->username_upper, srp->username_len);
    sha1_digest(&ctx, username_hash);

    
    srp_get_A(srp, A);
    srp_get_S(srp, S, B, salt);
    srp_get_K(srp, K, S);

    /* calculate M[1] */
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) srp_I, 20);
    sha1_input(&ctx, username_hash, 20);
    sha1_input(&ctx, (guint8 *) salt, 32);
    sha1_input(&ctx, (guint8 *) A, 32);
    sha1_input(&ctx, (guint8 *) B, 32);
    sha1_input(&ctx, (guint8 *) K, 40);
    sha1_digest(&ctx, (guint8 *) out);

    srp->salt = (gchar *) g_malloc(32);
    srp->B = (gchar *) g_malloc(32);
    srp->M1 = (gchar *) g_malloc(20);
    if (srp->salt)
        g_memmove(srp->salt, salt, 32);
    if (srp->B)
        g_memmove(srp->B, B, 32);
    if (srp->M1)
        g_memmove(srp->M1, out, 20);
}

int srp_check_M2(srp_t *srp, const gchar *var_M2)
{
    sha1_context ctx;
    gchar local_M2[SHA1_HASH_SIZE];
    gchar *A;
    gchar S[32];
    gchar *K;
    gchar *M1;
    guint8 username_hash[SHA1_HASH_SIZE];
    int res;
    int mustFree = 0;

    ctx.version = SHA1_TYPE_NORMAL;
    
    if (!srp)
        return 0;

    if (srp->M2)
        return (memcmp(srp->M2, var_M2, 20) == 0);

    if (srp->A && srp->K && srp->M1) {
        A = srp->A;
        K = srp->K;
        M1 = srp->M1;
    } else {
        if (!srp->B || !srp->salt)
            return 0;

        A = (gchar *) g_malloc(32);
        if (!A)
            return 0;
        K = (gchar *) g_malloc(40);
        if (!K) {
            g_free(A);
            return 0;
        }
        M1 = (gchar *) g_malloc(20);
        if (!M1) {
            g_free(K);
            g_free(A);
            return 0;
        }

        mustFree = 1;

        /* get the other values needed for the hash */
        srp_get_A(srp, A);
        srp_get_S(srp, S, (gchar *) srp->B, (gchar *) srp->salt);
        srp_get_K(srp, K, S);

        /* calculate SHA-1 hash of username */
        sha1_reset(&ctx);
        sha1_input(&ctx, (guint8 *) srp->username_upper, srp->username_len);
        sha1_digest(&ctx, username_hash);
    
        /* calculate M[1] */
        sha1_reset(&ctx);
        sha1_input(&ctx, (guint8 *) srp_I, 20);
        sha1_input(&ctx, username_hash, 20);
        sha1_input(&ctx, (guint8 *) srp->salt, 32);
        sha1_input(&ctx, (guint8 *) A, 32);
        sha1_input(&ctx, (guint8 *) srp->B, 32);
        sha1_input(&ctx, (guint8 *) K, 40);
        sha1_digest(&ctx, (guint8 *) M1);
    }
    
    /* calculate M[2] */
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) A, 32);
    sha1_input(&ctx, (guint8 *) M1, 20);
    sha1_input(&ctx, (guint8 *) K, 40);
    sha1_digest(&ctx, (guint8 *) local_M2);

    res = (memcmp(local_M2, var_M2, 20) == 0);

    if (mustFree) {
        g_free(A);
        g_free(K);
        g_free(M1);
    }

    /* cache result */
    srp->M2 = (gchar *) g_malloc(20);
    if (srp->M2)
        g_memmove(srp->M2, local_M2, 20);
    
    return res;
}

int srp_check_signature(guint32 address, const gchar *signature_raw)
{
    gchar *result_raw;
    gchar check[32];
    mpz_t result;
    mpz_t modulus;
    mpz_t signature;
    gsize size, alloc_size;
    int cmp_result;
    
    /* build the "check" array */
    memcpy(check, &address, 4);
    memset(check + 4, 0xBB, 28);
    
    /* initialize the modulus */
    mpz_init2(modulus, 1024);
    mpz_import(modulus, 128, -1, 1, 0, 0, srp_sig_n);
    
    /* initialize the server signature */
    mpz_init2(signature, 1024);
    mpz_import(signature, 128, -1, 1, 0, 0, signature_raw);
    
    /* initialize the result */
    mpz_init2(result, 1024);
    
    /* calculate the result */
    mpz_powm_ui(result, signature, SRP_SIGNATURE_KEY, modulus);
    
    /* clear (free) the intermediates */
    mpz_clear(signature);
    mpz_clear(modulus);

    /* allocate space for raw signature  */
    alloc_size = mpz_size(result) * sizeof(mp_limb_t);
    result_raw = (gchar *) g_malloc(alloc_size);
    if (!result_raw) {
            mpz_clear(result);
            return 0;
    }
    
    /* get a byte array of the signature */
    mpz_export(result_raw, &size, -1, 1, 0, 0, result);
    
    /* clear (free) the result */
    mpz_clear(result);
    
    /* check the result */
    cmp_result = (memcmp(result_raw, check, 32) == 0);

    /* free the result_raw buffer */
    g_free(result_raw);

    /* return */
    return cmp_result;
}
    
static guint32 srp_pre_seed()
{
#ifdef _WIN32
    return (unsigned long) GetTickCount();
#else
    FILE *f;
    unsigned long r;
    /* try to get data from /dev/random or /dev/urandom */
    f = fopen("/dev/urandom", "r");
    if (!f) {
        f = fopen("/dev/random", "r");
        if (!f) {
            srand(time(NULL));
            return (unsigned long) rand();
        }
    }
    if (fread(&r, sizeof(unsigned long), 1, f) != 1) {
        fclose(f);
        srand(time(NULL));
        return (unsigned long) rand();
    }
    fclose(f);
    return r;
#endif
}

static void srp_get_x(srp_t *srp, mpz_t x_c, const gchar *raw_salt)
{
    gchar *userpass;
    guint8 hash[SHA1_HASH_SIZE], final_hash[SHA1_HASH_SIZE];
    sha1_context ctx;
    
    ctx.version = SHA1_TYPE_NORMAL;
    
    // build the string Username:Password
    userpass = (gchar *) g_malloc(srp->username_len + srp->password_len + 2);
    memcpy(userpass, srp->username_upper, srp->username_len);
    userpass[srp->username_len] = ':';
    memcpy(userpass + srp->username_len + 1, srp->password_upper, srp->password_len);
    userpass[srp->username_len + srp->password_len + 1] = 0; // null-terminator
    
    // get the SHA-1 hash of the string
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) userpass,
        (srp->username_len + srp->password_len + 1));
    sha1_digest(&ctx, hash);
    g_free(userpass);
    
    // get the SHA-1 hash of the salt and user:pass hash
    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) raw_salt, 32);
    sha1_input(&ctx, hash, 20);
    sha1_digest(&ctx, final_hash);
    
    // create an arbitrary-length integer from the hash and return it
    mpz_init2(x_c, 160);
    mpz_import(x_c, 20, -1, 1, 0, 0, (gchar *) final_hash);
}

static void srp_get_v_mpz(srp_t *srp, mpz_t v, mpz_t x)
{
    mpz_t g;
    mpz_init_set_ui(g, SRP_VAR_g);
    mpz_init(v);
    mpz_powm(v, g, x, srp->n);
    mpz_clear(g);
}

#define MSB4(num) ((((num) >> 24) & 0x000000FF) | (((num) >> 8) & 0x0000FF00) | (((num) << 8) & 0x00FF0000) | (((num) << 24) & 0xFF000000))
static guint32 srp_get_u(const gchar *B)
{
    sha1_context ctx;
    union {
        guint8 as8[SHA1_HASH_SIZE];
        guint32 as32[5];
    } data;
    guint32 u;

    ctx.version = SHA1_TYPE_NORMAL;

    sha1_reset(&ctx);
    sha1_input(&ctx, (guint8 *) B, 32);
    sha1_digest(&ctx, data.as8);

    u = data.as32[0];
    u = MSB4(u); // needed? yes
    return u;
}

#endif
