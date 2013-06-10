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
 * This is converted from nls.h from BNCSutil library:
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

#ifndef _SRP_H_
#define _SRP_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <gmp.h>
#include <glib.h>

#include "debug.h"

#include "sha1.h"

#ifdef _WIN32
#include "windows.h"
#endif

// modulus ("N") in base-16
#define SRP_VAR_N_STR \
    "F8FF1A8B619918032186B68CA092B5557E976C78C73212D91216F6658523C787"
// generator var ("g")
#define SRP_VAR_g 0x2F
// SHA1(g) ^ SHA1(N) ("I")
#define SRP_VAR_I_STR "8018CF0A425BA8BEB8958B1AB6BF90AED970E6C"
// Server Signature Key
#define SRP_SIGNATURE_KEY 0x10001

typedef struct {
    gchar *username;
    gchar *username_upper;
    gchar *password_upper;
    guint32 username_len;
    guint32 password_len;
    
    mpz_t n;
    mpz_t a;
    
    gmp_randstate_t rand;

    gchar *A;
    gchar *S;
    gchar *K;
    gchar *M1;
    gchar *M2;
    gchar *salt;
    gchar *B;
} srp_t;

/**
 * Allocates and initializes an srp_t structure.
 * Returns a NULL pointer on failure.
 */
srp_t* srp_init(const gchar* username, const gchar* password);

/**
 * Allocates and initializes an srp_t structure, using the given string lengths.
 * Returns a NULL pointer on failure.
 * (Lengths do not include the null-terminator.)
 */
srp_t* srp_init_l(const gchar* username, guint32 username_length,
        const gchar* password, guint32 password_length);

/**
 * Frees an srp_t structure.
 */
void srp_free(srp_t* srp);

/**
 * Re-initializes an srp_t structure with a new username and
 * password.  Returns the srp argument on success or a NULL
 * pointer on failure.
 */
srp_t* srp_reinit(srp_t* srp, const char* username,
        const char* password);

/**
 * Re-initializes an srp_t structure with a new username and
 * password and their given lengths.  Returns the srp argument
 * on success or a NULL pointer on failure.
 */
srp_t *srp_reinit_l(srp_t *srp, const gchar *username,
        guint32 username_length, const gchar *password,
        guint32 password_length);

/**
 * Generates a salt and verifier. (64 bytes)
 */
guint32 srp_generate_salt_and_v(srp_t *srp, gchar *out);

/* Calculation Functions */

/**
 * Gets the "secret" value (S). (32 bytes)
 */
void srp_get_S(srp_t* srp, char* out, const char* B, const char* salt);

/**
 * Gets the password verifier (v). (32 bytes)
 */
void srp_get_v(srp_t* srp, char* out, const char* salt);

/**
 * Gets the public key (A). (32 bytes)
 */
void srp_get_A(srp_t* srp, char* out);

/**
 * Gets "K" value, which is based on the secret (S).
 * The buffer "out" must be at least 40 bytes long.
 */
void srp_get_K(srp_t* srp, char* out, const char* S);

/**
 * Gets the "M[1]" value, which proves that you know your password.
 * The buffer "out" must be at least 20 bytes long.
 * Also stores salt and B for the M2 check
 */
void srp_get_M1(srp_t* srp, char* out, const char* B, const char* salt);

/**
 * Checks the "M[2]" value, which proves that the server knows your
 * password.  Pass the M2 value in the var_M2 argument.  Returns 0
 * if the check failed, nonzero if the proof matches.  Now that
 * calculated value caching has been added, B and salt can be
 * safely set to NULL.
 */
int srp_check_M2(srp_t* srp, const char* var_M2);

/**
 * Checks the server signature received in SID_AUTH_INFO (0x50).
 * Pass the IPv4 address of the server you're connecting to in the address
 * paramater and the 128-byte server signature in the signature_raw paramater.
 * Address paramater should be in network byte order (big-endian).
 * Returns a nonzero value if the signature matches or 0 on failure.
 * Note that this function does NOT take an srp_t* argument!
 */
int srp_check_signature(guint32 address, const char* signature_raw);

#endif