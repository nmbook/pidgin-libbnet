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

#ifndef _USERDATA_C_
#define _USERDATA_C_

#include "userdata.h"

struct _BnetUserDataRequest {
    // readuserdata data:
    // the cookie
    int cookie;
    // the type of request
    BnetUserDataRequestType request_type;
    // the user name
    gchar *username;
    // user data keys
    gchar **userdata_keys;
    // product for this request
    BnetProductID product;
};


void
bnet_userdata_request_free(BnetUserDataRequest *req)
{
    if (req != NULL) {
        if (((struct _BnetUserDataRequest *) req)->username != NULL) {
            g_free(((struct _BnetUserDataRequest *) req)->username);
            ((struct _BnetUserDataRequest *) req)->username = NULL;
        }
        if (((struct _BnetUserDataRequest *) req)->userdata_keys != NULL) {
            g_strfreev(((struct _BnetUserDataRequest *) req)->userdata_keys);
            ((struct _BnetUserDataRequest *) req)->userdata_keys = NULL;
        }
        g_free(req);
    }
}

/**
 * Duplicates: username
 * Do not free: userdata_keys
 */
BnetUserDataRequest *
bnet_userdata_request_new(int cookie, BnetUserDataRequestType type,
                          const gchar *username, gchar **userdata_keys,
                          BnetProductID product)
{
    struct _BnetUserDataRequest *req = g_new0(struct _BnetUserDataRequest, 1);
    req->cookie = cookie;
    req->request_type = type;
    req->username = g_strdup(username);
    req->userdata_keys = userdata_keys;
    req->product = product;
    return (BnetUserDataRequest *)req;
}

int
bnet_userdata_request_get_cookie(const BnetUserDataRequest *req)
{
    return ((struct _BnetUserDataRequest *) req)->cookie;
}

gchar *
bnet_userdata_request_get_key_by_index(const BnetUserDataRequest *req, int i)
{
    return ((struct _BnetUserDataRequest *) req)->userdata_keys[i];
}

BnetUserDataRequestType
bnet_userdata_request_get_type(const BnetUserDataRequest *req)
{
    return ((struct _BnetUserDataRequest *) req)->request_type;
}

BnetProductID
bnet_userdata_request_get_product(const BnetUserDataRequest *req)
{
    return ((struct _BnetUserDataRequest *) req)->product;
}

#endif
