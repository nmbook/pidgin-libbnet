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

#ifndef _USERDATA_H_
#define _USERDATA_H_

#include "glib.h"

// userdata request
#define BNET_USERDATA_PROFILE_REQUEST "profile\\sex\nprofile\\age\nprofile\\location\nprofile\\description"
#define BNET_USERDATA_RECORD_REQUEST(prod, num) "Record\\%s\\%d\\wins\nRecord\\%s\\%d\\losses\nRecord\\%s\\%d\\disconnects\nRecord\\%s\\%d\\last game\nRecord\\%s\\%d\\last game result", (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num)
#define BNET_USERDATA_RECORD_LADDER_REQUEST(prod, num) "Record\\%s\\%d\\wins\nRecord\\%s\\%d\\losses\nRecord\\%s\\%d\\disconnects\nRecord\\%s\\%d\\last game\nRecord\\%s\\%d\\last game result\nRecord\\%s\\%d\\rating\nRecord\\%s\\%d\\high rating\nDynKey\\%s\\%d\\rank\nRecord\\%s\\%d\\high rank", (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num), (prod), (num)
#define BNET_USERDATA_SYSTEM_REQUEST "System\\Account Created\nSystem\\Last Logoff\nSystem\\Last Logon\nSystem\\Time Logged\nSystem\\Username\n"
#define BNET_USERDATA_RECORD_NORMAL  0
#define BNET_USERDATA_RECORD_LADDER  1
#define BNET_USERDATA_RECORD_IRONMAN 3
#define BNET_RECORD_NONE    0
#define BNET_RECORD_NORMAL  1
#define BNET_RECORD_LADDER  2
#define BNET_RECORD_IRONMAN 8

typedef enum {
    BNET_READUSERDATA_REQUEST_NONE    = 0x0,
    BNET_READUSERDATA_REQUEST_PROFILE = 0x1,
    BNET_READUSERDATA_REQUEST_RECORD  = 0x2,
    BNET_READUSERDATA_REQUEST_SYSTEM  = 0x4
} BnetUserDataRequestType;

typedef guint32 BnetProductID;
typedef struct _BnetUserDataRequest BnetUserDataRequest;

void bnet_userdata_request_free(BnetUserDataRequest *req);
BnetUserDataRequest *bnet_userdata_request_new(int cookie, BnetUserDataRequestType type,
                                               const gchar *username, gchar **userdata_keys,
                                               BnetProductID product);
int bnet_userdata_request_get_cookie(const BnetUserDataRequest *req);
gchar *bnet_userdata_request_get_key_by_index(const BnetUserDataRequest *req, int i);
BnetUserDataRequestType bnet_userdata_request_get_type(const BnetUserDataRequest *req);
BnetProductID bnet_userdata_request_get_product(const BnetUserDataRequest *req);

#endif
