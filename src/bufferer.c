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

#ifndef _BUFFERER_C_
#define _BUFFERER_C_

#include "bufferer.h"

void
bnet_packet_free(BnetPacket *bnet_packet)
{
    if (bnet_packet->allocd) {
        if (bnet_packet->data != NULL) {
            g_free(bnet_packet->data);
        }
    }
    g_free(bnet_packet);
}

gboolean
bnet_packet_insert(BnetPacket *bnet_packet, gconstpointer data, const gsize length)
{
    gsize _length = length;

    if (bnet_packet->allocd == FALSE) return FALSE;

    if (_length == BNET_SIZE_CSTRING) {
        _length = strlen(data) + 1;
    }
    
    while (bnet_packet->pos + _length > bnet_packet->len) {
        bnet_packet->len += BNET_BUFFER_GROW_SIZE;
        if (bnet_packet->data == NULL) return FALSE;
        bnet_packet->data = g_realloc(bnet_packet->data, bnet_packet->len);
    }
    
    if (bnet_packet->data == NULL) return FALSE;
    
    g_memmove(bnet_packet->data + bnet_packet->pos, data, _length);
    bnet_packet->pos += _length;
    
    return TRUE;
}

BnetPacket *
bnet_packet_refer(const gchar *start, const gsize length)
{
    BnetPacket *bnet_packet = g_new0(BnetPacket, 1);
    bnet_packet->pos = 4;
    bnet_packet->len = length;
    bnet_packet->data = (gchar *)start;
    bnet_packet->allocd = FALSE;
    
    return bnet_packet;
}

BnetPacket *
bnet_packet_refer_bnls(const gchar *start, const gsize length)
{
    BnetPacket *bnet_packet = g_new0(BnetPacket, 1);
    bnet_packet->pos = 3;
    bnet_packet->len = length;
    bnet_packet->data = (gchar *)start;
    bnet_packet->allocd = FALSE;
    
    return bnet_packet;
}

BnetPacket *
bnet_packet_deserialize(const gchar *str)
{
    BnetPacket *bnet_packet;
    guchar *ret;
    gsize ret_len;
    
    ret = purple_base64_decode(str, &ret_len);
    
    purple_debug_misc("bnet", "DESERIALIZE: length %d\n", (int)ret_len);
    
    if (ret == NULL) {
        return NULL;
    }
    
    bnet_packet = g_new0(BnetPacket, 1);
    bnet_packet->pos = 0;
    bnet_packet->len = (guint16)ret_len;
    bnet_packet->data = (gchar *)ret;
    bnet_packet->allocd = FALSE;
    
    return bnet_packet;
}

gboolean
bnet_packet_can_read(BnetPacket *bnet_packet, const gsize size)
{
    if (bnet_packet->allocd == TRUE) return FALSE;
    return (bnet_packet->len >= bnet_packet->pos + size);
}

void *
bnet_packet_read(BnetPacket *bnet_packet, const gsize size)
{
    void *ret;
    
    if (bnet_packet->allocd == TRUE) return NULL;
    
    if (bnet_packet->len < bnet_packet->pos + size) {
        return NULL;
    }
    ret = g_memdup(bnet_packet->data + bnet_packet->pos, size);
    bnet_packet->pos += size;
    return ret;
}

char *
bnet_packet_read_cstring(BnetPacket *bnet_packet)
{
    gsize size = 0;
    char *ret;
    
    if (bnet_packet->allocd == TRUE) {
        purple_debug_error("bnet", "read cstring fail 1: allocd=true\n");
        return NULL;
    }
    
    if (bnet_packet->len < bnet_packet->pos + 1) {
        purple_debug_error("bnet", "read cstring fail 2: out of range\n");
        return NULL;
    }
    
    while (*(bnet_packet->data + bnet_packet->pos + size) != 0) {
        size++;
        if (bnet_packet->len < bnet_packet->pos + size) {
            purple_debug_error("bnet", "read cstring fail 3: out of range\n");
            return NULL;
        }
    }
    
    //purple_debug_info("bnet", "%d:%s\n", size,(char *)(bnet_packet->data + bnet_packet->pos));
    
    ret = g_strdup((char *)(bnet_packet->data + bnet_packet->pos));
    
    bnet_packet->pos += size + 1;
    
    //purple_debug_info("bnet", "read cstring success: %s (length: %d; %d)\n", ret, size, strlen(ret));
    
    return ret;
}

guint64
bnet_packet_read_qword(BnetPacket *bnet_packet)
{
    guint64 i;
    void *ret;
    
    ret = bnet_packet_read(bnet_packet, BNET_SIZE_FILETIME);
    if (ret == NULL) return 0;
    i = *((guint64 *)ret);
    g_free(ret);

    return i;
}

guint32
bnet_packet_read_dword(BnetPacket *bnet_packet)
{
    guint32 i;
    void *ret;

    ret = bnet_packet_read(bnet_packet, BNET_SIZE_DWORD);
    if (ret == NULL) return 0;
    i = *((guint32 *)ret);
    g_free(ret);
    
    return i;
}

guint16
bnet_packet_read_word(BnetPacket *bnet_packet)
{
    guint16 i;
    void *ret;

    ret = bnet_packet_read(bnet_packet, BNET_SIZE_WORD);
    if (ret == NULL) return 0;
    i = *((guint16 *)ret);
    g_free(ret);
    return i;
}

guint8
bnet_packet_read_byte(BnetPacket *bnet_packet)
{
    guint8 i;
    void *ret;

    ret = bnet_packet_read(bnet_packet, BNET_SIZE_BYTE);
    if (ret == NULL) return 0;
    i = *((guint8 *)ret);
    g_free(ret);

    return i;
}

BnetPacket *
bnet_packet_create(const gsize header_length)
{
    int zero = 0;
    
    BnetPacket *bnet_packet = g_new0(BnetPacket, 1);
     
    bnet_packet->pos = 0;
    bnet_packet->len = BNET_BUFFER_GROW_SIZE;
    bnet_packet->allocd = TRUE;
    bnet_packet->data = g_malloc0(BNET_BUFFER_GROW_SIZE);
    
    if (bnet_packet->data == NULL) {
        bnet_packet_free(bnet_packet);
        return NULL;
    }
    
    bnet_packet_insert(bnet_packet, &zero, header_length);
    
    return bnet_packet;
}

int
bnet_packet_send(BnetPacket *bnet_packet, const guint8 id, const int fd)
{
    int ret;
    
    *(bnet_packet->data + 0) = BNET_IDENT_FLAG;
    *(bnet_packet->data + 1) = id;
    *(bnet_packet->data + 2) = bnet_packet->pos & 0xFF;
    *(bnet_packet->data + 3) = (bnet_packet->pos >> 8) & 0xFF;
    
    ret = write(fd, bnet_packet->data, bnet_packet->pos);
    
    purple_debug_misc("bnet", "BNCS C>S 0x%02x: length %d\n", id, bnet_packet->pos);
    
    bnet_packet_free(bnet_packet);
    
    return ret;
}

int
bnet_packet_send_bnls(BnetPacket *bnet_packet, const guint8 id, const int fd)
{
    int ret;
    
    *(bnet_packet->data + 0) = bnet_packet->pos & 0xFF;
    *(bnet_packet->data + 1) = (bnet_packet->pos >> 8) & 0xFF;
    *(bnet_packet->data + 2) = id;
    
    ret = write(fd, bnet_packet->data, bnet_packet->pos);
    
    purple_debug_misc("bnet", "BNLS C>S 0x%02x: length %d\n", id, bnet_packet->pos);
    
    bnet_packet_free(bnet_packet);
    
    return ret;
}

gchar *
bnet_packet_serialize(BnetPacket *bnet_packet)
{
    gchar *ret;
    
    purple_debug_misc("bnet", "SERIALIZE: length %d\n", bnet_packet->pos);
    
    ret = purple_base64_encode((guchar *)bnet_packet->data, bnet_packet->pos);
    
    bnet_packet_free(bnet_packet);
    
    return ret;
}

#define HEX_OFFSET    1
#define ASCII_OFFSET 51
#define NUM_CHARS    16

char *
bnet_packet_debug(const BnetPacket *bnet_packet)
{
    guint pos = 0;
    guint8 c = 0;
    int len = 0;
    char *tmp;
    char * hex_offset;
    char * ascii_offset;
    char *final = NULL;
    char line[81];
    
    while (pos < bnet_packet->len )
    {
        /* Prepare the variables.	*/		
        clear_line(line, sizeof line);
        hex_offset   = line+HEX_OFFSET;
        ascii_offset = line+ASCII_OFFSET;

        while ( ascii_offset < line+ASCII_OFFSET+NUM_CHARS)
        {
            if (pos < bnet_packet->len) {
                c = *(bnet_packet->data + pos);
            
                /* Build the hex part of the line.			*/
                hex_offset = hex_char(hex_offset, c); 

                /* Build the Ascii part of the line.			*/
                ascii_offset = ascii_char(ascii_offset, c);
                
                pos++;
            } else {
                c = 0;
                hex_offset += 3;
                ascii_offset++;
            }
        }
        
        /* Append the current line	*/
        if (final == NULL) {
            len += 81;
            final = g_realloc(final, len);
            sprintf(final, "%s", line);
        } else {
            tmp = g_memdup(final, len);
            len += 81;
            final = g_realloc(final, len);
            sprintf(final, "%s\n%s", tmp, line);
            g_free(tmp);
        }
    }
    
    return final;
}

/************************************************************************
 *
 *	Clear the display line.
 *
 ************************************************************************/

void
clear_line(char *line, int size)
   {
   int count;

   for  (count=0; count < size; line[count]=' ', count++);
   }

/************************************************************************
 *
 *	Put a character into the display line and return the location 
 * 	of the next character.
 *
 ************************************************************************/
char *
ascii_char(char *position, int c)
   {
					/* If the character is NOT printable
					 * replace it with a '.'	*/
   if (!isprint(c)) c='.';
     
   sprintf(position, "%c", c); 		/* Put the character to the line
					 * so it can be displayed later	*/

					/* Return the position of the next 
					 * ASCII character.		*/
   return(++position);
   }

/************************************************************************
 *
 *	Put the hex value of a character into the display line and 
 *	return the location of the next  hex character.
 *
 ************************************************************************/
char *
hex_char(char *position, int c)
   {
   int offset=3;
				/* Format and place the character into 
				 * the display line.	
				 * (unsigned char) required for correct
				 * O/P.					*/

   sprintf(position, "%02X ", (unsigned char) c); 

   *(position+offset)=' '; 	/* Remove the '/0' created by 'sprint'	*/

   return (position+offset);
   }

#endif
