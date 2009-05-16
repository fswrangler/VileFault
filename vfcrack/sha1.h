/*
 * Copyright (c) 2006 - David Hulton <dhulton@openciphers.org>
 * see LICENSE for details
 */
/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: sha1.h,v 1.1 2006/04/21 00:52:24 h1kari Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 */

#ifndef SHA1_H
#define SHA1_H

#include <openssl/sha.h>

#define USECACHED 1
#define NOCACHED 0

typedef struct {
  unsigned char k_ipad[sizeof(SHA_CTX)];
  unsigned char k_opad[sizeof(SHA_CTX)];
  unsigned char k_ipad_set;
  unsigned char k_opad_set;
} SHA1_CACHE;

#endif        /* SHA1_H */
