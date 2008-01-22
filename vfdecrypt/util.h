#ifndef _UTIL_H

#include "vfdecrypt.h"

#define _UTIL_H	1

void print_hex(uint8_t * /* data */, uint32_t /* len */);
void convert_hex(char * /* str */, uint8_t * /* bytes */,
		 int /* maxlen */);
void dump_v2_header(void * /* hdr */);
void adjust_v1_header_byteorder(cencrypted_v1_header * /* hdr */);
void adjust_v2_header_byteorder(cencrypted_v2_pwheader * /* pwhdr */);

#endif
