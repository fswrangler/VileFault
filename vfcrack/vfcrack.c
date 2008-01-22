/*
 * Copyright (c) 2006 - David Hulton <dhulton@openciphers.org>
 * see LICENSE for details
 */
/*
 * Copyright (c) 2006 Ralf-Philipp Weinmann <ralf@coderpunks.org>
 *
 * Decrypt a AES-128 encrypted disk image given the encryption key
 * and the hmacsha1key of the image. These two keys can be found
 * out by running hdiutil attach with -debug on the disk image.
 * The chunk size currently is not variable
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "sha1.h"
#include "common.h"

SHA1_CACHE cached;
int sig;
int piconum = -1;
char *picodev = NULL;
extern int usefpga;
static cencrypted_v1_header *header_;
static cencrypted_v2_pwheader *header2_;
static uint8_t *aes_key_;
static uint8_t *hmacsha1_key_;
HMAC_CTX hmacsha1_ctx;
int hdr_version;
FILE *in_;

void print_hex(uint8_t *data, uint32_t len)
{
  uint32_t ctr;
  char *sep;

  for(ctr = 0; ctr < len; ctr++) {
    sep = (((ctr&7)==0)&&ctr) ? "\n" : "";
    fprintf(stderr, "%s%02x ", sep, data[ctr]);
  }
  fprintf(stderr, "\n\n");
}

void convert_hex(char *str, uint8_t *bytes, int maxlen)
{
  int slen = strlen(str);
  int bytelen = (slen+1)/2;
  int rpos, wpos = 0;

  while(wpos < maxlen - bytelen) bytes[wpos++] = 0;

  for(rpos = 0; rpos < bytelen; rpos++)
    sscanf(&str[rpos*2], "%02hhx", &bytes[wpos++]);
}

/* DES3-EDE unwrap according to RFC 2630, section 12.6 
 * instead of the fixed IV 0x4adda22c79e82105, a variable IV is used
 *
 * wrapped_key has to be 40 bytes in length.
 */
int apple_des3_ede_unwrap_key(uint8_t *wrapped_key, int wrapped_key_len, uint8_t *decryptKey, uint8_t *unwrapped_key) 
{
  EVP_CIPHER_CTX ctx;
  uint8_t *TEMP1, *TEMP2, *CEKICV;
  uint8_t IV[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
  int outlen, tmplen, i;

  EVP_CIPHER_CTX_init(&ctx);
  /* result of the decryption operation shouldn't be bigger than ciphertext */
  TEMP1 = malloc(wrapped_key_len);
  TEMP2 = malloc(wrapped_key_len);
  CEKICV = malloc(wrapped_key_len);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, decryptKey, IV);

  if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, wrapped_key, wrapped_key_len))
    return 0;
  if(!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen))
    return 0;
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(&ctx);

  /* reverse order of TEMP3 */
  for(i = 0; i < outlen; i++)
    TEMP2[i] = TEMP1[outlen - i - 1];
  EVP_CIPHER_CTX_init(&ctx);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, decryptKey, TEMP2);
  if(!EVP_DecryptUpdate(&ctx, CEKICV, &outlen, TEMP2+8, outlen-8))
    return 0;
  if(!EVP_DecryptFinal_ex(&ctx, CEKICV + outlen, &tmplen))
    return 0;
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(&ctx);

  /*
   * from libsecurity_apple_csp-12/lib/wrapKeyCms.cpp:
   *
   * XXX ;) --- we assume the length of the descriptive data to be zero
   *
   * 1. PRIVATE_KEY_BYTES is the private data to be wrapped. It consists of the 
   *    following concatenation:
   *
   *    4-byte length of Descriptive Data, big-endian  |
   *    Descriptive Data | 
   *    rawBlob.Data bytes
   */
  
  memcpy(unwrapped_key, CEKICV+4, outlen-4);
  free(TEMP1);
  free(TEMP2);
  free(CEKICV);
  return 1;
}

int determine_header_version(FILE *dmg)
{
  char buf[8];

  fseek(dmg, 0L, SEEK_SET);
  fread(buf, 8, 1, dmg);

  if (!strncmp(buf, "encrcdsa", 8)) {
    return(2);
  }

  fseek(dmg, -8L, SEEK_END);
  fread(buf, 8, 1, dmg);

  if (!strncmp(buf, "cdsaencr", 8)) {
    return(1);
  }

  return(-1);
}

/* HMAC code is based on RFC 2104 
   Modifications (hacks) by Joshua Wright.  Optimized a bit for pbkdf2
   processing by caching values that are repetitive.  There is some repetitive
   code in this function, which I've retained to make it more readable (for my
   sanity's sake).
 */
void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
  size_t num_elem, unsigned char *addr[],
  unsigned char *len, unsigned char *mac, int usecached)
{
  SHA_CTX context;
  unsigned char k_ipad[65];	/* inner padding - key XORd with ipad */
  unsigned char k_opad[65];	/* outer padding - key XORd with opad */
  int i;

  /* the HMAC_SHA1 transform looks like:
   *
   * SHA1(K XOR opad, SHA1(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected */
  if (usecached == NOCACHED || !cached.k_ipad_set || !cached.k_opad_set) {
    /* We either don't want to cache values, or we do want to cache but
       haven't cached them yet. */

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    /* XOR key with ipad and opad values */
    for (i = 0; i < 64; i++) {
      k_ipad[i] ^= 0x36;
      k_opad[i] ^= 0x5c;
    }
    SHA1_Init(&context);	/* init context for 1st pass */
    SHA1_Update(&context, k_ipad, 64);	/* start with inner pad */

    if (usecached) {
      /* Cached the context value */
      memcpy(&cached.k_ipad, &context, sizeof(context));
      cached.k_ipad_set = 1;
    }

    /* then text of datagram; all fragments */
    for (i = 0; i < num_elem; i++)
      SHA1_Update(&context, addr[i], len[i]);
    SHA1_Final(mac, &context);	/* finish up 1st pass */

    /* perform outer SHA1 */
    SHA1_Init(&context);	/* init context for 2nd pass */
    SHA1_Update(&context, k_opad, 64);	/* start with outer pad */
    if (usecached) {
      /* Cached the context value */
      memcpy(&cached.k_opad, &context, sizeof(context));
      cached.k_opad_set = 1;
    }

    SHA1_Update(&context, mac, 20);	/* then results of 1st hash */
    SHA1_Final(mac, &context);	/* finish up 2nd pass */

    return;
  }

  /* End NOCACHED SHA1 processing */
  /* This code attempts to optimize the hmac-sha1 process by caching
  values that remain constant for the same key.  This code is called
  many times by pbkdf2, so all optimizations help. 
  If we've gotten here, we want to use caching, and have already cached
  the values for k_ipad and k_opad after SHA1Update. */
  memcpy(&context, &cached.k_ipad, sizeof(context));
  for (i = 0; i < num_elem; i++)
    SHA1_Update(&context, addr[i], len[i]);
  SHA1_Final(mac, &context);
  memcpy(&context, &cached.k_opad, sizeof(context));
  SHA1_Update(&context, mac, 20);
  SHA1_Final(mac, &context); 
  return;
}

void
pbkdf2_sha1_f(unsigned char *passphrase, size_t passphrase_len,
  unsigned char *salt, size_t salt_len, int iterations, int count,
  unsigned char *digest)
{
  unsigned char tmp[SHA_DIGEST_LENGTH], tmp2[SHA_DIGEST_LENGTH];
  int i, j;
  unsigned char count_buf[4];
  unsigned char *addr[] = { salt, count_buf };
  unsigned char len[] = { salt_len, 4 };
  unsigned char *addr2[] = { tmp };
  unsigned char len2[] = { SHA_DIGEST_LENGTH };

  count_buf[0] = (count >> 24) & 0xff;
  count_buf[1] = (count >> 16) & 0xff;
  count_buf[2] = (count >> 8) & 0xff;
  count_buf[3] = count & 0xff;

  memset(&cached, 0, sizeof(cached));

  hmac_sha1_vector(passphrase, passphrase_len, 2, addr, len, tmp, USECACHED);
  memcpy(digest, tmp, SHA_DIGEST_LENGTH);
  if(usefpga)
    addreg(&cached, digest, (char *)passphrase);
  else {
    for(i = 1; i < iterations; i++) {
      hmac_sha1_vector(passphrase, passphrase_len, 1, addr2, len2, tmp2, USECACHED);
      memcpy(tmp, tmp2, SHA_DIGEST_LENGTH);
      for(j = 0; j < SHA_DIGEST_LENGTH; j++)
        digest[j] ^= tmp2[j];
    }
  }
}

void
pbkdf2_sha1(unsigned char *passphrase, size_t passphrase_len,
  unsigned char *salt, size_t salt_len, int iterations, size_t digest_len,
  unsigned char *digest)
{
  int count = 0;
  unsigned char *pos = digest;
  size_t left = digest_len, plen;
  unsigned char digest_[SHA_DIGEST_LENGTH];

  while(left > 0) {
    count++;
    pbkdf2_sha1_f(passphrase, passphrase_len, salt, salt_len, iterations,
      count, digest_);
    plen = left > SHA_DIGEST_LENGTH ? SHA_DIGEST_LENGTH : left;
    memcpy(pos, digest_, plen);
    pos += plen;
    left -= plen;
  }
}

int
dictfile_v1_found(unsigned char *derived_key, char *passphrase)
{
  if(!apple_des3_ede_unwrap_key(header_->wrapped_aes_key, 40, derived_key, aes_key_))
    return 0;
  /* 2006-12-26, 5pm: correct encryption key is computed */
  if(!apple_des3_ede_unwrap_key(header_->wrapped_hmac_sha1_key, 48, derived_key, hmacsha1_key_))
    return 0;

  printf("found passphrase: %s\n", passphrase);
  exit(0);
}

/**
 * Compute IV of current block as
 * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 */
void compute_iv(uint32_t chunk_no, uint8_t *iv)
{
  unsigned char mdResult[MD_LENGTH];
  unsigned int mdLen;

  chunk_no = htonl(chunk_no);
  HMAC_Init_ex(&hmacsha1_ctx, NULL, 0, NULL, NULL);
  HMAC_Update(&hmacsha1_ctx, (void *) &chunk_no, sizeof(uint32_t));
  HMAC_Final(&hmacsha1_ctx, mdResult, &mdLen);
  memcpy(iv, mdResult, CIPHER_BLOCKSIZE);
}

void decrypt_chunk(uint8_t *ctext, uint8_t *ptext, uint32_t chunk_no)
{
  uint8_t iv[CIPHER_BLOCKSIZE];

  compute_iv(chunk_no, iv);
  AES_cbc_encrypt(ctext, ptext, CHUNK_SIZE, &aes_decrypt_key, iv, AES_DECRYPT);
}

int
dictfile_v2_found(unsigned char *derived_key, char *passphrase)
{
  EVP_CIPHER_CTX ctx;
  uint8_t *TEMP1;
  int outlen, tmplen;
  AES_KEY aes_decrypt_key;
  uint8_t inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE];
//  print_hex(derived_key, 192/8);

  EVP_CIPHER_CTX_init(&ctx);
  /* result of the decryption operation shouldn't be bigger than ciphertext */
  TEMP1 = malloc(header2_->encrypted_blob_size);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, derived_key, header2_->blob_enc_iv);

  if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, header2_->encrypted_blob, header2_->encrypted_blob_size))
    return 0;
  if(!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen))
    return 0;
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(&ctx);
  memcpy(aes_key_, TEMP1, 16);
  memcpy(hmacsha1_key_, TEMP1, 20);

  HMAC_CTX_init(&hmacsha1_ctx);
  HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key_, sizeof(hmacsha1_key_), EVP_sha1(), NULL);
  AES_set_decrypt_key(aes_key_, CIPHER_KEY_LENGTH * 8, &aes_decrypt_key);
  fseek(in_, (long) CHUNK_SIZE, SEEK_SET);

  fread(inbuf, CHUNK_SIZE, 1, in_);
  decrypt_chunk(inbuf, outbuf, 0);
//  print_hex(outbuf, CHUNK_SIZE);

  if(memcmp(outbuf, "\xf6\x6e\xae\x23\xed\xb6\x27\x04\x7f\x5a\x91\xa0\x4b\x17\x82\xf9", 16) != 0)
    return 0;

  printf("found passphrase: %s\n", passphrase);
  exit(0);
}

void adjust_v1_header_byteorder(cencrypted_v1_header *hdr) {
  hdr->kdf_iteration_count = htonl(hdr->kdf_iteration_count);
  hdr->kdf_salt_len = htonl(hdr->kdf_salt_len);
  hdr->len_wrapped_aes_key = htonl(hdr->len_wrapped_aes_key);
  hdr->len_hmac_sha1_key = htonl(hdr->len_hmac_sha1_key);
  hdr->len_integrity_key = htonl(hdr->len_integrity_key);
}

void adjust_v2_header_byteorder(cencrypted_v2_pwheader *pwhdr) {
  pwhdr->kdf_algorithm = htonl(pwhdr->kdf_algorithm);
  pwhdr->kdf_prng_algorithm = htonl(pwhdr->kdf_prng_algorithm);
  pwhdr->kdf_iteration_count = htonl(pwhdr->kdf_iteration_count);
  pwhdr->kdf_salt_len = htonl(pwhdr->kdf_salt_len);
  pwhdr->blob_enc_iv_size = htonl(pwhdr->blob_enc_iv_size);
  pwhdr->blob_enc_key_bits = htonl(pwhdr->blob_enc_key_bits);
  pwhdr->blob_enc_algorithm = htonl(pwhdr->blob_enc_algorithm);
  pwhdr->blob_enc_padding = htonl(pwhdr->blob_enc_padding);
  pwhdr->blob_enc_mode = htonl(pwhdr->blob_enc_mode);
  pwhdr->encrypted_blob_size = htonl(pwhdr->encrypted_blob_size);
}

int unwrap_v1_header(char *passphrase, cencrypted_v1_header *header)
{
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];

  pbkdf2_sha1((unsigned char *)passphrase, strlen(passphrase), (unsigned char *)header->kdf_salt, 20, PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  /* 2006-12-26, 3am: derived_key is correct !!! */
  if(!usefpga)
    dictfile_v1_found(derived_key, passphrase);
  /* 2006-12-26, 5pm: correct hmacsha1 key is computed */
  return 1;
}

int unwrap_v2_header(char *passphrase, cencrypted_v2_pwheader *header)
{
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];

  pbkdf2_sha1((unsigned char *)passphrase, strlen(passphrase), (unsigned char*)header->kdf_salt, 20,
                         PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  if(!usefpga)
    dictfile_v2_found(derived_key, passphrase);

  return 1;
}

int main(int argc, char *argv[])
{
  int i;
  FILE *dict, *in;
  char passphrase[1024];
  uint8_t hmacsha1_key[20];
  uint8_t aes_key[16];
  cencrypted_v1_header header;
  cencrypted_v2_pwheader header2;

  if (argc < 3) {
    fprintf(stderr, "usage: %s <dict> <dmg> [fpga]\n", argv[0]);
    exit(1);

  }

  dict = fopen(argv[1], "rb");
  in = fopen(argv[2], "rb");
  hdr_version = determine_header_version(in);

  if(hdr_version == 1) {
    fseek(in, (long) -sizeof(cencrypted_v1_header), SEEK_END);
    if (fread(&header, sizeof(cencrypted_v1_header), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n");
      exit(0);
    }
    adjust_v1_header_byteorder(&header);
  }

  if(hdr_version == 2) {
    fseek(in, 0L, SEEK_SET);
    if(fread(&header2, sizeof(cencrypted_v2_pwheader), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n");
      exit(0);
    }
    adjust_v2_header_byteorder(&header2);
  }

  if(argc > 3) {
    usefpga = 1;
    piconum = atoi(argv[3]);
    initfpga();
  } else {
    usefpga = 0;
    piconum = -1;
  }
  for(i = 0; ; i++) {
    if(fgets(passphrase, 1024, dict) == NULL)
      break;
    passphrase[strlen(passphrase) - 1] = '\0';
    if(passphrase[strlen(passphrase) - 1] == '\r')
      passphrase[strlen(passphrase) - 1] = '\0';
    header2_ = &header2;
    header_ = &header;
    aes_key_ = aes_key;
    hmacsha1_key_ = hmacsha1_key;
    in_ = in;
    if(hdr_version == 1)
      unwrap_v1_header(passphrase, &header);
    else
      unwrap_v2_header(passphrase, &header2);
    if((i % 100) == 0)
      printf("%d: %s\n", i, passphrase);
  }
  if(usefpga) {
    printf("waiting..."); fflush(stdout);
    finishreg();
    printf("\ndone\n");
  }
 
  fclose(in);
  return 0;
}
