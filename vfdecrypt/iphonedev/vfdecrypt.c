/*
 * Copyright (c) 2006-2008
 * Ralf-Philipp Weinmann <ralf@coderpunks.org>
 * Jacob Appelbaum <jacob@appelbaum.net>
 * Christian Fromme <kaner@strace.org>
 *
 * Decrypt a AES-128 encrypted disk image given the encryption key
 * and the hmacsha1key of the image. These two keys can be found
 * out by running hdiutil attach with -debug on the disk image.
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
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "vfdecrypt.h"
#include "util.h"

HMAC_CTX hmacsha1_ctx;
AES_KEY aes_decrypt_key;
int CHUNK_SIZE=4096;  // default

/**
 *  * Compute IV of current block as
 *   * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 *    */
void compute_iv(uint32_t chunk_no, uint8_t *iv) {
  unsigned char mdResult[MD_LENGTH];
  unsigned int mdLen,i;
  
  chunk_no = OSSwapHostToBigInt32(chunk_no);
  HMAC_Init_ex(&hmacsha1_ctx, NULL, 0, NULL, NULL);
  HMAC_Update(&hmacsha1_ctx, (void *) &chunk_no, sizeof(uint32_t));
  HMAC_Final(&hmacsha1_ctx, mdResult, &mdLen);
  memcpy(iv, mdResult, CIPHER_BLOCKSIZE);
}

void decrypt_chunk(uint8_t *ctext, uint8_t *ptext, uint32_t chunk_no) {
  uint8_t iv[CIPHER_BLOCKSIZE];

  compute_iv(chunk_no, iv);
  AES_cbc_encrypt(ctext, ptext, CHUNK_SIZE, &aes_decrypt_key, iv, AES_DECRYPT);
}

/* DES3-EDE unwrap operation loosely based on to RFC 2630, section 12.6 
 *    wrapped_key has to be 40 bytes in length.  */
int apple_des3_ede_unwrap_key(uint8_t *wrapped_key, int wrapped_key_len, uint8_t *decryptKey, uint8_t *unwrapped_key) {
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

  if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, wrapped_key, wrapped_key_len)) {
    fprintf(stderr, "internal error (1) during key unwrap operation!\n");
    return(-1);
  }
  if(!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (2) during key unwrap operation!\n");
    return(-1);
  }
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(&ctx);

  /* reverse order of TEMP3 */
  for(i = 0; i < outlen; i++) TEMP2[i] = TEMP1[outlen - i - 1];

  EVP_CIPHER_CTX_init(&ctx);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, decryptKey, TEMP2);
  if(!EVP_DecryptUpdate(&ctx, CEKICV, &outlen, TEMP2+8, outlen-8)) {
    fprintf(stderr, "internal error (3) during key unwrap operation!\n");
    return(-1);
  }
  if(!EVP_DecryptFinal_ex(&ctx, CEKICV + outlen, &tmplen)) {
    fprintf(stderr, "internal error (4) during key unwrap operation!\n");
    return(-1);
  }

  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(&ctx);

  memcpy(unwrapped_key, CEKICV+4, outlen-4);
  free(TEMP1);
  free(TEMP2);
  free(CEKICV);
  return(0);
}

int unwrap_v1_header(char *passphrase, cencrypted_v1_header *header, uint8_t *aes_key, uint8_t *hmacsha1_key) {
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char*)header->kdf_salt, 20, 
			 PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  if (apple_des3_ede_unwrap_key(header->wrapped_aes_key, 40, derived_key, aes_key) != 0)
    return(-1);
  if (apple_des3_ede_unwrap_key(header->wrapped_hmac_sha1_key, 48, derived_key, hmacsha1_key) != 0)
    return(-1);

  return(0);
}

int unwrap_v2_header(char *passphrase, cencrypted_v2_pwheader *header, uint8_t *aes_key, uint8_t *hmacsha1_key) {
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];
  EVP_CIPHER_CTX ctx;
  uint8_t *TEMP1;
  int outlen, tmplen;

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char*)header->kdf_salt, 20,
			 PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  print_hex(derived_key, 192/8);

  EVP_CIPHER_CTX_init(&ctx);
  /* result of the decryption operation shouldn't be bigger than ciphertext */
  TEMP1 = malloc(header->encrypted_keyblob_size);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, derived_key, header->blob_enc_iv);

  if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, header->encrypted_keyblob, header->encrypted_keyblob_size)) {
    fprintf(stderr, "internal error (1) during key unwrap operation!\n");
    return(-1);
  }
  if(!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (2) during key unwrap operation!\n");
    return(-1);
  }
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(&ctx);
  memcpy(aes_key, TEMP1, 16);
  memcpy(hmacsha1_key, TEMP1, 20);

  return(0);
}

int determine_header_version(FILE *dmg) {
  return(2);
}

int usage(char *message) {
  fprintf(stderr, "%s\n", message);
  fprintf(stderr, "Usage: vfdecrypt -i in-file [-p password] [-k key] -o out-file\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  FILE *in, *out;
  cencrypted_v1_header v1header;
  cencrypted_v2_pwheader v2header;
  
  uint8_t hmacsha1_key[20], aes_key[16], inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE];
  uint32_t chunk_no;
  int hdr_version, c,i, optError = 0;
  char inFile[512], outFile[512], passphrase[512];
  int iflag = 0, oflag = 0, pflag = 0, kflag = 1, verbose = 0;
  extern char *optarg;
  extern int optind, optopt;
  //--------INSERT KEY HERE--------------
  //Find the key using command:
  // strings 009-7662-6.dmg | grep "^[0-9a-fA-F]*$"
  //It's the longest string that pops out
  //The first bit of the key replaces the first set of hyphens
  convert_hex("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", aes_key, 16);
  //The second bit is the second set - there is no separation in the file though
  convert_hex("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", hmacsha1_key, 20);

    if ((in = fopen(argv[1], "rb")) == NULL) {
      fprintf(stderr, "Error: unable to open input %s\n", inFile);
      exit(1);
    }

    if ((out = fopen(argv[2], "wb")) == NULL) {
      fprintf(stderr, "Error: unable to open output %s\n", outFile);
      exit(1);
    }
 
  hdr_version = determine_header_version(in);
  
  if (verbose >= 1) {
    if (hdr_version > 0) {
      fprintf(stderr, "v%d header detected.\n", hdr_version);
    } else {
      fprintf(stderr, "unknown format.\n");
      exit(1);
    }
  }
  
  if (hdr_version == 1) {
    fseek(in, (long) -sizeof(cencrypted_v1_header), SEEK_END);
    if (fread(&v1header, sizeof(cencrypted_v1_header), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n"), exit(1);
    }
    adjust_v1_header_byteorder(&v1header);
    if(!kflag) unwrap_v1_header(passphrase, &v1header, aes_key, hmacsha1_key);
  }
  
  if (hdr_version == 2) {
    fseek(in, 0L, SEEK_SET);
    if (fread(&v2header, sizeof(cencrypted_v2_pwheader), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n"), exit(1);
    }
    adjust_v2_header_byteorder(&v2header);
    dump_v2_header(&v2header);
    if(!kflag) unwrap_v2_header(passphrase, &v2header, aes_key, hmacsha1_key);
    CHUNK_SIZE = v2header.blocksize;
  }
  
  HMAC_CTX_init(&hmacsha1_ctx);
  HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key, sizeof(hmacsha1_key), EVP_sha1(), NULL);
  AES_set_decrypt_key(aes_key, CIPHER_KEY_LENGTH * 8, &aes_decrypt_key);
  
  if (verbose >= 1) {
    printf("AES Key: \n");
    print_hex(aes_key, 16);
    printf("SHA1 seed: \n");
    print_hex(hmacsha1_key, 20);
  }
  
  if (hdr_version == 2) fseek(in, v2header.dataoffset, SEEK_SET);
  else fseek(in, 0L, SEEK_SET);
  
  chunk_no = 0;
  while(fread(inbuf, CHUNK_SIZE, 1, in) > 0) {
    decrypt_chunk(inbuf, outbuf, chunk_no);
    chunk_no++;
    if(hdr_version == 2 && (v2header.datasize-ftell(out)) < CHUNK_SIZE) {
      fwrite(outbuf, v2header.datasize - ftell(out), 1, out);
      break;
    }
    fwrite(outbuf, CHUNK_SIZE, 1, out);
  }
  
  if (verbose)  fprintf(stderr, "%d chunks written\n", chunk_no);
  return(0);
}
