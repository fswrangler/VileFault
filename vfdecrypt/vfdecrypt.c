/*
 * Copyright (c) 2006 
 * Ralf-Philipp Weinmann <ralf@coderpunks.org>
 * Jacob Appelbaum <jacob@appelbaum.net>
 * Christian Fromme <kaner@strace.org>
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
#include <unistd.h>

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "vfdecrypt.h"
#include "util.h"

HMAC_CTX hmacsha1_ctx;
AES_KEY aes_decrypt_key;

static int CHUNK_SIZE = DEFAULT_CHUNK_SIZE;

/**
 * Compute IV of current block as
 * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 */
void compute_iv(uint32_t chunk_no, uint8_t *iv)
{
  unsigned char mdResult[MD_LENGTH];
  unsigned int mdLen;
  
  chunk_no = ntohl(chunk_no);
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

/* DES3-EDE unwrap operation loosely based on to RFC 2630, section 12.6 
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
  for(i = 0; i < outlen; i++) {
    TEMP2[i] = TEMP1[outlen - i - 1];
  }
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
  return(0);
}

int unwrap_v1_header(char *passphrase, cencrypted_v1_header *header, uint8_t *aes_key, uint8_t *hmacsha1_key)
{
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

int unwrap_v2_header(char *passphrase, cencrypted_v2_pwheader *header, uint8_t *aes_key, uint8_t *hmacsha1_key)
{
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];
  EVP_CIPHER_CTX ctx;
  uint8_t *TEMP1;
  int outlen, tmplen;

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char*)header->kdf_salt, 20,
			 PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  print_hex(stderr, derived_key, 192/8);

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

int usage(char *message)
{
  fprintf(stderr, "%s\n", message);
  fprintf(stderr, "Usage: vfdecrypt -i in-file [-p password | -k aeskey [-m hmacsha1key | -n ]] -o out-file\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  FILE *in, *out;
  cencrypted_v1_header v1header;
  cencrypted_v2_pwheader v2header;
  char hmacsha1_key_str[20*2+1];
  char aes_key_str[16*2+1];
  uint8_t hmacsha1_key[20];
  uint8_t aes_key[16];
  uint8_t inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE];
  uint32_t chunk_no;
  int hdr_version;
  
  /* getopts */
  int c;
  int optError;
  char inFile[512] = "";
  char outFile[512] = "";
  char passphrase[512];
  int kflag = 0, iflag = 0, oflag = 0, pflag = 0, mflag = 0;
  int verbose = 0;
  extern char *optarg;
  extern int optind, optopt;

  memset(hmacsha1_key_str, '0', sizeof(hmacsha1_key_str)-1);
  hmacsha1_key_str[sizeof(hmacsha1_key_str)-1] = '\0';

  optError = 0;
  while((c = getopt(argc, argv, "hvi:o::p::k::m::")) != -1){
    switch(c) {
    case 'h':      
      usage("Help is on the way. Stay calm.");
      break;
    case 'v':      
      verbose = verbose + 1;
      break;
    case 'i':
      if(optarg) {
	strncpy(inFile, optarg, sizeof(inFile)-1);
      } 
      iflag = 1;
      break;
    case 'o':
      if (optarg) {
	strncpy(outFile, optarg, sizeof(outFile)-1);
      }
      oflag = 1;
      break;
    case 'p':
      if (optarg) {
	strncpy(passphrase, optarg, sizeof(passphrase)-1);
      }
      pflag = 1;
      break;
    case 'k':
      if (optarg) {
	if (strlen(optarg) == 2*(16+20)) {
	  strncpy(aes_key_str, optarg, sizeof(aes_key_str));
	  aes_key_str[sizeof(aes_key_str)-1] = '\0';
	  strncpy(hmacsha1_key_str, optarg+(2*16), sizeof(hmacsha1_key_str));
	  hmacsha1_key_str[sizeof(hmacsha1_key_str)-1] = '\0';
	  mflag = 1;
	} else if(strlen(optarg) == 2*16) {
	  strncpy(aes_key_str, optarg, sizeof(aes_key_str));
	  aes_key_str[sizeof(aes_key_str)-1] = '\0';
	} else {
	  usage("you should either specify a aeskey||hmacsha1key or simply aeskey");
	  optError++;
	}
      }
      kflag = 1;
      break;
    case 'm':
      if (mflag) {
	usage("hmacsha1 key has already been specified!");
	optError++;
      }
      if (optarg && strlen(optarg) == 2*20) {
	strncpy(hmacsha1_key_str, optarg, sizeof(hmacsha1_key_str));
	hmacsha1_key_str[sizeof(hmacsha1_key_str)-1] = '\0';
      } else {
        usage("Perhaps you'd like to give us 40 hex bytes of the HMACSHA1 key?");
	optError++;
      }
      mflag = 1;
      break;
    case '?':
      fprintf(stderr, "Unknown option: -%c\n", optopt);
      optError++;
      break;
    }
  }

  /* check to see if our user gave incorrect options */
  if (optError) {
    usage("Incorrect arguments.");
  }

  if (strlen(inFile) == 0) {
    in = stdin; 
  } else {
    if ((in = fopen(inFile, "rb")) == NULL) {
      fprintf(stderr, "Error: unable to open %s\n", inFile);
      exit(1);
    }
  }

  if (strlen(outFile) == 0) {
    out = stdout;
  } else {
    if ((out = fopen(outFile, "wb")) == NULL) {
      fprintf(stderr, "Error: unable to open %s\n", outFile);
      exit(1);
    }
  }

  /* Obviously change this if we implement brute force methods inside vfdecrypt */
  if (!kflag && !pflag) {
    fprintf(stderr, "Neither a passphrase nor a valid key/hmac combo were given.\n");
    exit(1);
  }

  if (kflag && !mflag) {
    fprintf(stderr, "Setting HMAC-SHA1 key to all zeros!\n");
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
    if (verbose >= 1) {
      dump_v2_header(&v2header);
    }
    if(!kflag) unwrap_v2_header(passphrase, &v2header, aes_key, hmacsha1_key);
    CHUNK_SIZE = v2header.blocksize;
  }

  if (kflag) {
    convert_hex(aes_key_str, aes_key, 16);
    convert_hex(hmacsha1_key_str, hmacsha1_key, 20);
  }
  
  HMAC_CTX_init(&hmacsha1_ctx);
  HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key, sizeof(hmacsha1_key), EVP_sha1(), NULL);
  AES_set_decrypt_key(aes_key, CIPHER_KEY_LENGTH * 8, &aes_decrypt_key);

  if (verbose >= 1) {
    fprintf(stderr, "aeskey:\n");
    print_hex(stderr, aes_key, 16);
  }
  if (verbose >= 1) {
    fprintf(stderr, "hmacsha1key:\n");
    print_hex(stderr, hmacsha1_key, 20);
  }
  if (hdr_version == 2) {
    if (verbose >= 1) {
      fprintf(stderr, "data offset : %llu\n", v2header.dataoffset);
      fprintf(stderr, "data size   : %llu\n", v2header.datasize);
    }
    fseek(in, v2header.dataoffset, SEEK_SET);
  } else  {
    fseek(in, 0L, SEEK_SET);
  }

  chunk_no = 0;
  while(fread(inbuf, CHUNK_SIZE, 1, in) > 0) {
    decrypt_chunk(inbuf, outbuf, chunk_no);
    chunk_no++;
    // fix for last chunk
    if(hdr_version == 2 && (v2header.datasize-ftell(out)) < CHUNK_SIZE) {
      fwrite(outbuf, v2header.datasize - ftell(out), 1, out);
      break;
    }
    fwrite(outbuf, CHUNK_SIZE, 1, out);
  }
  if (verbose >= 1) {
    fprintf(stderr, "%d chunks written\n", chunk_no);
  }
  fclose(in);
  fclose(out);
  return(0);
}

