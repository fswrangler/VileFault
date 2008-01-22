/*
 * Copyright (c) 2006 - David Hulton <dhulton@openciphers.org>
 * see LICENSE for details
 */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH		20
/* length of cipher key in bytes (128 bits) */
#define CIPHER_KEY_LENGTH	16
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE	16
/* chunk size (FileVault specific) */
#define CHUNK_SIZE		4096
/* number of iterations for PBKDF2 key derivation */
#define PBKDF2_ITERATION_COUNT	1000

HMAC_CTX hmacsha1_ctx;
AES_KEY aes_decrypt_key;

typedef struct {
  /* 0x000: */ uint8_t  filler1[48];
  /* 0x034: */ uint32_t kdf_iteration_count;
  /* 0x034: */ uint32_t kdf_salt_len;
  /* 0x038: */ uint8_t  kdf_salt[48]; /* salt value for key derivation */
  /* 0x068: */ uint8_t  unwrap_iv[32]; /* IV for encryption-key unwrapping */
  /* 0x088: */ uint32_t len_wrapped_aes_key;
  /* 0x08c: */ uint8_t  wrapped_aes_key[296];
  /* 0x1b4: */ uint32_t len_hmac_sha1_key;
  /* 0x1b8: */ uint8_t  wrapped_hmac_sha1_key[300];
  /* 0x1b4: */ uint32_t len_integrity_key;
  /* 0x2e8: */ uint8_t  wrapped_integrity_key[48];
  /* 0x318: */ uint8_t  filler6[484];
} cencrypted_v1_header;

/* this structure is valid only if there's a recovery key defined */
typedef struct {
  uint8_t filler1[0x2a8];
  uint32_t kdf_algorithm;
  uint32_t kdf_prng_algorithm;
  uint32_t kdf_iteration_count;
  uint32_t kdf_salt_len; /* in bytes */
  uint8_t  kdf_salt[32];
  uint32_t blob_enc_iv_size;
  uint8_t  blob_enc_iv[32];
  uint32_t blob_enc_key_bits;
  uint32_t blob_enc_algorithm;
  uint32_t blob_enc_padding;
  uint32_t blob_enc_mode;
  uint32_t encrypted_blob_size;
  uint8_t  encrypted_blob[0x30];
} cencrypted_v2_pwheader;

void initfpga(void);
void addreg(SHA1_CACHE *, unsigned char *, char *);
void finishreg(void);
