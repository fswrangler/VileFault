#ifndef _FVDECRYPT_H

#define _FVDECRYPT_H		1

#define OSSwapHostToBigInt32(x) ntohl(x)

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH		20
/* length of cipher key in bytes (128 bits) */
#define CIPHER_KEY_LENGTH	16
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE	16
/* number of iterations for PBKDF2 key derivation */
#define PBKDF2_ITERATION_COUNT	1000

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

typedef struct {
  unsigned char sig[8];
  uint32_t version;
  uint32_t enc_iv_size;
  uint32_t unk1;
  uint32_t unk2;
  uint32_t unk3;
  uint32_t unk4;
  uint32_t unk5;
  unsigned char uuid[16];
  uint32_t blocksize;
  uint64_t datasize;
  uint64_t dataoffset;
  uint8_t filler1[0x260];
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
  uint32_t encrypted_keyblob_size;
  uint8_t  encrypted_keyblob[0x30];
} cencrypted_v2_pwheader;
#endif
