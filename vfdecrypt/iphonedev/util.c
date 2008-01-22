#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

void print_hex(uint8_t *data, uint32_t len) {
  uint32_t ctr;
  char *sep;

  if (len > 64) len = 64;

  for(ctr = 0; ctr < len; ctr++) {
    sep = (((ctr&7)==0)&&ctr) ? "\n" : "";
    fprintf(stderr, "%s%02x ", sep, data[ctr]);
  }
  fprintf(stderr, "\n\n");
}

void convert_hex(char *str, uint8_t *bytes, int maxlen) {
  int slen = strlen(str);
  int bytelen = maxlen;
  int rpos, wpos = 0;

  for(rpos = 0; rpos < bytelen; rpos++) {
    sscanf(&str[rpos*2], "%02hhx", &bytes[wpos++]);
  }
}

void dump_v2_header(void *hdr) {
  cencrypted_v2_pwheader *pwhdr = (cencrypted_v2_pwheader *) hdr;

  fprintf(stderr, "sig\t%8s\n", pwhdr->sig);
  fprintf(stderr, "blocksize\t%lu\n", pwhdr->blocksize);
  fprintf(stderr, "datasize\t%llu\n", pwhdr->datasize);
  fprintf(stderr, "dataoffset\t%llu\n", pwhdr->dataoffset);

  /* 103: CSSM_ALGID_PKCS5_PBKDF2 */
  fprintf(stderr, "keyDerivationAlgorithm      %lu\n", (unsigned long) pwhdr->kdf_algorithm);
  fprintf(stderr, "keyDerivationPRNGAlgorithm  %lu\n", (unsigned long) pwhdr->kdf_prng_algorithm);
  /* by default the iteration count should be 1000 iterations */
  fprintf(stderr, "keyDerivationIterationCount %lu\n", (unsigned long) pwhdr->kdf_iteration_count);
  fprintf(stderr, "keyDerivationSaltSize       %lu\n", (unsigned long) pwhdr->kdf_salt_len);
  fprintf(stderr, "keyDerivationSalt           \n");
  print_hex(pwhdr->kdf_salt, pwhdr->kdf_salt_len);
  fprintf(stderr, "blobEncryptionIVSize        %lu\n", (unsigned long) pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionIV            \n");
  print_hex(pwhdr->blob_enc_iv, pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionKeySizeInBits %lu\n",  (unsigned long) pwhdr->blob_enc_key_bits);
  /*  17: CSSM_ALGID_3DES_3KEY_EDE */
  fprintf(stderr, "blobEncryptionAlgorithm     %lu\n",  (unsigned long) pwhdr->blob_enc_algorithm);
  /*   7: CSSM_PADDING_PKCS7 */
  fprintf(stderr, "blobEncryptionPadding       %lu\n",  (unsigned long) pwhdr->blob_enc_padding);
  /*   6: CSSM_ALGMODE_CBCPadIV8 */
  fprintf(stderr, "blobEncryptionMode          %lu\n",  (unsigned long)  pwhdr->blob_enc_mode);
  fprintf(stderr, "encryptedBlobSize           %lu\n",  (unsigned long)  pwhdr->encrypted_keyblob_size);
  fprintf(stderr, "encryptedBlob               \n");
  print_hex(pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size);
}

void adjust_v1_header_byteorder(cencrypted_v1_header *hdr) {
  hdr->kdf_iteration_count = htonl(hdr->kdf_iteration_count);
  hdr->kdf_salt_len = htonl(hdr->kdf_salt_len);
  hdr->len_wrapped_aes_key = htonl(hdr->len_wrapped_aes_key);
  hdr->len_hmac_sha1_key = htonl(hdr->len_hmac_sha1_key);
  hdr->len_integrity_key = htonl(hdr->len_integrity_key);
}

#define swap32(x) x = OSSwapHostToBigInt32(x)
#define swap64(x) x = ((uint64_t) ntohl(x >> 32)) | (((uint64_t) ntohl((uint32_t) (x & 0xFFFFFFFF))) << 32)

void adjust_v2_header_byteorder(cencrypted_v2_pwheader *pwhdr) {
  swap32(pwhdr->blocksize);
  swap64(pwhdr->datasize);
  swap64(pwhdr->dataoffset);
  pwhdr->kdf_algorithm = htonl(pwhdr->kdf_algorithm);
  pwhdr->kdf_prng_algorithm = htonl(pwhdr->kdf_prng_algorithm);
  pwhdr->kdf_iteration_count = htonl(pwhdr->kdf_iteration_count);
  pwhdr->kdf_salt_len = htonl(pwhdr->kdf_salt_len);
  pwhdr->blob_enc_iv_size = htonl(pwhdr->blob_enc_iv_size);
  pwhdr->blob_enc_key_bits = htonl(pwhdr->blob_enc_key_bits);
  pwhdr->blob_enc_algorithm = htonl(pwhdr->blob_enc_algorithm);
  pwhdr->blob_enc_padding = htonl(pwhdr->blob_enc_padding);
  pwhdr->blob_enc_mode = htonl(pwhdr->blob_enc_mode);
  pwhdr->encrypted_keyblob_size = htonl(pwhdr->encrypted_keyblob_size);
}
