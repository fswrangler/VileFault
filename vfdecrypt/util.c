#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

void print_hex(FILE *outstream, uint8_t *data, uint32_t len)
{
  uint32_t ctr;
  char *sep;

  if (len > 64) {
    len = 64;
  }

  for(ctr = 0; ctr < len; ctr++) {
    sep = (((ctr&7)==0)&&ctr) ? "\n" : "";
    fprintf(outstream, "%s%02x ", sep, data[ctr]);
  }
  fprintf(outstream, "\n\n");
}

void convert_hex(char *str, uint8_t *bytes, int maxlen)
{
  int slen = strlen(str);
  int bytelen = (slen+1)/2;
  int rpos, wpos = 0;

  while(wpos < maxlen - bytelen) bytes[wpos++] = 0;

  for(rpos = 0; rpos < bytelen; rpos++) {
    sscanf(&str[rpos*2], "%02hhx", &bytes[wpos++]);
  }
}

void dump_v2_header(void *hdr)
{
  cencrypted_v2_pwheader *pwhdr = (cencrypted_v2_pwheader *) hdr;

  /* 103: CSSM_ALGID_PKCS5_PBKDF2 */
  fprintf(stderr, "keyDerivationAlgorithm      %lu\n", (unsigned long) pwhdr->kdf_algorithm);
  fprintf(stderr, "keyDerivationPRNGAlgorithm  %lu\n", (unsigned long) pwhdr->kdf_prng_algorithm);
  /* by default the iteration count should be 1000 iterations */
  fprintf(stderr, "keyDerivationIterationCount %lu\n", (unsigned long) pwhdr->kdf_iteration_count);
  fprintf(stderr, "keyDerivationSaltSize       %lu\n", (unsigned long) pwhdr->kdf_salt_len);
  fprintf(stderr, "keyDerivationSalt           \n");
  print_hex(stderr, pwhdr->kdf_salt, pwhdr->kdf_salt_len);
  fprintf(stderr, "blobEncryptionIVSize        %lu\n", (unsigned long) pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionIV            \n");
  print_hex(stderr, pwhdr->blob_enc_iv, pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionKeySizeInBits %lu\n",  (unsigned long) pwhdr->blob_enc_key_bits);
  /*  17: CSSM_ALGID_3DES_3KEY_EDE */
  fprintf(stderr, "blobEncryptionAlgorithm     %lu\n",  (unsigned long) pwhdr->blob_enc_algorithm);
  /*   7: CSSM_PADDING_PKCS7 */
  fprintf(stderr, "blobEncryptionPadding       %lu\n",  (unsigned long) pwhdr->blob_enc_padding);
  /*   6: CSSM_ALGMODE_CBCPadIV8 */
  fprintf(stderr, "blobEncryptionMode          %lu\n",  (unsigned long)  pwhdr->blob_enc_mode);
  fprintf(stderr, "encryptedBlobSize           %lu\n",  (unsigned long)  pwhdr->encrypted_keyblob_size);
  fprintf(stderr, "encryptedBlob               \n");
  print_hex(stderr, pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size);
}

void adjust_v1_header_byteorder(cencrypted_v1_header *hdr) {
  hdr->kdf_iteration_count = ntohl(hdr->kdf_iteration_count);
  hdr->kdf_salt_len = ntohl(hdr->kdf_salt_len);
  hdr->len_wrapped_aes_key = ntohl(hdr->len_wrapped_aes_key);
  hdr->len_hmac_sha1_key = ntohl(hdr->len_hmac_sha1_key);
  hdr->len_integrity_key = ntohl(hdr->len_integrity_key);
}

void adjust_v2_header_byteorder(cencrypted_v2_pwheader *pwhdr) {
  pwhdr->blocksize = ntohl(pwhdr->blocksize);
  pwhdr->datasize = ntohll(pwhdr->datasize);
  pwhdr->dataoffset = ntohll(pwhdr->dataoffset);
  pwhdr->kdf_algorithm = ntohl(pwhdr->kdf_algorithm);
  pwhdr->kdf_prng_algorithm = ntohl(pwhdr->kdf_prng_algorithm);
  pwhdr->kdf_iteration_count = ntohl(pwhdr->kdf_iteration_count);
  pwhdr->kdf_salt_len = ntohl(pwhdr->kdf_salt_len);
  pwhdr->blob_enc_iv_size = ntohl(pwhdr->blob_enc_iv_size);
  pwhdr->blob_enc_key_bits = ntohl(pwhdr->blob_enc_key_bits);
  pwhdr->blob_enc_algorithm = ntohl(pwhdr->blob_enc_algorithm);
  pwhdr->blob_enc_padding = ntohl(pwhdr->blob_enc_padding);
  pwhdr->blob_enc_mode = ntohl(pwhdr->blob_enc_mode);
  pwhdr->encrypted_keyblob_size = ntohl(pwhdr->encrypted_keyblob_size);
}
