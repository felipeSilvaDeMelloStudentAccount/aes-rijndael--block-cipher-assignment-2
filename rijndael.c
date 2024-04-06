/*
 * Felipe Silva de Mello
 * D23125661
 * 
 * Implementation of AES(Rijndael) encryption and decryption functions
 */

#include <stdlib.h>
#include "rijndael.h"


// Define the S-box to lookup and perform the swaps operations during the encryption and decryption process
// Each byte in the block will be replaced by the corresponding byte in the S-box table 
static const unsigned char S_BOX[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B
    // C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
    0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2,
    0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5,
    0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80,
    0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
};


/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
    for(int i=0; i<BLOCK_SIZE; i++){
        block[i] = S_BOX[block[i]];
    }

}

void shift_rows(unsigned char *block) {
    unsigned char temp;

    // Row 1 doesn't shift (i.e., row 0 in 0-indexed)

    // Row 2 
    //shifts 1 to the left
    temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Row 3 
    // shifts 2 to the left
    temp = block[2];
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];
    block[6] = block[14];
    block[14] = temp;

    // Row 4 
    // shifts 3 to the left (or one to the right)
    temp = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = temp;
}

void mix_columns(unsigned char *block) {
      unsigned char tmp, tm, t;
    for (int i = 0; i < 4; ++i) {
        t = block[i*4];
        tmp = block[i*4] ^ block[i*4+1] ^ block[i*4+2] ^ block[i*4+3] ;
        tm = block[i*4] ^ block[i*4+1]; tm = XTIME(tm);  block[i*4] ^= tm ^ tmp;
        tm = block[i*4+1] ^ block[i*4+2]; tm = XTIME(tm);  block[i*4+1] ^= tm ^ tmp;
        tm = block[i*4+2] ^ block[i*4+3]; tm = XTIME(tm);  block[i*4+2] ^= tm ^ tmp;
        tm = block[i*4+3] ^ t; tm = XTIME(tm);  block[i*4+3] ^= tm ^ tmp;
    }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // TODO: Implement me!
}

void invert_shift_rows(unsigned char *block) {
  // TODO: Implement me!
}

void invert_mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  // TODO: Implement me!
  return 0;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}
