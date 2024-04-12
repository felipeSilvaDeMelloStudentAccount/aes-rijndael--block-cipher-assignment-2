/*
 * Felipe Silva de Mello
 * D23125661
 *
 * Implementation of AES(Rijndael) encryption and decryption functions
 */

#include "rijndael.h"

#include <stdlib.h>
#include <string.h>

static const unsigned char S_BOX[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C
    // D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F
};

static const unsigned char INV_S_BOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
};

static const unsigned char ROUND_CONSTANT[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

/**
 * Perform multiplication in GF(2^8)
 * @param polynomial_a         The first byte to be multiplied
 * @param polynomial_b         The second byte to be multiplied
 * @return                     The result of the multiplication
 */
static unsigned char MULTIPLY(unsigned char polynomial_a,
                              unsigned char polynomial_b) {
  unsigned char multiplication_result =
      0;  // Result of the finite field multiplication
  // Iterate until polynomial_b becomes 0
  while (polynomial_b) {
    // If the least significant bit of polynomial_b is 1, XOR the
    // multiplication_result with polynomial_a
    if (polynomial_b & 0x01) multiplication_result ^= polynomial_a;
    // If the most significant bit of polynomial_a is 1, left shift polynomial_a
    // and XOR with 0x1B (irreducible polynomial)
    if (polynomial_a & 0x80)
      polynomial_a = (polynomial_a << 1) ^ 0x1B;
    else
      // Otherwise, just left shift polynomial_a
      polynomial_a <<= 1;
    // Right shift polynomial_b to process the next bit
    polynomial_b >>= 1;
  }
  return multiplication_result;
}

void aes_cypher_ops(unsigned char *encrypted_block, unsigned char *expanded_key,
                    int *init_expanded_key, int *block_size);

void final_aes_operation(int init_expanded_key, int block_size,
                         unsigned char *encrypted_block,
                         unsigned char *expanded_key);

void aes_decypher_ops(unsigned char *decrypt_block, unsigned char *key_expanded,
                      int *init_expanded_key, int *expanded_key_length);

/**
 * Substitutes each byte in the block with the corresponding value from the
 * S-Box.
 * @param block     The block to be transformed.
 * @param size    The size of the block.
 */
void sub_bytes(unsigned char *block, int size) {
  for (int i = 0; i < size; i++) {
    block[i] = S_BOX[block[i]];
  }
}

/**
 * Shifts the rows of the state block to the left.
 * @param block     The block to be transformed.
 */
void shift_rows(unsigned char *block) {
  unsigned char temp_byte_for_shift;
  // Row 0 doesn't shift (i.e., row 0 in 0-indexed)

  // Row 1 - Shifts 1 to the left
  temp_byte_for_shift = block[1];
  block[1] = block[5];
  block[5] = block[9];
  block[9] = block[13];
  block[13] = temp_byte_for_shift;

  // Row 2 - Shifts 2 to the left
  temp_byte_for_shift = block[2];
  block[2] = block[10];
  block[10] = temp_byte_for_shift;
  temp_byte_for_shift = block[6];
  block[6] = block[14];
  block[14] = temp_byte_for_shift;

  // Row 3 - Shifts 3 to the left (or one to the right)
  temp_byte_for_shift = block[15];
  block[15] = block[11];
  block[11] = block[7];
  block[7] = block[3];
  block[3] = temp_byte_for_shift;
}

/**
 * Perform MixColumns operation on the state block
 *
 * @param block The block to be mixed
 */
void mix_columns(unsigned char *block) {
  // Temporary array to store the new block
  unsigned char temp_column[BLOCK_SIZE];
  // Loop through each column
  for (int col = 0; col < 4; ++col) {
    // Extract the col from the block
    temp_column[4 * col + 0] = MULTIPLY(0x02, block[4 * col + 0]) ^
                               MULTIPLY(0x03, block[4 * col + 1]) ^
                               block[4 * col + 2] ^ block[4 * col + 3];
    temp_column[4 * col + 1] =
        block[4 * col + 0] ^ MULTIPLY(0x02, block[4 * col + 1]) ^
        MULTIPLY(0x03, block[4 * col + 2]) ^ block[4 * col + 3];
    temp_column[4 * col + 2] = block[4 * col + 0] ^ block[4 * col + 1] ^
                               MULTIPLY(0x02, block[4 * col + 2]) ^
                               MULTIPLY(0x03, block[4 * col + 3]);
    temp_column[4 * col + 3] = MULTIPLY(0x03, block[4 * col + 0]) ^
                               block[4 * col + 1] ^ block[4 * col + 2] ^
                               MULTIPLY(0x02, block[4 * col + 3]);
  }
  // Write the mixed column back into the block
  for (int row = 0; row < BLOCK_SIZE; ++row) {
    block[row] = temp_column[row];
  }
}

/*
 * Operations used when decrypting a block
 *
 * @param block         The block to be transformed.
 * @param length        The length of the block.
 */
void invert_sub_bytes(unsigned char *block, int length) {
  for (int index = 0; index < length; index++) {
    // Replace each byte with its corresponding value from the inverse S-Box
    block[index] = INV_S_BOX[block[index]];
  }
}

/**
 * The function applies the inverse shift rows transformation
 *
 * @param block         The block to be transformed.
 */
void invert_shift_rows(unsigned char *block) {
  unsigned char temp_byte_for_shift;

  // Invert shift for row 1 (shift right by 1)
  temp_byte_for_shift = block[13];
  block[13] = block[9];
  block[9] = block[5];
  block[5] = block[1];
  block[1] = temp_byte_for_shift;

  // Invert shift for row 2 (shift right by 2)
  temp_byte_for_shift = block[10];
  block[10] = block[2];
  block[2] = temp_byte_for_shift;
  temp_byte_for_shift = block[14];
  block[14] = block[6];
  block[6] = temp_byte_for_shift;

  // Invert shift for row 3 (shift right by 3, equivalent to shifting left by 1)
  temp_byte_for_shift = block[3];
  block[3] = block[7];
  block[7] = block[11];
  block[11] = block[15];
  block[15] = temp_byte_for_shift;
}

/**
 * Performs the inverse MixColumns operation on a state block.
 * The function applies the inverse MixColumns transformation
 * as specified in the AES encryption standard. It operates on
 * each column of the state, transforming it using a fixed matrix.
 *
 * @param block A pointer to the 16-byte block to be transformed.
 */
void invert_mix_columns(unsigned char *block) {
  unsigned char temp[BLOCK_SIZE];
  int block_rows = BLOCK_ROWS;
  // Iterate over each column
  for (int col = 0; col < 4; ++col) {
    temp[4 * col + 0] = MULTIPLY(0x0e, block[block_rows * col + 0]) ^
                        MULTIPLY(0x0b, block[block_rows * col + 1]) ^
                        MULTIPLY(0x0d, block[block_rows * col + 2]) ^
                        MULTIPLY(0x09, block[block_rows * col + 3]);
    temp[block_rows * col + 1] = MULTIPLY(0x09, block[block_rows * col + 0]) ^
                                 MULTIPLY(0x0e, block[block_rows * col + 1]) ^
                                 MULTIPLY(0x0b, block[block_rows * col + 2]) ^
                                 MULTIPLY(0x0d, block[block_rows * col + 3]);
    temp[block_rows * col + 2] = MULTIPLY(0x0d, block[block_rows * col + 0]) ^
                                 MULTIPLY(0x09, block[block_rows * col + 1]) ^
                                 MULTIPLY(0x0e, block[block_rows * col + 2]) ^
                                 MULTIPLY(0x0b, block[block_rows * col + 3]);
    temp[block_rows * col + 3] = MULTIPLY(0x0b, block[block_rows * col + 0]) ^
                                 MULTIPLY(0x0d, block[block_rows * col + 1]) ^
                                 MULTIPLY(0x09, block[block_rows * col + 2]) ^
                                 MULTIPLY(0x0e, block[block_rows * col + 3]);
  }

  for (int i = 0; i < BLOCK_SIZE; ++i) {
    block[i] = temp[i];
  }
}

/*
 * This operation is shared between encryption and decryption
 *
 * XORs the AES block with the round key.
 * Both the block and the round_key are 128 bits,
 * represented here as arrays of 16 bytes.
 *
 * @param block     The block to be XORed
 * @param round_key The round key to XOR with the block
 * @param start     The start index of the round key
 * @param end       The end index of the round key
 */
void add_round_key(unsigned char *block, unsigned char *round_key, int start,
                   int end) {
  int key = 0;
  for (int byte_index = start; byte_index < end; byte_index++) {
    block[key] ^= round_key[byte_index];
    key++;
  }
}

/**
 * Expands the given cipher key to generate 11 round keys.
 * The function takes a 128-bit cipher key and expands it
 * to generate 11 round keys, each of which is 128 bits long.
 * The round keys are stored in a single array of 176 bytes.
 * The first 16 bytes are the original key, and the remaining
 * 160 bytes are the 11 round keys.
 * The key expansion process involves circular shifts, S-Box
 * substitutions, and XOR operations with round constants.
 * The round constants are used to introduce non-linearity into
 * the key expansion process.
 * @param cipher_key        The 128-bit cipher key to be expanded.
 * @return                  A pointer to the expanded key.
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  // Allocate memory for the expanded key
  unsigned char *expanded_key = (unsigned char *)malloc(BLOCK_SIZE * 11);

  int first_row = 0;
  int last_row = 3;
  // Index to the round constant
  int round_index = 1;
  int block_size = BLOCK_SIZE;
  int block_rows = BLOCK_ROWS;

  // Iterating 11 times to expand the keys
  for (int first_loop = 0; first_loop < 11; first_loop++) {
    // Copying all key to expand_key array
    if (first_loop == 0) {
      for (int i = 0; i < BLOCK_SIZE; i++) expanded_key[i] = cipher_key[i];
    } else {
      char rotate[4] = {BLOCK_ACCESS(expanded_key, last_row, 1),
                        BLOCK_ACCESS(expanded_key, last_row, 2),
                        BLOCK_ACCESS(expanded_key, last_row, 3),
                        BLOCK_ACCESS(expanded_key, last_row, 0)};
      sub_bytes(rotate, block_rows);
      for (int innerLoop = 0; innerLoop < block_rows; innerLoop++) {
        // First first_row of the block
        if (innerLoop == 0) {
          // XOR with round constant and rotate   1 byte to left
          expanded_key[block_size] = BLOCK_ACCESS(expanded_key, first_row, 0) ^
                                     ROUND_CONSTANT[round_index++] ^ rotate[0];
          // XOR with previous first_row  1 byte to left
          expanded_key[block_size + 1] =
              BLOCK_ACCESS(expanded_key, first_row, 1) ^ rotate[1];
          // XOR with previous first_row    2 byte to left
          expanded_key[block_size + 2] =
              BLOCK_ACCESS(expanded_key, first_row, 2) ^ rotate[2];
          // XOR with previous first_row    3 byte to left
          expanded_key[block_size + 3] =
              BLOCK_ACCESS(expanded_key, first_row, 3) ^ rotate[3];
          // Incrementing the block index and first_row
          first_row += 1;
          block_size += block_rows;
        } else {
          // XOR with previous first_row and previous block
          expanded_key[block_size] = BLOCK_ACCESS(expanded_key, first_row, 0) ^
                                     expanded_key[block_size - block_rows];
          // XOR with previous first_row  1 byte to left
          expanded_key[block_size + 1] =
              BLOCK_ACCESS(expanded_key, first_row, 1) ^
              expanded_key[block_size - 3];
          // XOR with previous first_row  2 byte to left
          expanded_key[block_size + 2] =
              BLOCK_ACCESS(expanded_key, first_row, 2) ^
              expanded_key[block_size - 2];
          // XOR with previous first_row  3 byte to left
          expanded_key[block_size + 3] =
              BLOCK_ACCESS(expanded_key, first_row, 3) ^
              expanded_key[block_size - 1];

          // Incrementing the block index
          block_size += block_rows;
          // Incrementing the first_row
          first_row += 1;
        }
      }
      // Reset the first_row and last_row
      last_row += block_rows;
    }
  }
  return expanded_key;
}

/**
 * Perform the final AES operation Helper Method
 * @param init_expanded_key     The initial expanded key
 * @param block_size            The block size
 * @param encrypted_block       The block to be encrypted
 * @param expanded_key          The expanded key
 */
void final_aes_operation(int init_expanded_key, int block_size,
                         unsigned char *encrypted_block,
                         unsigned char *expanded_key) {
  sub_bytes(encrypted_block, BLOCK_SIZE);
  shift_rows(encrypted_block);
  init_expanded_key += BLOCK_SIZE;
  block_size += BLOCK_SIZE;
  add_round_key(encrypted_block, expanded_key, init_expanded_key, block_size);
}

/**
 * Perform AES operations Helper Method
 *
 * @param encrypted_block       The block to be encrypted
 * @param expanded_key          The expanded key
 * @param init_expanded_key     The initial expanded key
 * @param block_size            The block size
 */
void aes_cypher_ops(unsigned char *encrypted_block, unsigned char *expanded_key,
                    int *init_expanded_key,
                    int *block_size) {  // Perform AES operations
  sub_bytes(encrypted_block, BLOCK_SIZE);
  shift_rows(encrypted_block);
  mix_columns(encrypted_block);

  // Update the expanded key index
  (*init_expanded_key) += BLOCK_SIZE;
  // Update the block size
  (*block_size) += BLOCK_SIZE;
  // Add the round key    to the block of data    using the expanded key  and
  // the block size  and the initial expanded key
  add_round_key(encrypted_block, expanded_key, (*init_expanded_key),
                (*block_size));
}

/**
 * Encrypts a single block of plaintext using AES encryption algorithm.
 * The function takes a 128-bit plaintext block and a 128-bit key
 * and encrypts the plaintext using the key. The function performs
 * AES encryption on the plaintext block using the key and returns
 * the encrypted block.
 * @param plaintext     The plaintext block to be encrypted.
 * @param key           The encryption key.
 * @return              The encrypted block.
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  int init_expanded_key = 0;
  int block_size = BLOCK_SIZE;
  // Allocate memory for the encrypted block of data
  unsigned char *encrypted_block =
      (unsigned char *)malloc(sizeof(unsigned char) * block_size);

  unsigned char *expanded_key = expand_key(key);

  // Copy the plaintext to the encrypted block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    encrypted_block[i] = plaintext[i];
  }
  // Add the initial round key to the block of data
  add_round_key(encrypted_block, key, init_expanded_key, block_size);

  // Perform AES operations for 10 rounds
  for (int i = 1; i < NUMBER_OF_ROUNDS; i++) {
    aes_cypher_ops(encrypted_block, expanded_key, &init_expanded_key,
                   &block_size);
  }
  // Perform the final round of AES operations
  final_aes_operation(init_expanded_key, block_size, encrypted_block,
                      expanded_key);

  return encrypted_block;  // Return the encrypted block
}

void aes_decypher_ops(
    unsigned char *decrypt_block, unsigned char *key_expanded,
    int *init_expanded_key,
    int *expanded_key_length) {  // Update key index range for the current round
                                 // starting from the last to first
  (*init_expanded_key) -= BLOCK_SIZE;
  (*expanded_key_length) -= BLOCK_SIZE;

  // Add the round key
  add_round_key(decrypt_block, key_expanded, (*init_expanded_key),
                (*expanded_key_length));

  // Perform inverse MixColumns, ShiftRows, and SubBytes operations
  invert_mix_columns(decrypt_block);
  invert_shift_rows(decrypt_block);
  invert_sub_bytes(decrypt_block, BLOCK_SIZE);
}

/**
 * Decrypts a single block of ciphertext using AES decryption algorithm.
 * The function takes a 128-bit ciphertext block and a 128-bit key
 * and decrypts the ciphertext using the key. The function performs
 * AES decryption on the ciphertext block using the key and returns
 * the decrypted block.
 * @param ciphertext    The ciphertext block to be decrypted.
 * @param key           The decryption key.
 * @return              The decrypted block.
 */
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  int init_expanded_key = 160;
  int expanded_key_length = EXPANDED_KEY_LENGTH;

  unsigned char *decrypt_block =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  // Copy ciphertext to decrypt_block block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    decrypt_block[i] = ciphertext[i];
  }

  unsigned char *key_expanded = expand_key(key);

  // Add the initial round key
  add_round_key(decrypt_block, key_expanded, init_expanded_key,
                expanded_key_length);

  // Perform inverse ShiftRows and SubBytes operations
  invert_shift_rows(decrypt_block);
  invert_sub_bytes(decrypt_block, BLOCK_SIZE);

  // iterating 10 time as this is 128 bit
  for (int i = NUMBER_OF_ROUNDS; i > 1; i--) {
    aes_decypher_ops(decrypt_block, key_expanded, &init_expanded_key,
                     &expanded_key_length);
  }

  // Update key index range for the final round
  init_expanded_key -= BLOCK_SIZE;
  expanded_key_length -= BLOCK_SIZE;

  // Add the final round key
  add_round_key(decrypt_block, key_expanded, init_expanded_key,
                expanded_key_length);

  return decrypt_block;  // Return the decrypted block
}
