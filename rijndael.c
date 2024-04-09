/*
 * Felipe Silva de Mello
 * D23125661
 * 
 * Implementation of AES(Rijndael) encryption and decryption functions
 */

#include <stdlib.h>
#include <string.h>
#include "rijndael.h"


// Define the S-box to lookup and perform the swaps operations during the encryption and decryption process
// Each byte in the block will be replaced by the corresponding byte in the S-box table 
static const unsigned char S_BOX[256] = {
        // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F
};
//   Inverse S-Box definition
static const unsigned char INV_S_BOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};


// Define the round constants for key expansion
static const unsigned char ROUND_CONSTANT[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Wrapper function for XTIME to be callable from Python ctypes
unsigned char xtime_wrapper(unsigned char x) {
    return XTIME(x);
}


/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
    // Iterate over each byte in the block
    for (size_t index = 0; index < BLOCK_SIZE; ++index) {
        // Replace each byte with its S-Box equivalent
        block[index] = S_BOX[block[index]];
    }
}

void shift_rows(unsigned char *block) {
    unsigned char tempByteForShift;

    // Row 0 doesn't shift (i.e., row 0 in 0-indexed)

    // Row 1 - Shifts 1 to the left
    tempByteForShift = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = tempByteForShift;

    // Row 2 - Shifts 2 to the left
    tempByteForShift = block[2];
    block[2] = block[10];
    block[10] = tempByteForShift;
    tempByteForShift = block[6];
    block[6] = block[14];
    block[14] = tempByteForShift;

    // Row 3 - Shifts 3 to the left (or one to the right)
    tempByteForShift = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = tempByteForShift;
}


/**
 * Perform the MixColumns operation on a single column of the state block.
 * @param column The column to be mixed.
 */
void mix_single_column(unsigned char *column) {
    // Calculate the XOR of all bytes in the column
    unsigned char columnXorResult = column[0] ^ column[1] ^ column[2] ^ column[3];
    unsigned char originalFirstByte = column[0];

    // Perform the mixing operation on each byte in the column
    column[0] ^= columnXorResult ^ XTIME(column[0] ^ column[1]);
    column[1] ^= columnXorResult ^ XTIME(column[1] ^ column[2]);
    column[2] ^= columnXorResult ^ XTIME(column[2] ^ column[3]);
    column[3] ^= columnXorResult ^ XTIME(column[3] ^ originalFirstByte);
}

/**
 * Perform the MixColumns operation on the state block.
 * @param block The block to be mixed.
 */
void mix_columns(unsigned char *block) {
    unsigned char column[4];
    for (int col = 0; col < 4; ++col) {
        // Extract the column from the block
        for (int row = 0; row < 4; ++row) {
            column[row] = BLOCK_ACCESS(block, row, col);
        }

        // Mix a single column
        mix_single_column(column);

        // Write the mixed column back into the block
        for (int row = 0; row < 4; ++row) {
            BLOCK_ACCESS(block, row, col) = column[row];
        }
    }
}


/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
    // Iterate over each byte in the block
    for (size_t index = 0; index < BLOCK_SIZE; ++index) {
        // Replace each byte with its corresponding value from the inverse S-Box
        block[index] = INV_S_BOX[block[index]];
    }
}


void invert_shift_rows(unsigned char *block) {
    unsigned char tempByteForShift;

    // Invert shift for row 1 (shift right by 1)
    tempByteForShift = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = tempByteForShift;

    // Invert shift for row 2 (shift right by 2)
    tempByteForShift = block[2];
    block[2] = block[10];
    block[10] = tempByteForShift;
    tempByteForShift = block[6];
    block[6] = block[14];
    block[14] = tempByteForShift;

    // Invert shift for row 3 (shift right by 3, equivalent to shifting left by 1)
    tempByteForShift = block[3];
    block[3] = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = tempByteForShift;
}


/**
 * Performs the inverse MixColumns operation on a state block.
 * The function applies the inverse MixColumns transformation
 * as specified in the AES encryption standard. It operates on
 * each column of the state, transforming it using a fixed matrix.
 *
 * @param block A pointer to the 16-byte block to be transformed.
 */
void inv_mix_columns(unsigned char *block) {
    // Iterate over each column
    for (int col = 0; col < 4; col++) {
        // Calculate intermediate values for the transformation
        // double_xor_first_third is the result of doubling the XOR of the first and third bytes in the column
        unsigned char double_xor_first_third =
                XTIME(XTIME(BLOCK_ACCESS(block, 0, col) ^ BLOCK_ACCESS(block, 2, col)));
        // double_xor_second_fourth is the result of doubling the XOR of the second and fourth bytes in the column
        unsigned char double_xor_second_fourth =
                XTIME(XTIME(BLOCK_ACCESS(block, 1, col) ^ BLOCK_ACCESS(block, 3, col)));

        // Apply the transformation to each byte in the column
        // XOR the first byte with the calculated value
        BLOCK_ACCESS(block, 0, col) ^= double_xor_first_third;
        // XOR the second byte with the calculated value
        BLOCK_ACCESS(block, 1, col) ^= double_xor_second_fourth;
        // XOR the third byte with the same value as the first byte
        BLOCK_ACCESS(block, 2, col) ^= double_xor_first_third;
        // XOR the fourth byte with the same value as the second byte
        BLOCK_ACCESS(block, 3, col) ^= double_xor_second_fourth;
    }

    // Call mix_columns as part of the inversion process
    // This is necessary to correctly apply the inverse mix columns transformation
    mix_columns(block);
}


/*
 * This operation is shared between encryption and decryption
 *
 * XORs the AES block with the round key.
 * Both the block and the round_key are 128 bits,
 * represented here as arrays of 16 bytes.
 *
 * @param block The current block of the AES encryption/decryption process.
 * @param round_key The round key to be combined with the block.
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
    for (size_t byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex) {
        // XOR each byte of the state with the corresponding byte of the round key
        block[byteIndex] ^= round_key[byteIndex];
    }
}


// Define the block size and the number of rounds
void applySBoxToWord(unsigned char *word) {
    for (int byteIndex = 0; byteIndex < WORD_LENGTH; ++byteIndex) {
        // Apply S-Box transformation to each byte of the word
        word[byteIndex] = S_BOX[word[byteIndex]]; // Assuming S_BOX is defined elsewhere
    }
}

// Rotate the bytes in a word one position to the left
void rotateWordLeft(unsigned char *word) {
    unsigned char firstByte = word[0]; // Store the first byte of the word
    for (int byteIndex = 0; byteIndex < WORD_LENGTH - 1; ++byteIndex) {
        // Shift each byte one position to the left
        word[byteIndex] = word[byteIndex + 1];
    }
    word[WORD_LENGTH - 1] = firstByte; // Move the first byte to the end of the word
}


/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
    // Allocate memory for the expanded key
    unsigned char *expandedKey = malloc(EXPANDED_KEY_LENGTH);
    if (!expandedKey) {
        return NULL; // Memory allocation failed
    }

    int bytes_generated = 0;
    unsigned char temp_word[WORD_LENGTH];
    // Index to the round constant
    unsigned char roundConIndex = 0;

    // Copy the original cipher key to the beginning of the expanded key
    memcpy(expandedKey, cipher_key, BLOCK_SIZE);
    bytes_generated += BLOCK_SIZE;

    // Generate the remaining round keys
    while (bytes_generated < EXPANDED_KEY_LENGTH) {
        // Copy the last generated word into temp_word
        memcpy(temp_word, expandedKey + bytes_generated - WORD_LENGTH, WORD_LENGTH);

        // Perform the key schedule core every 16 bytes
        if (bytes_generated % BLOCK_SIZE == 0) {
            // Perform the key schedule core (rot_word and applySBoxToWord)
            rotateWordLeft(temp_word);
            applySBoxToWord(temp_word);
            // XOR the first byte of temp_word with the round constant
            temp_word[0] ^= ROUND_CONSTANT[roundConIndex++];
        }

        // XOR the temp_word word with the word BLOCK_SIZE bytes before it
        for (int i = 0; i < WORD_LENGTH; ++i) {
            // XOR each byte of the temp_word word with the corresponding byte of the word BLOCK_SIZE bytes before it
            expandedKey[bytes_generated] = expandedKey[bytes_generated - BLOCK_SIZE] ^ temp_word[i];
            // Increment the number of bytes generated
            bytes_generated++;
        }
    }
    // Return the expanded key
    return expandedKey;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
    // TODO: Implement me!
    unsigned char *output =
            (unsigned char *) malloc(sizeof(unsigned char) * BLOCK_SIZE);
    return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
    // TODO: Implement me!
    unsigned char *output =
            (unsigned char *) malloc(sizeof(unsigned char) * BLOCK_SIZE);
    return output;
}
