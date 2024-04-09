/*
 * Felipe Silva de Mello
 * D23125661
 * This file is an interface of rijandael.c file 
 * which contains the complex implemention of the encryption and decryption functions
 */

// This file contains the function prototypes for the main encryption and decryption functions
#ifndef RIJNDAEL_H
#define RIJNDAEL_H
// Define the block size and the number of rounds
#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
// Define the block size and the number of rounds
#define BLOCK_SIZE 16
// 11 round keys of 128 bits each
#define EXPANDED_KEY_LENGTH 176
#define WORD_LENGTH 4


#define XTIME(x) (((x) << 1) ^ (((x) & 0x80) ? 0x1b : 0x00))

// Prototype for inv_mix_columns
void inv_mix_columns(unsigned char *block);


/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
