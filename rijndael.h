/*
 * Felipe Silva de Mello
 * D23125661
 * This file is an interface of rijandael.c file
 * which contains the complex implemention of the encryption and decryption
 * functions
 */
#ifndef RIJNDAEL_H
#define RIJNDAEL_H
#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16
#define BLOCK_ROWS 4
#define EXPANDED_KEY_LENGTH 176
#define NUMBER_OF_ROUNDS 10

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
