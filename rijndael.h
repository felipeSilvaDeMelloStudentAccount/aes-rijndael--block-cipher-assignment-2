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



//Define XTIME to perform multiplication by 2 in the GF(2^8) field.
//If the leftmost bit of the input is 1, the result of the shift is XORed with 0x1b (the irreducible polynomial).
#define XTIME(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))

// Define the number of rounds used in AES algorithm
#define MULTIPLY(x, y) ( \
    ((y & 0x01) * (x)) ^ \
    ((y & 0x02) ? XTIME(x) : 0) ^ \
    ((y & 0x04) ? XTIME(XTIME(x)) : 0) ^ \
    ((y & 0x08) ? XTIME(XTIME(XTIME(x))) : 0) ^ \
    ((y & 0x10) ? XTIME(XTIME(XTIME(XTIME(x)))) : 0))




/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
