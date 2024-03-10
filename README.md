# Secure Systems Development
## Assignment 2: The Advanced Encryption Standard (AES) 
### Weight 40%
#### Objective

The Aim of this assignment is to implement the 128-bit variant of AES as a C library.
The library should consist of header file, rijndael.h, wich should expose 2 functions to the user:
- unsigned char *aes_encrypt_block(unsigned char *plainText, unsigned char *key)
- unsigned char *aes_decrypt_block(unsigned char *cipherText, unsigned char *key)

Along with any corresponding implementation files which contain the implementation of these functions and any dependent functions.

aes_encrypt_block() takes a pointer to a 128-bit plaintext(i.e 16 bytes of data) and a pointer to a 128-bit key(i.e 16 bytes of data) and returns a pointer to a 128-bit ciphertext(i.e 16 bytes of data).
Then applies the Rijndael algorithm to the plaintext to return a ciphertext.
The ciphertext should be stored on the heap, and pointer to it should be returned by the function.

For example, if the plaintext is:
```1   2  3   4
   5   6   7   8
   9   10  11  12
   13  14  15  16
```
It will be passed to encrypt_block() as a pointer to the C array {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}.

Likewise, aes_decrypt_block() takes a pointer to a 128-bit ciphertext and a pointer to a 128-bit key 
and applies the Rijndael algorithm to the ciphertext to return a plaintext.
The plaintext should be stored on the heap, and a pointer to it should be returned by the function.

The library can assume that the programme that is using the library will take responsibility for freeing the pointers
passed to and from these functions. However, if the functions allocate any heap space internally, they must free this themselves.

The library must implement the algorithm in full, without using any third-party libraries or existing implementations of AES.
IT also may not use instructions in your CPU's instruction set that implement AWS in hardware.
Use of non-cryptographic functions in the C standard library is allowed.


//TODO makefile build.yml