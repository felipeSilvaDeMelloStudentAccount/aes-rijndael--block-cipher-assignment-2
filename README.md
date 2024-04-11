# Secure Systems Development
## Assignment 2: The Advanced Encryption Standard (AES)
### Weight: 40%

#### Objective

The aim of this assignment is to implement the 128-bit variant of AES as a C library. The library should consist of a header file, `rijndael.h`, which exposes two functions to the user:

- `unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key)`
- `unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key)`

Along with any corresponding implementation files that contain the implementation of these functions and any dependent functions.

`aes_encrypt_block()` takes a pointer to a 128-bit plaintext (i.e., 16 bytes of data) and a pointer to a 128-bit key (i.e., 16 bytes of data) and returns a pointer to a 128-bit ciphertext (i.e., 16 bytes of data). It then applies the Rijndael algorithm to the plaintext to return a ciphertext. The ciphertext should be stored on the heap, and a pointer to it should be returned by the function.

For example, if the plaintext is arranged as follows:


For example, if the plaintext is:
```1   2  3   4
   5   6   7   8
   9   10  11  12
   13  14  15  16
```

It will be passed to `encrypt_block()` as a pointer to the C array `{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}`.

Likewise, `aes_decrypt_block()` takes a pointer to a 128-bit ciphertext and a pointer to a 128-bit key and applies the Rijndael algorithm to the ciphertext to return a plaintext. The plaintext should be stored on the heap, and a pointer to it should be returned by the function.

The library can assume that the program using the library will take responsibility for freeing the pointers passed to and from these functions. However, if the functions allocate any heap space internally, they must free this themselves.

The library must implement the algorithm in full, without using any third-party libraries or existing implementations of AES. It also may not use instructions in your CPU's instruction set that implement AES in hardware. Use of non-cryptographic functions in the C standard library is allowed.

#### Working with Git and Git Submodules
This project uses Git submodules to include external libraries or shared components. Specifically, it incorporates the AES library from the following Git repository as a submodule: [https://github.com/boppreh/aes/](https://github.com/boppreh/aes/).

To properly clone this project along with its submodules, follow these steps:
1. Clone the project repository:
- git clone <https://github.com/felipeSilvaDeMelloStudentAccount/aes-rijndael--block-cipher-assignment-2>

2. Initialize and update the submodules:
    - cd aes-rijndael--block-cipher-assignment-2
    - git submodule init
    - git submodule update


#### Building and Running

To compile and build the library along with its test cases, you can use the provided Makefile. Use the following commands:

- `make`: Compiles and builds the library and any additional required files.
- `make test`: Compiles, builds, and runs the unit tests for the library.
- `make clean`: Cleans up the build, removing all generated files.

Ensure that you have a C compiler (such as `gcc`) installed on your system and accessible from your command line or terminal.

