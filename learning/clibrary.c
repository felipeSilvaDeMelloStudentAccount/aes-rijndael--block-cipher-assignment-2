#include <stdio.h>

char* display(char* str, int age){
    printf("My Name is %s and my age is %d", str, age);
    return "Completed";
}

// We need to to compile this file with the following command:
// gcc -fPIC -shared -o clibrary.so clibrary.c 
// we are using  -fPIC for position independent code, 
// -shared to create a shared library 
// -o to specify the output file name




// Ref : Python ctypes Tutorial - Using C/C++ Functions in Python
// https://youtu.be/neexS0HK9TY?si=SE1xH6Jxe-0Z1tNU