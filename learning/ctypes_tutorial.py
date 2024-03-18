# Importing c types library to use its functions and classes.
import ctypes


# Loading the shared library into the python program. CDLL - C Dynamic Link Library.
# include the full path as it can causes issues
clibrary = ctypes.CDLL("/home/fsdm/repos/aes-rijndael--block-cipher-assignment-2/learning/clibrary.so");




# Calling the function from the shared library.
# When passing a string we type cast it to bytes. using b"string"
# in python strings are immutable and can not be modified
# in c strings are mutable and can be modified
# clibrary.display(b"John", 18);

func = clibrary.display

func.argtypes = [ctypes.c_char_p, ctypes.c_int]
func.restype =  ctypes.c_char_p

func(b"John", 18)

# To run the program, open terminal and type 
# "python3 ctypes_tutorial.py" and press enter.
# output: "Hello, World!"