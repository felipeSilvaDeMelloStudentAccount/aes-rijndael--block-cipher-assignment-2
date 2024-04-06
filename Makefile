# set default compiler to cc
CC ?= cc

# declare all as a phony target
.PHONY: all test clean
# create main executable and shared library					
all: main rijndael.so

main: rijndael.o main.c
# create main executable
	$(CC) -o main main.c rijndael.o

rijndael.o: rijndael.c rijndael.h
# create object file
	$(CC) -o rijndael.o -fPIC -c rijndael.c

rijndael.so: rijndael.o
# create shared library
	$(CC) -o rijndael.so -shared rijndael.o

# call test target
	$(MAKE) test


test:
# Run Python unit tests for the C code
	python3 test_rijndael.py

clean:
# remove all object files and shared libraries
	rm -f *.o *.so
# remove main executable
	rm -f main

# to run the program, type 'make' in the terminal and it will create the main executable and shared library
# to run the tests, type 'make test' in the terminal and it will run the Python unit tests for the C code
