# Set default compiler to cc if not already set
CC ?= cc

# Declare phony targets
.PHONY: all test clean

# Create main executable and shared library
all: main rijndael.so

main: rijndael.o main.c
	# Create main executable
	$(CC) -o main main.c rijndael.o

rijndael.o: rijndael.c rijndael.h
	# Create object file
	$(CC) -o rijndael.o -fPIC -c rijndael.c

rijndael.so: rijndael.o
	# Create shared library
	$(CC) -o rijndael.so -shared rijndael.o

# call test target
	$(MAKE) test
test:
	# Run Python unit tests for the rijndael.so shared library
	echo "Running Python Unit tests for the rijndael.so shared library..."
	python3 test_rijndael.py

clean:
	# Remove all object files, shared libraries, and executables
	rm -f *.o *.so main

# Instructions:
# - To build everything and run Python tests, type 'make' or 'make test'
# - To clean up, type 'make clean'
