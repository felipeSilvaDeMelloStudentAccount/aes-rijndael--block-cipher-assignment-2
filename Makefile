# Set default compiler to cc if not already set
CC ?= cc

# Paths to source and header files to be formatted
SRC_FILES := $(wildcard *.c)
HEADER_FILES := $(wildcard *.h)


# Declare phony targets
.PHONY: all test clean format init-submodules

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

# Initialize and update git submodules
init-submodules:
	# Initialize and update git submodules
	git submodule update --init --recursive

# Run Python unit tests for the rijndael.so shared library
# NOTE Using python3 to run the tests
test: init-submodules
	# Run Python unit tests for the rijndael.so shared library
	echo "Running Python Unit tests for the rijndael.so shared library..."
	python3 test_rijndael.py

clean:
	# Remove all object files, shared libraries, and executables
	rm -f *.o *.so main


# Download and install clang-format before running format target
# Linux Machine (Ubuntu) - sudo apt-get install clang-format
format:
	# Format all C source and header files using Google's style
	clang-format -i --style=Google $(SRC_FILES) $(HEADER_FILES)


# Instructions:
# - To build everything and run Python tests, type 'make' or 'make test'
# - To clean up, type 'make clean'
# - To format source and header files, type 'make format'
