CC ?= cc										# set default compiler to cc

.PHONY: all										# declare all as a phony target
all: main rijndael.so							# create main executable and shared library

main: rijndael.o main.c
	$(CC) -o main main.c rijndael.o 			# create main executable

rijndael.o: rijndael.c rijndael.h
	$(CC) -o rijndael.o -fPIC -c rijndael.c   	# create object file

rijndael.so: rijndael.o
	$(CC) -o rijndael.so -shared rijndael.o   	# create shared library

test:
    python3 test_rijndael.py                    # Run Python unit tests for the C code

clean:
	rm -f *.o *.so    							# remove all object files and shared libraries
	rm -f main	      							# remove main executable
