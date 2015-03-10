# Display exported symbols:
#  nm pkcs11-mock.dylib | grep ' T '

SRC_DIR=../../src

CC= gcc
ARCH_FLAGS= -m32
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -Werror -O2 -I$(SRC_DIR)
LIBNAME=pkcs11-mock-x86.dylib

all: pkcs11-mock.o
	$(CC) $(ARCH_FLAGS) -dynamiclib -o $(LIBNAME) \
	-Wl,-exported_symbols_list,pkcs11-mock.symbols \
	pkcs11-mock.o
	strip -x $(LIBNAME)

pkcs11-mock.o: $(SRC_DIR)/pkcs11-mock.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/pkcs11-mock.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.dylib
