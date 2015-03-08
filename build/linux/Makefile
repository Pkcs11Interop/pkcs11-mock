# Display exported symbols:
#  nm -D pkcs11-mock.so | grep ' T '

SRC_DIR=../../src

CC= gcc
ARCH_FLAGS= -m32
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -Werror -O2 -I$(SRC_DIR)
LIBNAME=pkcs11-mock-x86.so

all: pkcs11-mock.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,pkcs11-mock.version \
	pkcs11-mock.o
	strip --strip-all $(LIBNAME)

pkcs11-mock.o: $(SRC_DIR)/pkcs11-mock.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/pkcs11-mock.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
