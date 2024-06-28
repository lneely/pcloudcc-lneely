CC=cc
#USESSL=openssl
USESSL=mbed

#CFLAGS=-Wall -Wpointer-arith -O2 -g -fsanitize=address -mtune=core2
CFLAGS=-Wall -Wpointer-arith -O2 -g -fno-stack-protector -fomit-frame-pointer -mtune=core2 -DPCLOUD_TESTING

UNAME_S := $(shell uname -s)
UNAME_V := $(shell uname -v)
CFLAGS += -DP_OS_LINUX
LDFLAGS += -lssl -lcrypto -lpthread

OBJ=overlay_client.o  debug.o

all: overlay_client

fs: overlay_client

overlay_client: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o overlay_client

clean:
	rm -f *~ *.o

