CC=gcc
AR=ar rcu
RANLIB=ranlib
#USESSL=openssl
USESSL=mbed

CFLAGS=-Wall -O2 -g -fno-stack-protector -fomit-frame-pointer -fPIC

LIB_A=psynclib.a
UNAME_S := $(shell uname -s)
UNAME_V := $(shell uname -v)
CFLAGS += -DP_OS_LINUX -D_FILE_OFFSET_BITS=64 -DP_SSL_MBEDTLS -I/usr/include -I/usr/include/mbedtls2
LDFLAGS += -lssl -lcrypto -lfuse -lpthread -lsqlite3 -lzlib -l:libmbedtls.so.14 -l:libmbedx509.so.14 -l:libmbedcrypto.so.14

OBJ=pcompat.o psynclib.o plocks.o plibs.o pcallbacks.o pdiff.o pstatus.o papi.o ptimer.o\
	pupload.o pdownload.o pfolder.o psyncer.o ptasks.o psettings.o pnetlibs.o pcache.o\
	pscanner.o plist.o plocalscan.o plocalnotify.o pp2p.o pcrypto.o pssl.o pfileops.o\
	ptree.o ppassword.o prunratelimit.o pmemlock.o pnotifications.o pexternalstatus.o\
	publiclinks.o pbusinessaccount.o pcontacts.o poverlay.o poverlay_lin.o pcompression.o\
	pasyncnet.o ppathstatus.o pdevice_monitor.o ptools.o

OBJFS=pfs.o ppagecache.o pfsfolder.o pfstasks.o pfsupload.o pintervaltree.o pfsxattr.o\
	pcloudcrypto.o pfscrypto.o pcrc32c.o pfsstatic.o plocks.o

OBJ1=overlay_client.o

all: $(LIB_A)

$(LIB_A): $(OBJ) 
	$(AR) $@ $(OBJ) 
	$(RANLIB) $@

fs: $(OBJ) $(OBJFS)
	$(AR) $(LIB_A) $(OBJ) $(OBJFS)
	$(RANLIB) $(LIB_A)

debugfs: fs
	CFLAGS += -DDEBUG_LEVEL=${DEBUG}

overlay_client:
	cd ../poverlay_linux && make

clean:
	rm -f *~ *.o $(LIB_A) ../poverlay_linux/*.o ../poverlay_linux/overlay_client

