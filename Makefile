CFLAGS=-fPIC -Wall -O0 -g -fsanitize=address -I./pclsync -I/usr/include -I/usr/include/mbedtls2
LDFLAGS=-lboost_program_options -lssl -lcrypto -lfuse -lpthread -ludev -lsqlite3 -lz -l:libmbedtls.so.14 -l:libmbedx509.so.1 -l:libmbedcrypto.so.7
CMDSRC=control_tools.cpp pclsync_lib_c.cpp pclsync_lib.cpp main.cpp
DESTDIR=/usr/local
LIBSRC=$(wildcard pclsync/*.c)
LIBOBJ = $(notdir $(LIBSRC:%.c=%.o))
STATIC=$STATIC

all: $(LIBSRC) $(CMDSRC)
ifeq ($(STATIC),1)
	make pcloudcc_static
else
	make libpcloudcc_lib.so pcloudcc
endif

pcloudcc_static:
	gcc -c $(CFLAGS) $(LDFLAGS) $(LIBSRC)
	g++ -o pcloudcc $(CFLAGS) $(LDFLAGS) $(LIBOBJ) $(CMDSRC)


libpcloudcc_lib.so: $(LIBSRC)
	gcc -o $@ -shared $(CFLAGS) $(LDFLAGS) $(LIBSRC)

pcloudcc: $(CMDSRC)
	g++ -o $@ $(CFLAGS) $(LDFLAGS) -L. -lpcloudcc_lib $(CMDSRC)

clean:
	rm -f *.o a.out libpcloudcc_lib.so pcloudcc

install:
	install -m 755 pcloudcc $(DESTDIR)/bin/pcloudcc
	install -m 755 libpcloudcc_lib.so $(DESTDIR)/lib/libpcloudcc_lib.so

uninstall:
	rm -f $(DESTDIR)/bin/pcloudcc
	rm -f $(DESTDIR)/lib/libpcloudcc_lib.so
