CFLAGS=-Wall -O2 -g -fsanitize=address -fPIC -I./pclsync -I./poverlay_linux
LDFLAGS=-l:libpcloudcc_lib.so -lboost_program_options
LIBSRC=control_tools.cpp pclsync_lib_c.cpp pclsync_lib.cpp
DESTDIR=/usr/local

all: 
	make -C ./pclsync fs
	make -C ./poverlay_linux all
	make libpcloudcc_lib.so pcloudcc

libpcloudcc_lib.so: 
	g++ -shared $(CFLAGS) $(LIBSRC) -o libpcloudcc_lib.so

pcloudcc:
	g++ $(CFLAGS) $(LDFLAGS) main.cpp -o pcloudcc

clean:
	make -C ./pclsync clean
	make -C ./poverlay_linux clean
	rm -f *.o a.out libpcloudcc_lib.so pcloudcc

install:
	install -m 755 pcloudcc $(DESTDIR)/bin/pcloudcc
	install -m 755 libpcloudcc_lib.so $(DESTDIR)/lib/libpcloudcc_lib.so

uninstall:
	rm -f $(DESTDIR)/bin/pcloudcc
	rm -f $(DESTDIR)/lib/libpcloudcc_lib.so
