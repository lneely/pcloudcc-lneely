DESTDIR=/usr

all:
	make -C ./lib/pclsync fs
	cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -H./lib/mbedtls-2.1.14 -B./lib/mbedtls-2.1.14/build
	make -C ./lib/mbedtls-2.1.14/build
	mkdir -p ./cmd/pcloudcc/build
	cmake -DCMAKE_BUILD_TYPE=Debug -H. -B./cmd/pcloudcc/build
	make -C ./cmd/pcloudcc/build

clean:
	make -C lib/pclsync clean
	rm -rf lib/mbedtls-2.1.14/build
	rm -rf ./cmd/pcloudcc/build

install:
	install -m 755 cmd/pcloudcc/build/pcloudcc $(DESTDIR)/bin/pcloudcc
	install -m 755 cmd/pcloudcc/build/libpcloudcc_lib.so $(DESTDIR)/lib/libpcloudcc_lib.so

uninstall:
	rm -f $(DESTDIR)/bin/pcloudcc
	rm -f $(DESTDIR)/lib/libpcloudcc_lib.so
