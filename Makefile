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
	install -m 755 cmd/pcloudcc/build/pcloudcc /usr/bin/pcloudcc
	install -m 755 cmd/pcloudcc/build/libpcloudcc_lib.so /usr/lib/libpcloudcc_lib.so

uninstall:
	rm /usr/bin/pcloudcc
	rm /usr/lib/pcloudcc_lib.so
