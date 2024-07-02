all:
	make -C ./lib/pclsync fs
	cmake -DCMAKE_BUILD_TYPE=Debug -H./lib/mbedtls-1.3.10 -B./lib/mbedtls-1.3.10/build
	make -C ./lib/mbedtls-1.3.10/build
	cmake -DCMAKE_BUILD_TYPE=Debug -H./lib/mbedtls-2.1.14 -B./lib/mbedtls-2.1.14/build
	make -C ./lib/mbedtls-2.1.14/build
	mkdir -p ./cmd/pcloudcc/build
	cmake -DCMAKE_BUILD_TYPE=Debug -H. -B./cmd/pcloudcc/build
	make -C ./cmd/pcloudcc/build

clean:
	make -C lib/pclsync clean
	rm -rf lib/mbedtls-1.3.10/build
	rm -rf lib/mbedtls-2.1.14/build
	rm -rf ./cmd/pcloudcc/build


