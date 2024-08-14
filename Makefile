all:
	make -C ./lib/pclsync fs
	cmake -DCMAKE_BUILD_TYPE=Debug -H./lib/mbedtls -B./lib/mbedtls/build
	make -C ./lib/mbedtls/build
	mkdir -p ./cmd/pcloudcc/build
	cmake -DCMAKE_BUILD_TYPE=Debug -H. -B./cmd/pcloudcc/build
	make -C ./cmd/pcloudcc/build

clean:
	make -C lib/pclsync clean
	rm -rf lib/mbedtls/build
	rm -rf ./cmd/pcloudcc/build


