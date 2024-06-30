all:
	make -C ./lib/pclsync fs
	cmake -H./lib/mbedtls-1.3.10 -B./lib/mbedtls-1.3.10/build
	make -C ./lib/mbedtls-1.3.10/build
	mkdir -p ./cmd/pcloudcc/build
	cmake -H. -B./cmd/pcloudcc/build
	make -C ./cmd/pcloudcc/build

clean:
	make -C lib/pclsync clean
	rm -rf lib/mbedtls-1.3.10/build
	rm -rf ./cmd/pcloudcc/build


