all:
	make -C lib/pclsync fs
	cmake -H./lib/mbedtls -B./lib/mbedtls/build
	make -C lib/mbedtls/build
	mkdir -pf build
	cmake -H. -B./build
	make -C build

clean:
	make -C lib/pclsync clean
	rm -rf lib/mbedtls/build
	rm -rf ./build


