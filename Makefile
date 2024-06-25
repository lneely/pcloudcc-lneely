all:
	make -C pCloudCC/lib/pclsync fs
	cmake -H./pCloudCC/lib/mbedtls -B./pCloudCC/lib/mbedtls
	make -C pCloudCC/lib/mbedtls
	cmake -H./pCloudCC -B./pCloudCC
	make -C pCloudCC

clean:
	make -C pCloudCC/lib/pclsync clean
	make -C pCloudCC/lib/mbedtls clean
	rm -rf pCloudCC/lib/mbedtls/CMakeFiles
	rm pCloudCC/lib/mbedtls/CMakeCache.txt
	rm pCloudCC/lib/mbedtls/Makefile
	make -C pCloudCC clean
	rm -rf pCloudCC/CMakeFiles
	rm pCloudCC/CMakeCache.txt
	rm pCloudCC/Makefile

