all:
	make -C pCloudCC/lib/pclsync fs
	cmake -H./pCloudCC/lib/mbedtls -B./pCloudCC/lib/mbedtls
	make -C pCloudCC/lib/mbedtls
	cmake -H./pCloudCC -B./pCloudCC
	make -C pCloudCC

clean:
	make -C pCloudCC/lib/pclsync clean
	make -C pCloudCC/lib/mbedtls clean
	make -C pCloudCC clean

