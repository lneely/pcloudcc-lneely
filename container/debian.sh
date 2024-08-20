#!/bin/bash

set -x

echo "building debian container..."
ctrid=$(buildah from debian:latest)
buildah run "$ctrid" -- apt update
buildah run "$ctrid" -- apt install build-essential git libfuse-dev libudev-dev libsqlite3-dev libmbedtls-dev zlib1g-dev libboost-system-dev libboost-program-options-dev fuse llvm gdb
export ctrid=$(buildah commit "$ctrid" "$USER/debian-build")
echo "done! you can use $ctrid to start a container"
set +x
