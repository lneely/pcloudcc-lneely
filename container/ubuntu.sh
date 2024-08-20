#!/bin/bash

set -x

echo "building ubuntu container..."
ctrid=$(buildah from ubuntu:latest)
buildah run "$ctrid" -- apt update -y
buildah run "$ctrid" -- apt install -y build-essential git libfuse-dev libudev-dev libsqlite3-dev libmbedtls-dev zlib1g-dev libboost-system-dev libboost-program-options-dev fuse llvm gdb
export ctrid=$(buildah commit "$ctrid" "$USER/ubuntu-build")
echo "done! the container name is: $USER/ubuntu-build"
set +x
