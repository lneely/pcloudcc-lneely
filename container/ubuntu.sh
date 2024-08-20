#!/bin/bash

set -x

#cid=$(podman run -dit -v /home/lkn/src:/src ubuntu)

cid=$(buildah from "${1:-ubuntu}")
buildah run "$cid" -- apt update
buildah run "$cid" -- apt install build-essential git libfuse-dev libudev-dev libsqlite3-dev libmbedtls-dev zlib1g-dev libboost-system-dev libboost-program-options-dev fuse
buildah commit "$cid" "$USER"

set +x
