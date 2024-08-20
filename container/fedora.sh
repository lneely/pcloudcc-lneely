#!/bin/bash

set -x

#cid=$(podman run -dit -v /home/lkn/src:/src ubuntu)

cid=$(buildah from "${1:-fedora}")
buildah run "$cid" -- dnf update -y
buildah run "$cid" --  dnf group install -y "C Development Tools and Libraries"
buildah run "$cid" -- dnf install -y git fuse fuse-devel sqlite-devel mbedtls-devel zlib-devel boost-system boost-devel boost-program-options udev systemd-devel libasan
buildah commit "$cid" "$USER"

set +x
