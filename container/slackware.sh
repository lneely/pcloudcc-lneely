#!/bin/bash

set -x

echo "building slackware container..."
ctrid=$(buildah from slackware:latest)
#buildah run "$ctrid" -- dnf update -y
#buildah run "$ctrid" --  dnf group install -y "C Development Tools and Libraries"
#buildah run "$ctrid" -- dnf install -y git fuse fuse-devel sqlite-devel mbedtls-devel zlib-devel boost-system boost-devel boost-program-options udev systemd-devel libasan
export ctrid=$(buildah commit "$ctrid" "$USER/slack-build")
echo "done! the container name is: $USER/slack-build"

set +x
