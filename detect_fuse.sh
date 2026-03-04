#!/bin/bash
# Detect FUSE version and set appropriate flags

if pkg-config --exists fuse3; then
    echo "FUSE3"
elif pkg-config --exists fuse; then
    echo "FUSE2"
else
    echo "NONE"
    exit 1
fi
