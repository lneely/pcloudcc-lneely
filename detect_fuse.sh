#!/bin/bash
# Detect FUSE version and set appropriate flags

# Check if pkg-config is available
if ! command -v pkg-config >/dev/null 2>&1; then
    # Fallback: check for header files
    if [ -f /usr/include/fuse3/fuse.h ] || [ -f /usr/local/include/fuse3/fuse.h ]; then
        echo "FUSE3"
    elif [ -f /usr/include/fuse/fuse.h ] || [ -f /usr/local/include/fuse/fuse.h ]; then
        echo "FUSE2"
    else
        echo "NONE"
        exit 1
    fi
    exit 0
fi

# Use pkg-config if available
if pkg-config --exists fuse3 2>/dev/null; then
    echo "FUSE3"
elif pkg-config --exists fuse 2>/dev/null; then
    echo "FUSE2"
else
    echo "NONE"
    exit 1
fi
