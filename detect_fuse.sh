#!/bin/bash
# Detect FUSE version and set appropriate flags

# Check if pkg-config is available
if command -v pkg-config >/dev/null 2>&1; then
    # Use pkg-config if available
    if pkg-config --exists fuse3 2>/dev/null; then
        echo "FUSE3"
        exit 0
    elif pkg-config --exists fuse 2>/dev/null; then
        echo "FUSE2"
        exit 0
    fi
fi

# Fallback: search for header files in common locations
SEARCH_PATHS="/usr/include /usr/local/include /opt/local/include /opt/include"

for base in $SEARCH_PATHS; do
    if [ -f "$base/fuse3/fuse.h" ]; then
        echo "FUSE3"
        exit 0
    fi
done

for base in $SEARCH_PATHS; do
    if [ -f "$base/fuse/fuse.h" ]; then
        echo "FUSE2"
        exit 0
    fi
done

# Last resort: try to compile a test program
if command -v gcc >/dev/null 2>&1; then
    # Try FUSE 3
    if echo '#include <fuse.h>' | gcc -E -DFUSE_USE_VERSION=30 - >/dev/null 2>&1; then
        echo "FUSE3"
        exit 0
    fi
    # Try FUSE 2
    if echo '#include <fuse.h>' | gcc -E -DFUSE_USE_VERSION=26 - >/dev/null 2>&1; then
        echo "FUSE2"
        exit 0
    fi
fi

echo "NONE"
exit 1
