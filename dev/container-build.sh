#!/usr/bin/env bash

# This script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this script.  If not, see <https://www.gnu.org/licenses/>.

set -e

# Function to display supported distributions
show_supported_distros() {
    echo "Supported distributions:"
    echo "  - debian"
    echo "  - ubuntu"
    echo "  - fedora"
    echo "  - archlinux"
    echo "  - opensuse/tumbleweed"
    echo "  - opensuse/leap"
}

# Function to display help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Build a container with development tools and compile the project."
    echo
    echo "Options:"
    echo "  -i, --image IMAGE    Specify the base image (default: debian)"
    echo "  -t, --tag TAG        Specify the tag for the base image (default: trixie)"
    echo "  -n, --name NAME      Specify the name for the container (default: debian-build)"
    echo "  -l, --list           List supported distributions"
    echo "  -h, --help           Display this help message"
    echo
    echo "Examples:"
    echo "  $0 -i ubuntu -t 20.04 -n ubuntu-build"
    echo "  $0 --image debian --tag buster --name debian-buster-build"
    echo "  $0 --image fedora --tag 34 --name fedora-build"
    echo "  $0 --image archlinux --tag latest --name arch-build"
    echo "  $0 --image opensuse/tumbleweed --tag latest --name opensuse-build"
    echo "  $0 --image opensuse/leap --tag 15.3 --name opensuse-leap-build"
    echo
    echo "Use -l or --list to see supported distributions"
}

# Default values
IMAGE="debian"
TAG="trixie"
NAME="debian-build"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--image)
            IMAGE="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -n|--name)
            NAME="$2"
            shift 2
            ;;
        -l|--list)
            show_supported_distros
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

FULL_IMAGE="${IMAGE}:${TAG}"
echo "Building $NAME container from $FULL_IMAGE..."

case $IMAGE in
    debian|ubuntu)
        echo "Setting up Debian/Ubuntu-based container..."
        ctrid=$(buildah from "$FULL_IMAGE")
        buildah run "$ctrid" -- apt update
        buildah run "$ctrid" -- apt install -y build-essential git libfuse-dev libudev-dev libsqlite3-dev libmbedtls-dev zlib1g-dev libboost-system-dev libboost-program-options-dev fuse llvm gdb
        ;;
    fedora)
        echo "Setting up Fedora-based container..."
        ctrid=$(buildah from "$FULL_IMAGE")
        buildah run "$ctrid" -- dnf update -y
        buildah run "$ctrid" -- dnf group install -y "C Development Tools and Libraries"
        buildah run "$ctrid" -- dnf install -y git fuse-devel systemd-devel sqlite-devel mbedtls-devel zlib-devel boost-devel boost-program-options fuse llvm gdb fuse udev libasan
        ;;
    archlinux|arch)
        echo "Setting up Arch Linux-based container..."
        ctrid=$(buildah from "$FULL_IMAGE")
        buildah run "$ctrid" -- pacman -Syu --noconfirm
        buildah run "$ctrid" -- pacman -S --noconfirm base-devel git fuse2 systemd sqlite mbedtls2 zlib boost boost-libs llvm gdb udev gcc make
        ;;
    opensuse/tumbleweed|opensuse/leap)
        echo "Setting up openSUSE-based container..."
        ctrid=$(buildah from "$FULL_IMAGE")
        buildah run "$ctrid" -- zypper refresh
        buildah run "$ctrid" -- zypper install -y gcc gcc-c++ make git fuse-devel systemd-devel sqlite3-devel zlib-devel libboost_system-devel libboost_program_options-devel fuse llvm gdb udev mbedtls-2-devel
        ;;
    *)
        echo "Unsupported image: $IMAGE"
        echo "Use -l or --list to see supported distributions"
        show_help
        exit 1
        ;;
esac

echo "Creating /src directory in the container..."
buildah run "$ctrid" -- mkdir -p /src

echo "Committing changes to the container..."
ctrid=$(buildah commit "$ctrid" "$USER/${IMAGE}-build:$TAG")

# Assuming this script is in ./dev subdirectory of the source root
SOURCE_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
SOURCE_DIR_NAME=$(basename "$SOURCE_ROOT")

echo "Building the project inside the container..."
if [[ $IMAGE == opensuse/* ]]; then
    podman run --rm -v "$SOURCE_ROOT:/src" "$USER/${IMAGE}-build:$TAG" /bin/bash -c "cd /src && CFLAGS='-I/usr/include/mbedtls-2' LDFLAGS='-L/usr/lib64 -lmbedtls-2 -lmbedx509-2 -lmbedcrypto-2' make"
else
    podman run --rm -v "$SOURCE_ROOT:/src" "$USER/${IMAGE}-build:$TAG" /bin/bash -c "cd /src && make"
fi

echo "Build complete. The binary should now be in your source root directory."
