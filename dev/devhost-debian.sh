#!/bin/bash

# This script creates a fully-fledged Debian container using Podman

set -e

# Configuration
HOST_USER="$USER"
CONTAINER_NAME="debian-full-${HOST_USER}"
IMAGE="debian:bullseye"
USERNAME="debuser"
USER_PASSWORD="changeMe123!"  # You should change this!
SOURCE_DIR="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")"  # Parent of 'dev' directory
SOURCE_NAME="$(basename "$SOURCE_DIR")"

# Function to display help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Set up a fully-fledged Debian distribution in a Podman container."
    echo
    echo "Options:"
    echo "  -n, --name NAME      Specify the name for the container (default: debian-full-${HOST_USER})"
    echo "  -u, --user USER      Specify the username to create (default: debuser)"
    echo "  -p, --password PASS  Specify the user's password (default: changeMe123!)"
    echo "  -r, --remove         Stop and remove the container if it exists"
    echo "  -e, --enter          Enter the container as the specified user (builds if not exists)"
    echo "  -h, --help           Display this help message"
    echo
    echo "Note: This script assumes it's located in a 'dev' subdirectory of the source root."
    echo "      The entire source root will be copied to /src/<source_root_name> in the container."
    echo "      The container name will include the host username: ${CONTAINER_NAME}"
}

# Function to stop and remove the container
stop_and_remove_container() {
    if podman ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "Stopping container ${CONTAINER_NAME}..."
        podman stop "${CONTAINER_NAME}"
        echo "Removing container ${CONTAINER_NAME}..."
        podman rm "${CONTAINER_NAME}"
        echo "Container ${CONTAINER_NAME} has been stopped and removed."
        exit 0
    else
        echo "Container ${CONTAINER_NAME} does not exist."
        exit 0
    fi
}

# Function to enter the container
enter_container() {
    if ! podman ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "Container ${CONTAINER_NAME} does not exist. Building it now..."
        build_container
    fi

    if ! podman ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "Starting container ${CONTAINER_NAME}..."
        podman start "${CONTAINER_NAME}"
    fi
    echo "Entering container ${CONTAINER_NAME} as user ${USERNAME}..."
    podman exec -it -u "${USERNAME}" "${CONTAINER_NAME}" /bin/bash
    exit 0
}

# Function to build the container
build_container() {
    echo "Setting up Debian container: $CONTAINER_NAME"
    echo "Source root directory: $SOURCE_DIR"
    echo "Source name: $SOURCE_NAME"

    # Create the container
    podman run --name "$CONTAINER_NAME" -d "$IMAGE" sleep infinity

    # Update and install necessary packages
    podman exec "$CONTAINER_NAME" apt update
    podman exec "$CONTAINER_NAME" apt upgrade -y
    podman exec "$CONTAINER_NAME" apt install -y \
        sudo vim nano curl wget git htop tmux man-db locales \
        bash-completion ca-certificates ssh systemd systemd-sysv \
        build-essential libfuse-dev libudev-dev libsqlite3-dev \
        libmbedtls-dev zlib1g-dev libboost-system-dev \
        libboost-program-options-dev fuse llvm gdb

    # Configure locale
    podman exec "$CONTAINER_NAME" sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen
    podman exec "$CONTAINER_NAME" locale-gen
    podman exec "$CONTAINER_NAME" update-locale LANG=en_US.UTF-8

    # Create user account
    podman exec "$CONTAINER_NAME" useradd -m -s /bin/bash "$USERNAME"
    podman exec "$CONTAINER_NAME" bash -c "echo $USERNAME:$USER_PASSWORD | chpasswd"

    # Add user to sudo group
    podman exec "$CONTAINER_NAME" usermod -aG sudo "$USERNAME"

    # Configure sudo
    podman exec "$CONTAINER_NAME" bash -c 'echo "%sudo ALL=(ALL) ALL" > /etc/sudoers.d/sudo-group'

    # Set up .bashrc for the new user
    podman exec --user "$USERNAME" "$CONTAINER_NAME" bash -c 'echo "export PS1=\"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ \"" >> ~/.bashrc'

    # Create /src directory and subdirectory for the source
    podman exec "$CONTAINER_NAME" mkdir -p "/src/$SOURCE_NAME"

    # Copy source directory to container
    podman cp "$SOURCE_DIR/." "$CONTAINER_NAME:/src/$SOURCE_NAME/"

    # Change ownership of /src to the new user recursively
    podman exec "$CONTAINER_NAME" chown -R "$USERNAME:$USERNAME" /src

    # Add /usr/lib/x86_64-linux-gnu/ to the system library search path
    podman exec "$CONTAINER_NAME" bash -c 'echo "/usr/lib/x86_64-linux-gnu/" >> /etc/ld.so.conf'
    podman exec "$CONTAINER_NAME" ldconfig

    # Clean up
    podman exec "$CONTAINER_NAME" apt clean
    podman exec "$CONTAINER_NAME" rm -rf /var/lib/apt/lists/*

    echo "Debian container setup complete!"
    echo "Container name: $CONTAINER_NAME"
    echo "Username: $USERNAME"
    echo "Source root copied to: /src/$SOURCE_NAME"
    echo "Ownership of /src changed to $USERNAME recursively"
    echo "/usr/lib/x86_64-linux-gnu/ added to system library search path"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            CONTAINER_NAME="$2-${HOST_USER}"
            shift 2
            ;;
        -u|--user)
            USERNAME="$2"
            shift 2
            ;;
        -p|--password)
            USER_PASSWORD="$2"
            shift 2
            ;;
        -r|--remove)
            stop_and_remove_container
            ;;
        -e|--enter)
            enter_container
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

# If no options are provided, build the container
build_container

echo
echo "You can start the container with: podman start $CONTAINER_NAME"
echo "To enter the container, use: $0 -e"
echo "To stop and remove the container, use: $0 -r"

