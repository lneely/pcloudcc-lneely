#!/usr/bin/env bash

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# This script builds a development host based on Arch.

set -e

HOST_USER="$USER"
CONTAINER_NAME="devhost-arch-${HOST_USER}"
IMAGE="agners/archlinuxarm"
USERNAME="dev"
USER_PASSWORD="devhost"
SOURCE_DIR="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")" 
SOURCE_NAME="$(basename "$SOURCE_DIR")"
SSH_PORT="2222" 

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Set up a fully-fledged Arch distribution in a Podman container with FUSE support and SSH access."
    echo
    echo "Options:"
    echo "  -n, --name NAME      Specify the name for the container (default: devhost-arch-${HOST_USER})"
    echo "  -u, --user USER      Specify the username to create (default: dev)"
    echo "  -p, --password PASS  Specify the user's password (default: devhost)"
    echo "  -s, --ssh-port PORT  Specify the SSH port to forward (default: 2222)"
    echo "  -r, --remove         Stop and remove the container if it exists"
    echo "  -e, --enter          Enter the container as the specified user (builds if not exists)"
    echo "  -h, --help           Display this help message"
    echo
    echo "Note: This script assumes it's located in a 'dev' subdirectory of the source root."
    echo "      The entire source root will be copied to /src/<source_root_name> in the container."
    echo "      The container name will include the host username: ${CONTAINER_NAME}"
    echo "      SSH public keys from $HOME/.ssh/*.pub will be copied to the container for key-based authentication."
}

check_fuse() {
    if [ ! -e /dev/fuse ]; then
        echo "ERROR: FUSE is not available on the host. Please ensure FUSE is installed and loaded."
        echo "You may need to run 'sudo modprobe fuse' on the host system."
        exit 1
    fi
}

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

build_container() {
    echo "Setting up Arch container: $CONTAINER_NAME"
    echo "Source root directory: $SOURCE_DIR"
    echo "Source name: $SOURCE_NAME"
    echo "SSH Port: $SSH_PORT"

    # create container
    check_fuse
    podman run --name "$CONTAINER_NAME" -d \
        --device /dev/fuse \
        --cap-add SYS_ADMIN \
        --security-opt apparmor:unconfined \
        -p ${SSH_PORT}:22 \
        "$IMAGE" sleep infinity

    # install system
    podman exec "$CONTAINER_NAME" pacman -Syyu --noconfirm
    podman exec "$CONTAINER_NAME" pacman -S --noconfirm \
        sudo vim nano curl wget git htop tmux man-db \
        bash-completion ca-certificates openssh \
        base-devel gcc gcc-libs make fuse2 systemd sqlite3 \
        mbedtls zlib boost llvm gdb iproute \
        rsync readline

    # verify fuse
    if ! podman exec "$CONTAINER_NAME" ls /dev/fuse > /dev/null 2>&1; then
        echo "WARNING: FUSE device not found in the container. FUSE might not work properly."
    fi

    # setup system
    podman exec "$CONTAINER_NAME" useradd -m -s /bin/bash "$USERNAME"
    podman exec "$CONTAINER_NAME" bash -c "echo $USERNAME:$USER_PASSWORD | chpasswd"
    podman exec "$CONTAINER_NAME" usermod -aG wheel "$USERNAME"

    podman exec "$CONTAINER_NAME" bash -c 'echo "%wheel ALL=(ALL) ALL" > /etc/sudoers.d/wheel-group'

    podman exec --user "$USERNAME" "$CONTAINER_NAME" bash -c 'echo "export PS1=\"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ \"" >> ~/.bashrc'

    # setup /src tree
    podman exec "$CONTAINER_NAME" mkdir -p "/src/$SOURCE_NAME"
    podman exec "$CONTAINER_NAME" chown -R "$USERNAME:$USERNAME" /src

    # setup ld.so.conf
    podman exec "$CONTAINER_NAME" bash -c 'echo "/usr/lib64/" >> /etc/ld.so.conf'
    podman exec "$CONTAINER_NAME" ldconfig

    # setup ssh authentication
    podman exec "$CONTAINER_NAME" mkdir -p "/home/$USERNAME/.ssh"
    podman exec "$CONTAINER_NAME" touch "/home/$USERNAME/.ssh/authorized_keys"
    podman exec "$CONTAINER_NAME" chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"
    podman exec "$CONTAINER_NAME" chmod 700 "/home/$USERNAME/.ssh"
    podman exec "$CONTAINER_NAME" chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
    for privkey in "$HOME"/.ssh/id_*; do
        podman cp "$privkey" "$CONTAINER_NAME:/home/$USERNAME/.ssh"
    done
    for pubkey in "$HOME"/.ssh/id_*.pub; do
        if [ -f "$pubkey" ]; then
            podman cp "$pubkey" "$CONTAINER_NAME:/home/$USERNAME/.ssh"
            podman cp "$pubkey" "$CONTAINER_NAME:/tmp/$(basename "$pubkey")"
            podman exec "$CONTAINER_NAME" bash -c "cat /tmp/$(basename "$pubkey") >> /home/$USERNAME/.ssh/authorized_keys"
            podman exec "$CONTAINER_NAME" rm "/tmp/$(basename "$pubkey")"
        fi
    done

    # setup and run sshd
    podman exec "$CONTAINER_NAME" ssh-keygen -A
    podman exec "$CONTAINER_NAME" sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    podman exec "$CONTAINER_NAME" sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    podman exec "$CONTAINER_NAME" /usr/sbin/sshd

    # mop up
    podman exec "$CONTAINER_NAME" pacman -Scc --noconfirm

    echo "Fedora container setup complete!"
    echo "Container name: $CONTAINER_NAME"
    echo "Username: $USERNAME"
    echo "Source root copied to: /src/$SOURCE_NAME"
    echo "Ownership of /src changed to $USERNAME recursively"
    echo "/usr/lib64/ added to system library search path"
    echo "FUSE support enabled (check warning messages, if any)"
    echo "SSH server enabled and configured for key-based authentication"
    echo "SSH public keys copied from $HOME/.ssh/*.pub to /home/$USERNAME/.ssh/authorized_keys"
}

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
        -s|--ssh-port)
            SSH_PORT="$2"
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
build_container

echo
echo "You can start the container with: podman start $CONTAINER_NAME"
echo "To enter the container, use: $0 -e"
echo "To stop and remove the container, use: $0 -r"
echo "To SSH into the container, use: ssh -p $SSH_PORT $USERNAME@localhost"
