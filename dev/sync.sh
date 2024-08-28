#!/bin/bash

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


# This script syncs the source tree in the devhost with the local
# source tree.

set -e

SOURCE_DIR="$(pwd)"
CONTAINER_USER="dev"
DEST_DIR="/src/$(basename "$SOURCE_DIR")"
SSH_PORT="2222"

get_container_ip() {
    podman exec "$CONTAINER_NAME" bash -c "ip -4 addr show | grep -v '127.0.0.1' | grep 'inet ' | grep 'scope global' | head -n 1 | awk '{print \$2}' | cut -d/ -f1"
}

check_ssh_connection() {
    local container_ip=$1
    ssh-keyscan -p "$SSH_PORT" "$container_ip" > /dev/null 2>&1 || {
        echo "Error: Unable to establish SSH connection to $container_ip:$SSH_PORT"
        exit 1
    }
}

sync_files() {
    local container_ip=$(get_container_ip)
    if [ -z "$container_ip" ]; then
        echo "Error: Unable to get container IP address. Is the container running?"
        exit 1
    fi

    check_ssh_connection "$container_ip"

    echo "Syncing files to $CONTAINER_NAME ($container_ip)..."
    rsync -avz --delete \
        -e "ssh -p $SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5" \
        --exclude '.git' \
        --exclude 'target' \
        --exclude '*.tmp' \
        --exclude '*.o' \
        --exclude 'pcloudcc' \
        --exclude '*.log' \
        --exclude '.cache' \
        "$SOURCE_DIR/" \
        "${CONTAINER_USER}@${container_ip}:${DEST_DIR}/" || {
        echo "Error: rsync failed. Exiting."
        exit 1
    }
    
    echo "Sync completed at $(date)"
}

show_help() {
    echo "Usage: $0 [OPTIONS] -c CONTAINER_NAME"
    echo "Sync files to a devhost container using rsync and watchexec."
    echo
    echo "Options:"
    echo "  -c, --container CONTAINER_NAME   Specify the devhost container name (required)"
    echo "  -s, --source DIR                 Specify the source directory (default: current directory)"
    echo "  -d, --dest DIR                   Specify the destination directory in the container"
    echo "  -u, --user USER                  Specify the user in the container (default: dev)"
    echo "  -p, --port PORT                  Specify the SSH port (default: 2222)"
    echo "  -o, --once                       Sync files once and exit"
    echo "  -w, --watch                      Watch for changes and sync continuously (default)"
    echo "  -h, --help                       Display this help message"
}

WATCH=true
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        -s|--source)
            SOURCE_DIR="$2"
            shift 2
            ;;
        -d|--dest)
            DEST_DIR="$2"
            shift 2
            ;;
        -u|--user)
            CONTAINER_USER="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -o|--once)
            WATCH=false
            shift
            ;;
        -w|--watch)
            WATCH=true
            shift
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

if [ -z "$CONTAINER_NAME" ]; then
    echo "Error: Devhost container name is required. Use -c or --container to specify it."
    show_help
    exit 1
fi

if ! command -v watchexec &> /dev/null && [ "$WATCH" = true ]; then
    echo "Error: watchexec is not installed. Please install it to use the watch feature."
    echo "You can install it using: cargo install watchexec-cli"
    exit 1
fi

if ! command -v rsync &> /dev/null; then
    echo "Error: rsync is not installed. Please install it to use this script."
    exit 1
fi

if [ "$WATCH" = true ]; then
    echo "Watching for changes in $SOURCE_DIR"
    watchexec -w "$SOURCE_DIR" --on-busy-update=restart -- "$0" --once -c "$CONTAINER_NAME" -s "$SOURCE_DIR" -d "$DEST_DIR" -u "$CONTAINER_USER" -p "$SSH_PORT"
else
    sync_files
fi
