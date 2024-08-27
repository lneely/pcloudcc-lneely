#!/bin/bash

# Default configuration
SOURCE_DIR="$(pwd)"
CONTAINER_USER="root"
DEST_DIR="/src/$(basename "$SOURCE_DIR")"
NETWORK_INTERFACE="eth0"

# Function to get container IP address
get_container_ip() {
    podman exec "$CONTAINER_NAME" ip addr show "$NETWORK_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
}

# Function to sync files
sync_files() {
    local container_ip=$(get_container_ip)
    if [ -z "$container_ip" ]; then
        echo "Error: Unable to get container IP address. Is the container running and does it have the $NETWORK_INTERFACE interface?"
        exit 1
    fi

    echo "Syncing files to $CONTAINER_NAME ($container_ip)..."
    rsync -avz --delete \
        --exclude '.git' \
        --exclude 'node_modules' \
        --exclude 'target' \
        --exclude '*.tmp' \
        --exclude '*.log' \
        "$SOURCE_DIR/" \
        "${CONTAINER_USER}@${container_ip}:${DEST_DIR}/"
    
    echo "Sync completed at $(date)"
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS] -c CONTAINER_NAME"
    echo "Sync files to a devhost container using rsync and watchexec."
    echo
    echo "Options:"
    echo "  -c, --container CONTAINER_NAME   Specify the devhost container name (required)"
    echo "  -s, --source DIR                 Specify the source directory (default: current directory)"
    echo "  -d, --dest DIR                   Specify the destination directory in the container"
    echo "  -u, --user USER                  Specify the user in the container (default: root)"
    echo "  -i, --interface INTERFACE        Specify the network interface (default: eth0)"
    echo "  -o, --once                       Sync files once and exit"
    echo "  -w, --watch                      Watch for changes and sync continuously (default)"
    echo "  -h, --help                       Display this help message"
}

# Parse command line arguments
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
        -i|--interface)
            NETWORK_INTERFACE="$2"
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

# Check if container name is provided
if [ -z "$CONTAINER_NAME" ]; then
    echo "Error: Devhost container name is required. Use -c or --container to specify it."
    show_help
    exit 1
fi

# Check if watchexec is installed
if ! command -v watchexec &> /dev/null && [ "$WATCH" = true ]; then
    echo "Error: watchexec is not installed. Please install it to use the watch feature."
    echo "You can install it using: cargo install watchexec-cli"
    exit 1
fi

# Check if rsync is installed
if ! command -v rsync &> /dev/null; then
    echo "Error: rsync is not installed. Please install it to use this script."
    exit 1
fi

# Main execution
if [ "$WATCH" = true ]; then
    echo "Watching for changes in $SOURCE_DIR"
    watchexec -w "$SOURCE_DIR" --on-busy-update=restart -- "$0" --once -c "$CONTAINER_NAME" -s "$SOURCE_DIR" -d "$DEST_DIR" -u "$CONTAINER_USER" -i "$NETWORK_INTERFACE"
else
    sync_files
fi
