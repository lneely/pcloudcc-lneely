# DevHost Setup Scripts

This repository contains scripts to set up development environments using Podman containers. The scripts allow you to create and manage development hosts based on Fedora or Debian/Ubuntu, and sync your project files between the host and the container.

## Scripts

1. `devhost-fedora.sh`: Sets up a Fedora-based development environment.
2. `devhost-debian.sh`: Sets up a Debian or Ubuntu-based development environment.
3. `sync.sh`: Syncs project files between the host and the container.

## Prerequisites

- Podman installed on your host system
- FUSE support on your host system
- SSH key pair for authentication (optional, but recommended)

## Usage

### Setting up a Development Host

#### Fedora-based Host

```bash
./devhost-fedora.sh [OPTIONS]
```

#### Debian/Ubuntu-based Host

```bash
./devhost-debian.sh [OPTIONS]
```

Common options for both scripts:

- `-n, --name NAME`: Specify the name for the container (default: devhost-[distro]-[username])
- `-u, --user USER`: Specify the username to create (default: dev)
- `-p, --password PASS`: Specify the user's password (default: devhost)
- `-s, --ssh-port PORT`: Specify the SSH port to forward (default: 2222)
- `-r, --remove`: Stop and remove the container if it exists
- `-e, --enter`: Enter the container as the specified user (builds if not exists)
- `-h, --help`: Display the help message

Additional option for devhost-debian.sh:

- `-d, --distro DISTRO`: Specify the distribution (debian or ubuntu) (default: debian)

### Examples

1. Create a Fedora-based development host:
   ```bash
   ./devhost-fedora.sh
   ```

2. Create an Ubuntu-based development host:
   ```bash
   ./devhost-debian.sh -d ubuntu
   ```

3. Create a Debian-based host with a custom name and SSH port:
   ```bash
   ./devhost-debian.sh -n mydevhost -s 2345
   ```

4. Enter an existing container:
   ```bash
   ./devhost-fedora.sh -e
   ```

5. Remove an existing container:
   ```bash
   ./devhost-debian.sh -r
   ```

### Syncing Project Files

To sync your project files from the host to the container, use the `sync.sh` script:

```bash
./sync.sh [OPTIONS] -c CONTAINER_NAME
```

Options:

- `-c, --container CONTAINER_NAME`: Specify the devhost container name (required)
- `-s, --source DIR`: Specify the source directory on the host (default: current directory)
- `-d, --dest DIR`: Specify the destination directory in the container
- `-u, --user USER`: Specify the user in the container (default: dev)
- `-p, --port PORT`: Specify the SSH port (default: 2222)
- `-o, --once`: Sync files once and exit
- `-w, --watch`: Watch for changes and sync continuously (default)
- `-h, --help`: Display the help message

Example:

```bash
./sync.sh -c mydevhost-fedora -s /path/to/project -d /src/project -u dev -p 2222 -w
```

This will sync files from `/path/to/project` on the host to `/src/project` in the container named `mydevhost-fedora`, using the user `dev` and SSH port 2222. It will continue to watch for changes and sync automatically.

Note:
- The script syncs files one-way: from the host to the container.
- The `-c` or `--container` option is required.
- By default, it watches for changes and syncs continuously. Use the `-o` or `--once` option for a single sync.
- Make sure you have `rsync` installed on your host, and `watchexec` if you want to use the watch feature.

## Notes

- The scripts assume they are located in a 'dev' subdirectory of the source root.
- The entire source root will be copied to /src/<source_root_name> in the container.
- SSH public keys from $HOME/.ssh/*.pub will be copied to the container for key-based authentication.
- FUSE support is enabled in the containers, allowing for advanced filesystem operations.

## Troubleshooting

If you encounter issues with FUSE support, ensure that FUSE is properly installed and loaded on your host system. You may need to run `sudo modprobe fuse` on the host system.

For any other issues or questions, please open an issue in the repository.
