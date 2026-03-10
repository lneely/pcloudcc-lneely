# Introduction

`pcloudcc` is simple linux console client for pCloud cloud storage derived from the console-client developed by pCloud. This version is independently maintained by me, whose only affiliation with pCloud is as a user of their services. Due credit goes to Anton Titov, Ivan Stoev, and pCloud.

# Supported Platforms & Distributions

The target operating system and platform for this program is `linux/amd64`, and has been reported to work on `linux/aarch64`. Program behavior on 32-bit architectures is [considered undefined](https://github.com/lneely/pcloudcc-lneely/issues/85).

I aim to support as many distributions as possible. I maintain a package for [AUR](https://aur.archlinux.org/packages/pcloudcc-lneely) and [Nix](https://github.com/lneely/nixpkgs). I do not plan on providing or maintaining any other packages, but encourage anyone interested in doing so for their own distributions.

# Compatibility Matrix

| Distribution | FUSE |
|---|---|
| Debian trixie | 2.x |
| Debian trixie | 3.x |
| Arch Linux (rolling) | 3.x latest |
| Fedora 41 | 3.x |
| Fedora (latest) | 3.x latest |
| Debian forky | 3.18+ |
| Slackware 15 | 3.10.5 | 

All configurations require **mbedTLS 3.x**. Runtime mount testing was performed manually on FUSE 2 (libfuse 2.9.x), FUSE 3 (libfuse3 3.10.5), and FUSE 3.18+ (Debian forky container).

# Notices

## Security Notice

My code audits are best-effort, and I make security enhancements as I identify problems. However, I *do not* promise that this program is free of even older and well-known security vulnerabilities. Therefore, I recommend using this program only on a *trusted single-user* system. **Security-related code audits and contributions are most welcome!**

# See Also

- [Contributing](./doc/CONTRIBUTING.md): Read this if you're interested in
  helping out. **Short version**: do your best to write good code, be
  courteous to maintainers, and most importantly: have fun!

- [Building](./doc/BUILD.md): Read this if you're not sure how to build
  `pcloudcc`. For most users, `make` and `make install` are enough.

- [mbedtls 3.x migration notes](./doc/MBEDTLS-3.x.md): Read this if you use an
  older distribution such as `debian:bookworm` and encounter build problems.

- [Device Validation Guide](./doc/DEVICE-VALIDATION.md): Read this if you're
  running `pcloudcc` and encounter device validation-related errors.

- [Usage Guide](./doc/USAGE.md): Read this if you're unsure how to start using
  `pcloudcc`.

- [Log Management Guide](./LOG-MANAGEMENT.md): Read this to configure log rotation,
  cache size limits, and custom log paths. To set up automatic log rotation, copy
  `pcloudcc.logrotate` to `/etc/logrotate.d/pcloudcc`.

- [pcloudcc-service](https://github.com/ibressler/pcloudcc-service): Container-based
  systemd service for running `pcloudcc` in userspace with podman. Includes multi-stage
  Dockerfile that builds `pcloudcc` from source and Quadlet systemd unit for automated
  background syncing.
