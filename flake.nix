{
  description = "pcloudcc-lneely dev environment";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" ];
      perSystem = { config, self', inputs', pkgs, system, ... }: {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bear
            clang-tools
            zlib
            sqlite
            boost
            libudev-zero
            readline
            fuse
            mbedtls
          ];

          CFLAGS = [
            "-I${pkgs.zlib.dev}/include"
            "-I${pkgs.sqlite.dev}/include"
            "-I${pkgs.boost.dev}/include"
            "-I${pkgs.readline.dev}/include"
            "-I${pkgs.fuse.dev}/include"
            "-I${pkgs.mbedtls}/include"
          ];

          CXXFLAGS = [
            "-I${pkgs.zlib.dev}/include"
            "-I${pkgs.sqlite.dev}/include"
            "-I${pkgs.boost.dev}/include"
            "-I${pkgs.readline.dev}/include"
            "-I${pkgs.fuse.dev}/include"
            "-I${pkgs.mbedtls}/include"
          ];

        };
      };
    };
}
