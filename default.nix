let
  pkgs = import <nixpkgs> {};
in
pkgs.mkShell {
  buildInputs = with pkgs; [
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
}
