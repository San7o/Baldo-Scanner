let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-24.05";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

pkgs.mkShell {
  packages = with pkgs; [
    stdenv.cc.cc.lib        # libc
    cmake                   # build system
    doxygen                 # documentation
    valgrind                # memory debugging
    boost                   # C++ libraries
    curlFull                # libcurl
    curlpp                  # C++ wrapper for libcurl
    openssl_3_3             # libressl
    yara                    # malware detection
    sqlite                  # database
    unzip                   # zip file extraction
    libnl.dev               # netlink
    nasm                    # assembler
  ];

  LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.boost}/lib:${pkgs.curlFull}/lib:${pkgs.curlpp}/lib:${pkgs.openssl_3_3}/lib:${pkgs.libnl.dev}/lib";
}
