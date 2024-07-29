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
  ];

  LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib:";
}
