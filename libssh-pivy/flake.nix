{
  description = "LibSSH-pivy - OpenSSH library with PIV-specific patches";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/23d72dabcb3b12469f57b37170fcbc1789bd7457";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        openssh-src = pkgs.fetchurl {
          url = "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.0p1.tar.gz";
          sha256 = "sha256-AhoucJoO30JQsSVr1anlAEEakN3avqgw7VnO+Q652Fw=";
        };

        libssh-pivy = pkgs.stdenv.mkDerivation {
          pname = "libssh-pivy";
          version = "10.0p1";

          src = openssh-src;

          patches = [ ./patches/openssh-pivy.patch ];

          buildInputs = [ pkgs.libressl.dev pkgs.zlib ];

          nativeBuildInputs = [ pkgs.pkg-config ];

          configureFlags = [
            "--disable-security-key"
            "--disable-pkcs11"
            "--with-ssl-dir=${pkgs.libressl.dev}"
          ];

          CFLAGS = pkgs.lib.concatStringsSep " " [
            "-I${pkgs.libressl.dev}/include"
            "-I${pkgs.zlib.dev}/include"
            "-Wno-error"
          ];

          LDFLAGS = pkgs.lib.concatStringsSep " " [
            "-L${pkgs.libressl.out}/lib"
            "-L${pkgs.zlib}/lib"
          ];

          # Build only the library files, not the full OpenSSH binaries
          buildPhase = ''
            runHook preBuild

            # Compile only the library objects needed by pivy
            make -j$NIX_BUILD_CORES \
              libssh.a \
              openbsd-compat/libopenbsd-compat.a

            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            # Install headers
            mkdir -p $out/include/libssh-pivy
            cp *.h $out/include/libssh-pivy/
            cp openbsd-compat/*.h $out/include/libssh-pivy/

            # Combine libssh.a and libopenbsd-compat.a into one archive
            mkdir -p $out/lib
            COMBINE_DIR=$(mktemp -d)
            cd "$COMBINE_DIR"
            ar x $NIX_BUILD_TOP/*/libssh.a
            ar x $NIX_BUILD_TOP/*/openbsd-compat/libopenbsd-compat.a
            ar rcs $out/lib/libssh.a *.o
            cd - > /dev/null

            # Also provide separate openbsd-compat for reference
            cp openbsd-compat/libopenbsd-compat.a $out/lib/

            # Clean up
            rm -rf "$COMBINE_DIR"

            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "OpenSSH library with PIV-specific patches for pivy";
            homepage = "https://github.com/arekinath/pivy";
            license = licenses.bsd2;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };
      in
      {
        packages.default = libssh-pivy;
        packages.libssh-pivy = libssh-pivy;
      }
    );
}
