{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/23d72dabcb3b12469f57b37170fcbc1789bd7457";
    nixpkgs-master.url = "github:NixOS/nixpkgs/b28c4999ed71543e71552ccfd0d7e68c581ba7e9";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-master,
      utils,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        pkgs-master = import nixpkgs-master {
          inherit system;
        };

        openssh-src = pkgs.fetchurl {
          url = "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.0p1.tar.gz";
          sha256 = "sha256-AhoucJoO30JQsSVr1anlAEEakN3avqgw7VnO+Q652Fw=";
        };

        # Use nixpkgs libressl with static libraries for pivy linking
        libressl = pkgs.libressl.overrideAttrs (oldAttrs: {
          cmakeFlags = (oldAttrs.cmakeFlags or [ ]) ++ [
            "-DBUILD_SHARED_LIBS=OFF"
          ];
        });

        openssh = pkgs.stdenv.mkDerivation {
          pname = "openssh-pivy";
          version = "10.0p1";

          src = openssh-src;

          patches = [ ./openssh.patch ];

          buildInputs = [ libressl.dev pkgs.zlib ];

          configureFlags = [
            "--disable-security-key"
            "--disable-pkcs11"
            "--with-ssl-dir=${libressl.dev}"
          ];

          CFLAGS = pkgs.lib.concatStringsSep " " [
            "-I${libressl.dev}/include"
            "-I${pkgs.zlib.dev}/include"
            "-Wno-error"
          ];

          LDFLAGS = pkgs.lib.concatStringsSep " " [
            "-L${libressl.out}/lib"
            "-L${pkgs.zlib}/lib"
          ];

          dontBuild = true;

          installPhase = ''
            mkdir -p $out
            cp -r . $out/
          '';
        };

        buildInputs = with pkgs; [
          libbsd
          libedit
          zlib
        ] ++ pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [
          pcsclite
        ];

        nativeBuildInputs = with pkgs; [
          gcc
          gnumake
          pkg-config
          ragel
          curl
          gnutar
          patch
          makeWrapper
        ];

        pivy = pkgs.stdenv.mkDerivation {
          pname = "pivy";
          version = "0.12.1";

          src = ./.;

          inherit buildInputs nativeBuildInputs;

          preBuild = ''
            # Copy openssh to writable directory (Makefile needs to compile and write .o files)
            cp -r ${openssh} openssh
            chmod -R +w openssh

            # Create minimal libressl structure with pre-built library
            mkdir -p libressl/include libressl/crypto/.libs
            ln -sf ${libressl.dev}/include/* libressl/include/
            ln -sf ${libressl.out}/lib/libcrypto.a libressl/crypto/.libs/libcrypto.a

            # Create a no-op Makefile in libressl/crypto
            cat > libressl/crypto/Makefile <<'EOF'
            all:
            	@true
            EOF

            # Touch markers to skip extract/patch/configure steps
            # Make libcrypto.a appear newer than configure marker
            touch .libressl.extract .libressl.patch .libressl.configure
            touch -r ${libressl.out}/lib/libcrypto.a libressl/crypto/.libs/libcrypto.a || true
            touch .openssh.extract .openssh.patch .openssh.configure
          '';

          buildPhase = ''
            runHook preBuild
            make -j$NIX_BUILD_CORES \
              LIBRESSL_INC=${libressl.dev}/include \
              LIBRESSL_LIB=${libressl.out}/lib \
              ZLIB_LIB=${pkgs.zlib}/lib \
              ${pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
                SYSTEM_CFLAGS="-arch ${pkgs.stdenv.hostPlatform.darwinArch}" \
                SYSTEM_LDFLAGS="-arch ${pkgs.stdenv.hostPlatform.darwinArch}"
              ''}
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            install -m 755 pivy-tool $out/bin/.pivy-tool-unwrapped
            install -m 755 pivy-agent $out/bin/.pivy-agent-unwrapped
            install -m 755 pivy-box $out/bin/.pivy-box-unwrapped

            # Create wrapper scripts that preload system pcsclite
            # This is needed on non-NixOS where pcscd version must match client library
            for cmd in pivy-tool pivy-agent pivy-box; do
              cat > $out/bin/$cmd <<WRAPPER
            #!/bin/sh
            for lib in \\
              /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \\
              /usr/lib/aarch64-linux-gnu/libpcsclite.so.1 \\
              /usr/lib/libpcsclite.so.1 \\
              /lib/x86_64-linux-gnu/libpcsclite.so.1 \\
              /lib/libpcsclite.so.1; do
              if [ -e "\$lib" ]; then
                export LD_PRELOAD="\$lib\''${LD_PRELOAD:+:\$LD_PRELOAD}"
                break
              fi
            done
            exec $out/bin/.$cmd-unwrapped "\$@"
            WRAPPER
              chmod +x $out/bin/$cmd
            done
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "PIV tools for YubiKey and similar hardware tokens";
            homepage = "https://github.com/arekinath/pivy";
            license = licenses.mpl20;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };
      in
      {
        packages.default = pivy;
        packages.pivy = pivy;
        packages.libressl = libressl;
        packages.openssh = openssh;

        devShells.default = pkgs.mkShell {
          packages = buildInputs ++ nativeBuildInputs;
        };
      }
    ));
}
