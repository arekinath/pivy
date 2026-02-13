{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/23d72dabcb3b12469f57b37170fcbc1789bd7457";
    nixpkgs-master.url = "github:NixOS/nixpkgs/b28c4999ed71543e71552ccfd0d7e68c581ba7e9";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";
    libssh-pivy.url = "path:./libssh-pivy";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-master,
      utils,
      libssh-pivy,
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

        # Use nixpkgs libressl with static libraries for pivy linking
        libressl = pkgs.libressl.overrideAttrs (oldAttrs: {
          cmakeFlags = (oldAttrs.cmakeFlags or [ ]) ++ [
            "-DBUILD_SHARED_LIBS=OFF"
          ];
        });

        buildInputs = with pkgs; [
          libbsd
          libedit
          zlib
          libssh-pivy.packages.${system}.default
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

            # Create openssh directory with pre-built libssh-pivy
            mkdir -p openssh/openbsd-compat
            cp -r ${libssh-pivy.packages.${system}.default}/include/libssh-pivy/* openssh/
            cp ${libssh-pivy.packages.${system}.default}/lib/libssh.a openssh/libssh.a
            cp ${libssh-pivy.packages.${system}.default}/lib/libopenbsd-compat.a openssh/openbsd-compat/libopenbsd-compat.a || true

            # Touch markers to skip openssh extract/patch/configure
            touch .openssh.extract .openssh.patch .openssh.configure

            # Create dummy .c files that Makefile expects
            # These won't be compiled if libssh.a is up-to-date
            cat > openssh/dummy.c <<'DUMMY'
            // Dummy file - libssh.a is pre-built from libssh-pivy
            DUMMY

            # Main sources from _LIBSSH_SOURCES
            for src in sshbuf.c sshbuf-getput-basic.c sshbuf-getput-crypto.c sshbuf-misc.c \
                       sshkey.c ssh-ed25519.c ssh-ecdsa.c ssh-rsa.c ssh-dss.c \
                       cipher.c cipher-chachapoly.c cipher-chachapoly-libcrypto.c \
                       digest-openssl.c atomicio.c hmac.c authfd.c misc.c match.c \
                       ssh-sk.c log.c fatal.c xmalloc.c addrmatch.c addr.c; do
              cp openssh/dummy.c "openssh/$src"
            done

            # _ED25519_SOURCES
            for src in ed25519.c hash.c; do
              cp openssh/dummy.c "openssh/$src"
            done

            # _CHAPOLY_SOURCES
            for src in chacha.c poly1305.c; do
              cp openssh/dummy.c "openssh/$src"
            done

            # _OBSD_COMPAT
            for src in blowfish.c bcrypt_pbkdf.c base64.c bsd-setres_id.c vis.c \
                       bsd-poll.c timingsafe_bcmp.c reallocarray.c recallocarray.c \
                       explicit_bzero.c; do
              cp openssh/dummy.c "openssh/openbsd-compat/$src"
            done

            # Make libssh.a appear MUCH newer than all source files so make doesn't rebuild it
            # Touch it far in the future
            touch -t 203801010000 openssh/libssh.a
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
        packages.libssh-pivy = libssh-pivy.packages.${system}.default;

        devShells.default = pkgs.mkShell {
          packages = buildInputs ++ nativeBuildInputs;
        };
      }
    ));
}
