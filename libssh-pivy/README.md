# libssh-pivy

OpenSSH library with PIV-specific patches for the pivy project.

## Overview

This is a vendored version of OpenSSH 10.0p1 with PIV-specific patches applied. It provides the SSH buffer management, key handling, and cryptographic functions needed by pivy to interact with PIV cards.

## Patches

The `patches/openssh-pivy.patch` file contains ~787 lines of modifications across 16 OpenSSH source files:

1. **8-bit String Encoding** (sshbuf-getput-basic.c, ~200 lines)
   - Adds `sshbuf_get_string8()`, `sshbuf_put_string8()` and variants
   - PIV uses compact 8-bit length prefixes instead of SSH's standard 32-bit encoding

2. **Compressed EC Point Support** (sshbuf-getput-crypto.c, ~72 lines)
   - Adds `sshbuf_get_eckey8()`, `sshbuf_put_eckey8()`
   - PIV cards use compressed EC points (0x02/0x03 prefix) unlike standard SSH (0x04 prefix)

3. **Key/Signature Conversion** (sshkey.c, ~415 lines)
   - `sshkey_from_evp_pkey()` - Convert OpenSSL EVP_PKEY to OpenSSH sshkey
   - `sshkey_sig_from_asn1()` - Convert ASN.1 DER signatures to SSH wire format
   - `sshkey_sig_to_asn1()` - Convert SSH signatures to ASN.1 DER format
   - Bridges between X.509/PKCS#11 (PIV) and SSH key/signature formats

4. **Agent Protocol Extensions** (authfd.h/c, ~10 lines)
   - Exposes `ssh_request_reply()` as public API
   - Adds `SSH_AGENT_EXT_FAILURE` constant

5. **Portability Fixes** (~90 lines)
   - arc4random_stir() compatibility
   - closefrom() guards
   - Digest enum instead of #defines
   - Cipher name adjustments

## Building

This package is built automatically as part of the pivy build process:

```bash
nix build .#libssh-pivy
```

## Outputs

- `$out/include/libssh-pivy/*.h` - OpenSSH headers
- `$out/lib/libssh.a` - Static library with all OpenSSH functionality
- `$out/lib/libopenbsd-compat.a` - OpenBSD compatibility functions

## Future Migration

This is Phase 1 of a two-phase migration to use nixpkgs OpenSSH:

- **Phase 1 (current)**: Vendor OpenSSH with patches in separate subproject
- **Phase 2 (planned)**: Implement compatibility shim layer to use unpatched nixpkgs OpenSSH

See the main project's migration plan for details.
