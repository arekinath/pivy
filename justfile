build:
  nix build

# Verify static LibreSSL libraries exist
test-libressl:
  nix build .#libressl
  @test -f result/lib/libcrypto.a && echo "✓ Static libcrypto.a found" || echo "✗ Static libcrypto.a missing"
  @test -f result/lib/libssl.a && echo "✓ Static libssl.a found" || echo "✗ Static libssl.a missing"
  @test -f result/lib/libtls.a && echo "✓ Static libtls.a found" || echo "✗ Static libtls.a missing"
