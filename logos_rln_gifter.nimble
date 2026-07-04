# Package
version = "0.1.0"
author = "Logos"
description = "Standalone RLN membership gifter (allocation) libp2p protocol"
license = "MIT OR Apache-2.0"
srcDir = "src"

# Dependencies
requires "nim >= 2.0.0"
requires "results >= 0.4.0"
requires "chronicles >= 0.11.0"
requires "chronos >= 4.2.2"
requires "nimcrypto >= 0.6.0"
requires "secp256k1 >= 0.5.0"

# nim-libp2p — pinned to the SAME rev libp2p_mix (feat/mix-cbind) uses so a
# single nim-libp2p is in the combined build.
requires "https://github.com/vacp2p/nim-libp2p.git#c43199378f46d0aaf61be1cad1ee1d63e8f665d6"

task test, "Run tests":
  exec "nim c -r tests/test_all.nim"
