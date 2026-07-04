# EIP-191 sign/recover known-answer tests against the gifter fixtures
# FEATURE: gifter authentication test coverage

{.push raises: [].}

import std/unittest
import results
import ../src/rln_gifter/eip191

# Known key/address pairs from
# logos-chat/simulations/mix_lez_chat/fixtures/gifter_auth (NOT FOR PRODUCTION).
const
  KeyMix1 = "2c974e0a453f65dd2230d403f6981fc18f9a3ad7675afb647910e0798a3eaa4f"
  AddrMix1 = "0x8ba6d3237e6f2c84b0e3d71aa57bc5869d3b5218"
  KeySender = "5284ac01fed5fcb6b26933ac4a901412b66fcd7ee5b945b799f147a3b42f49ef"
  AddrSender = "0x0b6872aaae7a2d4f3c701793cde57b93337f4d4a"

proc bytes32(fill: byte): seq[byte] =
  result = newSeq[byte](32)
  for i in 0 ..< 32:
    result[i] = fill

suite "eip191 gifter auth":
  test "address derivation matches fixtures":
    check addressOfKey(KeyMix1).get().to0xHex() == AddrMix1
    check addressOfKey(KeySender).get().to0xHex() == AddrSender

  test "sign then recover round-trips to signer address":
    let idc = bytes32(0xAB)
    let sig = signEip191(idc, KeyMix1).get()
    check sig.len == 65
    let recovered = verifyEip191(idc, sig).get()
    check recovered.to0xHex() == AddrMix1

  test "recovery over a different commitment yields a different signer":
    let idcA = bytes32(0x11)
    let idcB = bytes32(0x22)
    let sig = signEip191(idcA, KeySender).get()
    # Correct commitment recovers the sender address.
    check verifyEip191(idcA, sig).get().to0xHex() == AddrSender
    # A different commitment recovers some OTHER address (not the sender).
    let other = verifyEip191(idcB, sig)
    check (other.isErr or other.get().to0xHex() != AddrSender)

  test "wrong-length signature is rejected":
    let idc = bytes32(0x01)
    check verifyEip191(idc, @[byte 1, 2, 3]).isErr

{.pop.}
