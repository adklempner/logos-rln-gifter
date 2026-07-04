# EIP-191 personal_sign over the RLN identity commitment (gifter client auth)
# FEATURE: RLN membership gifter authentication primitives

## Sign/recover an EIP-191 "personal_sign" message wrapping the lowercase hex
## of the 32-byte RLN identity commitment. Byte-compatible with the original
## nwaku rln_gifter implementation (nim-eth keys): 65-byte recoverable
## signature r||s||recid, keccak256 message hash, 20-byte Ethereum address.
## Used ONLY for client<->gifter authentication — RLN proofs are untouched.

{.push raises: [].}

import results
import secp256k1
import nimcrypto/[keccak, hash]

type EthAddress* = array[20, byte]

proc toHexLower*(b: openArray[byte]): string =
  result = newStringOfCap(b.len * 2)
  const digits = "0123456789abcdef"
  for x in b:
    result.add(digits[int(x shr 4)])
    result.add(digits[int(x and 0x0f)])

proc to0xHex*(a: EthAddress): string =
  "0x" & toHexLower(a)

proc eip191Message*(idCommitment: openArray[byte]): seq[byte] =
  ## The EIP-191 personal_sign envelope wraps the lowercase hex representation
  ## of the 32-byte identity commitment. Hex is used (rather than raw bytes)
  ## so the signed message is human-readable in wallets that surface it.
  let hex = toHexLower(idCommitment)
  let prefix = "\x19Ethereum Signed Message:\n" & $hex.len
  result = newSeqOfCap[byte](prefix.len + hex.len)
  for c in prefix:
    result.add(byte(c))
  for c in hex:
    result.add(byte(c))

proc eip191Hash(idCommitment: openArray[byte]): SkResult[SkMessage] =
  let digest = keccak256.digest(eip191Message(idCommitment))
  SkMessage.fromBytes(digest.data)

proc pubkeyToAddress(pub: SkPublicKey): EthAddress =
  let raw = pub.toRaw() # 65 bytes: 0x04 || X || Y
  let digest = keccak256.digest(raw.toOpenArray(1, 64))
  for i in 0 ..< 20:
    result[i] = digest.data[12 + i]

proc signEip191*(
    idCommitment: openArray[byte], privKeyHex: string
): Result[seq[byte], string] =
  ## 65-byte recoverable signature (r||s||recid) over the EIP-191 envelope.
  let key = SkSecretKey.fromHex(privKeyHex).valueOr:
    return err("invalid secp256k1 private key: " & $error)
  let msg = eip191Hash(idCommitment).valueOr:
    return err("failed to hash message: " & $error)
  ok(@(signRecoverable(key, msg).toRaw()))

proc verifyEip191*(
    idCommitment: openArray[byte], sigBytes: openArray[byte]
): Result[EthAddress, string] =
  ## Recover the signer's Ethereum address from a 65-byte recoverable sig.
  if sigBytes.len != 65:
    return err("signature must be 65 bytes, got " & $sigBytes.len)
  let sig = SkRecoverableSignature.fromRaw(sigBytes).valueOr:
    return err("invalid signature encoding: " & $error)
  let msg = eip191Hash(idCommitment).valueOr:
    return err("failed to hash message: " & $error)
  let pub = recover(sig, msg).valueOr:
    return err("signature recovery failed: " & $error)
  ok(pubkeyToAddress(pub))

proc addressOfKey*(privKeyHex: string): Result[EthAddress, string] =
  ## Ethereum address of a secp256k1 private key (for tests/fixtures).
  let key = SkSecretKey.fromHex(privKeyHex).valueOr:
    return err("invalid secp256k1 private key: " & $error)
  ok(pubkeyToAddress(key.toPublicKey()))

{.pop.}
