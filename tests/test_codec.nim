# Protobuf codec round-trip tests for the gifter allocation messages
# FEATURE: gifter wire codec test coverage

{.push raises: [].}

import std/[options, unittest]
import results
import ../src/rln_gifter/[rpc, rpc_codec]

proc seqBytes(n: int, fill: byte): seq[byte] =
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = fill

suite "gifter rpc codec":
  test "request round-trips (with auth + rate)":
    let req = RlnGifterRequest(
      requestId: "abc123",
      authenticationType: @[byte(ord('e')), byte(ord('t')), byte(ord('h'))],
      authenticationPayload: seqBytes(65, 0x7),
      identityCommitment: seqBytes(32, 0xAB),
      rateLimit: some(100'u64),
    )
    let decoded = RlnGifterRequest.decode(req.encode().buffer).get()
    check decoded.requestId == req.requestId
    check decoded.authenticationType == req.authenticationType
    check decoded.authenticationPayload == req.authenticationPayload
    check decoded.identityCommitment == req.identityCommitment
    check decoded.rateLimit == req.rateLimit

  test "request round-trips (no auth, no rate)":
    let req = RlnGifterRequest(
      requestId: "r2", identityCommitment: seqBytes(32, 0x1)
    )
    let decoded = RlnGifterRequest.decode(req.encode().buffer).get()
    check decoded.requestId == "r2"
    check decoded.identityCommitment == req.identityCommitment
    check decoded.rateLimit.isNone

  test "success response round-trips with configAccountId (tag 100)":
    let success = MembershipAllocationSuccess(
      leafIndex: 42'u64,
      merkleRoot: seqBytes(32, 0x9),
      blockNumber: 1234'u64,
      transactionHash: seqBytes(32, 0x5),
      configAccountId: some("FUhP8quu5WKEL33oALSgDnXq9JZ8Qx72en7zSrzmPrDC"),
    )
    let resp = RlnGifterResponse(
      requestId: "r3", authSuccess: true, success: some(success)
    )
    let decoded = RlnGifterResponse.decode(resp.encode().buffer).get()
    check decoded.requestId == "r3"
    check decoded.authSuccess
    check decoded.success.isSome
    let s = decoded.success.get()
    check s.leafIndex == 42'u64
    check s.blockNumber == 1234'u64
    check s.configAccountId == some("FUhP8quu5WKEL33oALSgDnXq9JZ8Qx72en7zSrzmPrDC")

  test "failure response round-trips":
    let resp = RlnGifterResponse(
      requestId: "r4",
      authSuccess: false,
      error: some("address not allowlisted: 0xdead"),
      failure: some(MembershipAllocationFailure(
        errorMessage: "address not allowlisted: 0xdead"
      )),
    )
    let decoded = RlnGifterResponse.decode(resp.encode().buffer).get()
    check not decoded.authSuccess
    check decoded.error == some("address not allowlisted: 0xdead")
    check decoded.failure.get().errorMessage == "address not allowlisted: 0xdead"

{.pop.}
