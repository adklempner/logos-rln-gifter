# RLN membership gifter client (dial gifter, request allocation)
# FEATURE: standalone gifter LPProtocol client over switch.dial

## Client side of /logos/rln/membership/1.0.0: dials the gifter by
## peerId+multiaddr, sends the allocation request (identity commitment +
## optional EIP-191 auth payload), and returns the allocated membership.
## Ported from the nwaku rln_gifter client, peer_manager replaced with a
## direct switch.dial.

{.push raises: [].}

import std/[options, sysrand]
import results, chronicles, chronos
import pkg/libp2p
import ./rpc, ./rpc_codec, ./eip191

logScope:
  topics = "rln-gifter client"

type RlnGifterResult* = Result[MembershipAllocationSuccess, string]

proc generateRequestId(): string =
  var bytes: array[16, byte]
  discard urandom(bytes)
  toHexLower(bytes)

proc requestMembership*(
    switch: Switch,
    gifterPeerId: PeerId,
    gifterAddrs: seq[MultiAddress],
    identityCommitment: seq[byte],
    rateLimit: Option[uint64],
    authenticationType: seq[byte] = @[],
    authenticationPayload: seq[byte] = @[],
): Future[RlnGifterResult] {.async.} =
  let request = RlnGifterRequest(
    requestId: generateRequestId(),
    authenticationType: authenticationType,
    authenticationPayload: authenticationPayload,
    identityCommitment: identityCommitment,
    rateLimit: rateLimit,
  )

  info "requesting RLN membership from gifter",
    requestId = request.requestId, identityCommitmentLen = identityCommitment.len

  # Retry dial with backoff (gifter node may still be initializing)
  var stream: Stream
  var dialAttempts = 0
  while true:
    try:
      stream = await switch.dial(gifterPeerId, gifterAddrs, RlnGifterCodec)
      break
    except DialFailedError as exc:
      dialAttempts += 1
      if dialAttempts >= 5:
        return err(
          "failed to dial gifter peer after " & $dialAttempts & " attempts: " & exc.msg
        )
      warn "gifter dial failed, retrying", attempt = dialAttempts, error = exc.msg
      await sleepAsync(seconds(3))

  try:
    await stream.writeLp(request.encode().buffer)
  except LPStreamError:
    return err("failed to write request: " & getCurrentExceptionMsg())

  var buffer: seq[byte]
  try:
    buffer = await stream.readLp(DefaultMaxRpcSize)
  except LPStreamError:
    return err("failed to read response: " & getCurrentExceptionMsg())

  # Do NOT close the stream here. Let it leak and be cleaned up by GC.
  # Closing triggers yamux cleanup that races the FFI boundary's return to
  # the host (known use-after-free crash class in the delivery-module port).

  let response = RlnGifterResponse.decode(buffer).valueOr:
    return err("failed to decode response: " & $error)

  if response.requestId != request.requestId:
    return err("requestId mismatch")

  if not response.authSuccess:
    let desc = response.error.get(
      if response.failure.isSome:
        response.failure.get().errorMessage
      else:
        "authentication failed"
    )
    return err("authentication failed: " & desc)

  if response.failure.isSome:
    return err("registration failed: " & response.failure.get().errorMessage)

  if response.success.isNone:
    return err("response missing success/failure result")
  let success = response.success.get()

  info "RLN membership granted", leafIndex = success.leafIndex

  return ok(success)

{.pop.}
