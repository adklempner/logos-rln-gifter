# RLN membership gifter libp2p protocol (server side, LIP-158 allocation)
# FEATURE: standalone gifter LPProtocol mounted alongside mix

## Serves /logos/rln/membership/1.0.0: authenticates a client's EIP-191
## signature over its RLN identity commitment against an allowlist (one-shot
## per address), then delegates the on-chain registration to a host-provided
## handler and returns the allocated leaf. Ported from the nwaku rln_gifter
## protocol, waku deps replaced with plain nim-libp2p.

{.push raises: [].}

import std/[options, sets]
import results, chronicles, chronos
import pkg/libp2p
import ./rpc, ./rpc_codec, ./eip191

export rpc

logScope:
  topics = "rln-gifter"

type
  RegisterMemberHandler* = proc(
    identityCommitment: seq[byte], rateLimit: uint64
  ): Future[Result[MembershipAllocationSuccess, string]] {.async, gcsafe.}

  EthAllowlistAuth* = ref object
    addresses*: HashSet[string] ## lowercase 0x-hex Ethereum addresses
    consumed*: HashSet[string] ## one membership per authenticated address

  RlnGifter* = ref object of LPProtocol
    registerHandler*: RegisterMemberHandler
    auth*: Option[EthAllowlistAuth]

proc newEthAllowlistAuth*(addresses: openArray[string]): EthAllowlistAuth =
  var normalized = initHashSet[string]()
  for a in addresses:
    var lower = newStringOfCap(a.len)
    for c in a:
      lower.add(if c in {'A' .. 'F'}: char(ord(c) + 32) else: c)
    normalized.incl(lower)
  EthAllowlistAuth(addresses: normalized, consumed: initHashSet[string]())

proc failureResponse(
    requestId: string, authSuccess: bool, message: string
): RlnGifterResponse =
  RlnGifterResponse(
    requestId: requestId,
    authSuccess: authSuccess,
    error: some(message),
    failure: some(MembershipAllocationFailure(errorMessage: message)),
  )

proc handleRequest(
    wg: RlnGifter, peerId: PeerId, buffer: seq[byte]
): Future[RlnGifterResponse] {.async.} =
  let request = RlnGifterRequest.decode(buffer).valueOr:
    error "failed to decode RLN gifter request", error = $error
    return failureResponse("N/A", false, "decode error: " & $error)

  info "handling RLN gifter request",
    peerId = peerId,
    requestId = request.requestId,
    identityCommitment =
      toHexLower(request.identityCommitment)[
        0 .. min(15, max(0, request.identityCommitment.len * 2 - 1))
      ] & "..."

  if request.identityCommitment.len != 32:
    return failureResponse(request.requestId, true, "identity_commitment must be 32 bytes")

  var authorizedSigner: Option[string]
  if wg.auth.isSome:
    let auth = wg.auth.get()
    let authType = block:
      var s = newStringOfCap(request.authenticationType.len)
      for b in request.authenticationType:
        s.add(char(b))
      s
    if authType != EthAllowlistAuthType:
      return failureResponse(
        request.requestId, false, "unsupported authentication_type: '" & authType & "'"
      )
    if request.authenticationPayload.len == 0:
      return failureResponse(request.requestId, false, "missing authentication_payload")
    let signer = verifyEip191(
      request.identityCommitment, request.authenticationPayload
    ).valueOr:
      return failureResponse(
        request.requestId, false, "signature verification failed: " & error
      )
    let signerHex = signer.to0xHex()
    if signerHex notin auth.addresses:
      return failureResponse(
        request.requestId, false, "address not allowlisted: " & signerHex
      )
    if signerHex in auth.consumed:
      return failureResponse(request.requestId, false, "address already used: " & signerHex)
    authorizedSigner = some(signerHex)

  let effectiveRateLimit = request.rateLimit.get(100'u64)
  let success = (
    await wg.registerHandler(request.identityCommitment, effectiveRateLimit)
  ).valueOr:
    error "RLN gifter registration failed", error = error
    return RlnGifterResponse(
      requestId: request.requestId,
      authSuccess: true,
      failure: some(MembershipAllocationFailure(errorMessage: error)),
    )

  if authorizedSigner.isSome and wg.auth.isSome:
    wg.auth.get().consumed.incl(authorizedSigner.get())

  info "RLN gifter registration succeeded",
    leafIndex = success.leafIndex, requestId = request.requestId

  return RlnGifterResponse(
    requestId: request.requestId, authSuccess: true, success: some(success)
  )

proc initProtocolHandler(wg: RlnGifter) =
  proc handler(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    var rpc: RlnGifterResponse
    # NOTE: Do NOT close the stream from the server side. The client closes
    # its side after reading the response. If the server closes first, the
    # remote FIN triggers yamux cleanup races on the client side (known
    # use-after-free crash class in the FFI host process).

    var buffer: seq[byte]
    try:
      buffer = await stream.readLp(DefaultMaxRpcSize)
    except LPStreamError:
      error "rln-gifter read stream failed", error = getCurrentExceptionMsg()
      return

    try:
      rpc = await wg.handleRequest(stream.peerId, buffer)
    except CancelledError as exc:
      raise exc
    except CatchableError:
      error "rln-gifter handleRequest failed", error = getCurrentExceptionMsg()
      rpc = failureResponse("N/A", true, "internal error")

    try:
      await stream.writeLp(rpc.encode().buffer)
    except LPStreamError:
      error "rln-gifter write stream failed", error = getCurrentExceptionMsg()

  wg.handler = handler
  wg.codec = RlnGifterCodec

proc new*(
    T: type RlnGifter,
    registerHandler: RegisterMemberHandler,
    auth: Option[EthAllowlistAuth] = none(EthAllowlistAuth),
): T =
  let wg = RlnGifter(registerHandler: registerHandler, auth: auth)
  wg.initProtocolHandler()
  return wg

{.pop.}
