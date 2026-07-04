# C surface for the RLN membership gifter protocol (serve + request)
# FEATURE: gifter cbind superset-linked into the combined libp2p .lgx library

## Exposes libp2p_gifter_serve / libp2p_gifter_request / libp2p_gifter_complete.
## The protocol runs on the libp2p worker thread (mounted on the shared switch
## alongside mix). On-chain registration is delegated to the host via a
## register callback + an async completion (libp2p_gifter_complete), so no
## blocking cross-thread call is made from the libp2p thread into QtRO.
##
## Threading: the cross-thread registration channel uses a fixed array of
## value-type slots guarded by a Lock (no GC object crosses the boundary), the
## same discipline as the mix-rln cbind's lock-protected pointer globals.

{.push raises: [].}

import std/[json, locks, options]
import chronos, chronicles

import ffi_types
import types
import libp2p_thread/libp2p_thread
import libp2p_thread/inter_thread_communication/libp2p_thread_request
import libp2p_thread/inter_thread_communication/requests/libp2p_custom_requests

import pkg/libp2p

import rln_gifter/[rpc, protocol, client, eip191]
import results

logScope:
  topics = "gifter-cbind"

type GifterRegisterCallback* = proc(
  handle: uint64, idCommitmentHex: cstring, rateLimit: uint64, userData: pointer
) {.cdecl, gcsafe, raises: [].}

const
  MaxPending = 32
  ResultCap = 1024

type PendingSlot = object
  handle: uint64
  inUse: bool
  done: bool
  resultLen: int
  resultBuf: array[ResultCap, char]

type ServeData = object
  configJson: cstring
  mountCb: Libp2pCallback
  mountUserData: pointer
  registerCb: GifterRegisterCallback
  registerUserData: pointer

type RequestData = object
  argsJson: cstring
  resultCb: Libp2pCallback
  resultUserData: pointer

var
  gifterLock: Lock
  slots: array[MaxPending, PendingSlot]
  handleCounter: uint64
  serveRegisterCb: GifterRegisterCallback = nil
  serveRegisterUserData: pointer = nil

gifterLock.initLock()

proc dupShared(s: cstring): cstring =
  if s.isNil:
    return nil
  var n = 0
  while s[n] != '\0':
    inc n
  let ret = cast[cstring](allocShared(n + 1))
  copyMem(ret, s, n + 1)
  ret

proc cstrLen(s: cstring): int =
  result = 0
  while s[result] != '\0':
    inc result

proc invokeCb(cb: Libp2pCallback, userData: pointer, ok: bool, msg: string) =
  if cb.isNil:
    return
  let ret = (if ok: RET_OK else: RET_ERR).cint
  foreignThreadGc:
    if msg.len > 0:
      cb(ret, cast[ptr cchar](unsafeAddr msg[0]), csize_t(msg.len), userData)
    else:
      cb(ret, cast[ptr cchar](nil), 0, userData)

proc hexToSeq(hex: string): seq[byte] =
  var h = hex
  if h.len >= 2 and (h[0 .. 1] == "0x" or h[0 .. 1] == "0X"):
    h = h[2 .. ^1]
  if h.len mod 2 != 0:
    return @[]
  result = newSeqOfCap[byte](h.len div 2)
  var i = 0
  while i < h.len:
    let hi = block:
      let c = h[i]
      if c in {'0' .. '9'}: ord(c) - ord('0')
      elif c in {'a' .. 'f'}: ord(c) - ord('a') + 10
      elif c in {'A' .. 'F'}: ord(c) - ord('A') + 10
      else: return @[]
    let lo = block:
      let c = h[i + 1]
      if c in {'0' .. '9'}: ord(c) - ord('0')
      elif c in {'a' .. 'f'}: ord(c) - ord('a') + 10
      elif c in {'A' .. 'F'}: ord(c) - ord('A') + 10
      else: return @[]
    result.add(byte((hi shl 4) or lo))
    i += 2

# --------------------------------------------------------------------------
# Register bridge (RegisterMemberHandler): runs on the libp2p thread. Hands the
# authed request to the host via the register callback and polls a value-type
# slot for the async completion pushed by libp2p_gifter_complete.
# --------------------------------------------------------------------------

proc gifterRegisterBridge(
    identityCommitment: seq[byte], rateLimit: uint64
): Future[Result[MembershipAllocationSuccess, string]] {.async, gcsafe.} =
  gifterLock.acquire()
  let cb = serveRegisterCb
  let ud = serveRegisterUserData
  gifterLock.release()
  if cb.isNil:
    return err("gifter register callback not set")

  var slotIdx = -1
  var handle: uint64 = 0
  gifterLock.acquire()
  inc handleCounter
  handle = handleCounter
  for i in 0 ..< MaxPending:
    if not slots[i].inUse:
      slots[i].handle = handle
      slots[i].inUse = true
      slots[i].done = false
      slots[i].resultLen = 0
      slotIdx = i
      break
  gifterLock.release()
  if slotIdx < 0:
    return err("gifter: too many concurrent registrations")

  let idHex = toHexLower(identityCommitment)
  cb(handle, idHex.cstring, rateLimit, ud)

  const pollMs = 500
  const deadlineMs = 600_000
  var waited = 0
  var resultJson = ""
  var got = false
  while waited < deadlineMs:
    await sleepAsync(chronos.milliseconds(pollMs))
    waited += pollMs
    gifterLock.acquire()
    if slots[slotIdx].handle == handle and slots[slotIdx].done:
      resultJson = newString(slots[slotIdx].resultLen)
      for j in 0 ..< slots[slotIdx].resultLen:
        resultJson[j] = slots[slotIdx].resultBuf[j]
      slots[slotIdx].inUse = false
      slots[slotIdx].done = false
      got = true
    gifterLock.release()
    if got:
      break

  if not got:
    gifterLock.acquire()
    slots[slotIdx].inUse = false
    gifterLock.release()
    return err("gifter: registration timed out")

  try:
    let j = parseJson(resultJson)
    if not j{"ok"}.getBool(false):
      return err(j{"error"}.getStr("registration failed"))
    var success =
      MembershipAllocationSuccess(leafIndex: uint64(j{"leaf_index"}.getInt()))
    if j.hasKey("config_account"):
      success.configAccountId = some(j["config_account"].getStr())
    return ok(success)
  except CatchableError as e:
    return err("gifter: bad completion json: " & e.msg)

# --------------------------------------------------------------------------
# Serve: mount the gifter protocol on the switch (libp2p thread).
# --------------------------------------------------------------------------

proc serveAsync(libp2p: ptr LibP2P, data: pointer) {.async: (raises: []).} =
  let d = cast[ptr ServeData](data)

  var allowlist: seq[string]
  var haveAuth = false
  var parsedOk = true
  var parseErr = ""
  try:
    let j = parseJson($d[].configJson)
    if j.hasKey("allowlist"):
      for a in j["allowlist"]:
        allowlist.add(a.getStr())
      haveAuth = allowlist.len > 0
  except CatchableError as e:
    parsedOk = false
    parseErr = e.msg

  block work:
    if not parsedOk:
      invokeCb(d[].mountCb, d[].mountUserData, false,
        "bad config json: " & parseErr)
      break work

    gifterLock.acquire()
    serveRegisterCb = d[].registerCb
    serveRegisterUserData = d[].registerUserData
    gifterLock.release()

    let auth =
      if haveAuth:
        some(newEthAllowlistAuth(allowlist))
      else:
        none(EthAllowlistAuth)
    let gifter = RlnGifter.new(gifterRegisterBridge, auth)

    var okMount = true
    var errMsg = ""
    try:
      await gifter.start()
      libp2p[].switch.mount(gifter)
      libp2p[].customProtocols[RlnGifterCodec] = gifter
      if haveAuth:
        info "RLN gifter allowlist auth enabled", entries = allowlist.len
      info "RLN gifter service mounted for mix", codec = RlnGifterCodec
    except CancelledError:
      okMount = false
      errMsg = "cancelled"
    except CatchableError as e:
      okMount = false
      errMsg = e.msg

    invokeCb(d[].mountCb, d[].mountUserData, okMount,
      if okMount: "mounted" else: errMsg)

  if not d[].configJson.isNil:
    deallocShared(d[].configJson)
  deallocShared(d)

proc serveTask(libp2p: ptr LibP2P, data: pointer) {.nimcall, gcsafe, raises: [].} =
  asyncSpawn serveAsync(libp2p, data)

# --------------------------------------------------------------------------
# Request: dial the gifter and request an allocation (libp2p thread).
# --------------------------------------------------------------------------

proc requestAsync(libp2p: ptr LibP2P, data: pointer) {.async: (raises: []).} =
  let d = cast[ptr RequestData](data)

  var gifterPeerId, gifterMaddr, idHex, authKeyHex: string
  var rate: uint64 = 100
  var parsedOk = true
  var parseErr = ""
  try:
    let j = parseJson($d[].argsJson)
    gifterPeerId = j["gifterPeerId"].getStr()
    gifterMaddr = j["gifterMultiaddr"].getStr()
    idHex = j["idCommitment"].getStr()
    if j.hasKey("rate"):
      rate = uint64(j["rate"].getInt())
    if j.hasKey("authKey"):
      authKeyHex = j["authKey"].getStr()
  except CatchableError as e:
    parsedOk = false
    parseErr = e.msg

  block work:
    if not parsedOk:
      invokeCb(d[].resultCb, d[].resultUserData, false, "bad args: " & parseErr)
      break work

    let peerId = PeerId.init(gifterPeerId).valueOr:
      invokeCb(d[].resultCb, d[].resultUserData, false, "bad gifter peerId")
      break work
    let maddr = MultiAddress.init(gifterMaddr).valueOr:
      invokeCb(d[].resultCb, d[].resultUserData, false, "bad gifter multiaddr")
      break work

    let idBytes = hexToSeq(idHex)
    if idBytes.len != 32:
      invokeCb(d[].resultCb, d[].resultUserData, false, "idCommitment must be 32 bytes")
      break work

    # Sign the EIP-191 auth payload over the idCommitment with the provided
    # private key. The RLN secret never enters this path — only the commitment
    # is signed and sent.
    var authTypeBytes, authPayloadBytes: seq[byte]
    if authKeyHex.len > 0:
      let sig = signEip191(idBytes, authKeyHex).valueOr:
        invokeCb(d[].resultCb, d[].resultUserData, false, "auth signing failed: " & error)
        break work
      authPayloadBytes = sig
      for c in EthAllowlistAuthType:
        authTypeBytes.add(byte(c))

    let res =
      try:
        await requestMembership(
          libp2p[].switch, peerId, @[maddr], idBytes, some(rate), authTypeBytes,
          authPayloadBytes,
        )
      except CancelledError:
        RlnGifterResult.err("cancelled")
      except CatchableError as e:
        RlnGifterResult.err("request failed: " & e.msg)

    if res.isErr:
      invokeCb(d[].resultCb, d[].resultUserData, false, res.error)
      break work

    let s = res.get()
    let outJson =
      %*{"leaf_index": s.leafIndex, "config_account": s.configAccountId.get("")}
    invokeCb(d[].resultCb, d[].resultUserData, true, $outJson)

  if not d[].argsJson.isNil:
    deallocShared(d[].argsJson)
  deallocShared(d)

proc requestTask(libp2p: ptr LibP2P, data: pointer) {.nimcall, gcsafe, raises: [].} =
  asyncSpawn requestAsync(libp2p, data)

# --------------------------------------------------------------------------
# Exported C functions.
# --------------------------------------------------------------------------

# Same rule as the plugin cbind: the mix cbind owns the Nim runtime in the
# superset library; every exported proc must register the calling (host)
# thread with the GC before allocating.
when appType == "lib" or appType == "staticlib":
  proc mixCbindInitializeLibrary() {.importc: "initializeLibrary", cdecl, raises: [].}
else:
  # Executables (unit tests) run NimMain at startup and use Nim-managed
  # threads, so no foreign-thread registration is needed.
  proc mixCbindInitializeLibrary() {.raises: [].} =
    discard

proc libp2p_gifter_serve*(
    ctx: ptr LibP2PContext,
    configJson: cstring,
    mountCb: Libp2pCallback,
    mountUserData: pointer,
    registerCb: GifterRegisterCallback,
    registerUserData: pointer,
): cint {.dynlib, exportc, cdecl.} =
  mixCbindInitializeLibrary()
  if ctx.isNil:
    return RET_ERR.cint
  let d = cast[ptr ServeData](allocShared0(sizeof(ServeData)))
  d[].configJson = dupShared(configJson)
  d[].mountCb = mountCb
  d[].mountUserData = mountUserData
  d[].registerCb = registerCb
  d[].registerUserData = registerUserData

  let sendRes = sendRequestToLibP2PThread(
    ctx, RequestType.CUSTOM, CustomRequest.createShared(serveTask, d),
    cast[Libp2pCallback](nil), nil,
  )
  if sendRes.isErr:
    if not d[].configJson.isNil:
      deallocShared(d[].configJson)
    deallocShared(d)
    return RET_ERR.cint
  return RET_OK.cint

proc libp2p_gifter_request*(
    ctx: ptr LibP2PContext,
    argsJson: cstring,
    resultCb: Libp2pCallback,
    resultUserData: pointer,
): cint {.dynlib, exportc, cdecl.} =
  mixCbindInitializeLibrary()
  if ctx.isNil or resultCb.isNil:
    return RET_ERR.cint
  let d = cast[ptr RequestData](allocShared0(sizeof(RequestData)))
  d[].argsJson = dupShared(argsJson)
  d[].resultCb = resultCb
  d[].resultUserData = resultUserData

  let sendRes = sendRequestToLibP2PThread(
    ctx, RequestType.CUSTOM, CustomRequest.createShared(requestTask, d),
    cast[Libp2pCallback](nil), nil,
  )
  if sendRes.isErr:
    if not d[].argsJson.isNil:
      deallocShared(d[].argsJson)
    deallocShared(d)
    return RET_ERR.cint
  return RET_OK.cint

proc libp2p_gifter_complete*(
    handle: uint64, resultJson: cstring
): cint {.dynlib, exportc, cdecl.} =
  ## Called by the host (Qt thread) after register_member confirms on-chain.
  ## resultJson: {"ok":true,"leaf_index":N,"config_account":"..."} or
  ## {"ok":false,"error":"..."}. Copied into a value-type slot under the lock
  ## (no GC object crosses the boundary).
  mixCbindInitializeLibrary()
  if resultJson.isNil:
    return RET_ERR.cint
  let n = min(cstrLen(resultJson), ResultCap - 1)
  var found = false
  gifterLock.acquire()
  for i in 0 ..< MaxPending:
    if slots[i].inUse and not slots[i].done and slots[i].handle == handle:
      for j in 0 ..< n:
        slots[i].resultBuf[j] = resultJson[j]
      slots[i].resultLen = n
      slots[i].done = true
      found = true
      break
  gifterLock.release()
  if found: RET_OK.cint else: RET_ERR.cint

{.pop.}
