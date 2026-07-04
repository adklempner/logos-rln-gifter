// RLN membership gifter protocol C surface for the mix cbind.
// Companion to libp2p.h (from nim-libp2p-mix cbind) and libp2p_mix_rln.h; all
// are emitted by the combined cbind library. No RLN type crosses this boundary.
#ifndef LIBP2P_GIFTER_H
#define LIBP2P_GIFTER_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p.h"  // libp2p_ctx_t, Libp2pCallback

#ifdef __cplusplus
extern "C" {
#endif

// Host callback invoked (on the libp2p thread) when an AUTHENTICATED gifter
// request arrives and needs on-chain registration. The host must NOT block:
// marshal the work to its own thread, register the membership, and then call
// libp2p_gifter_complete(handle, ...) when done. idCommitmentHex is a 64-char
// lowercase hex string valid only for the duration of this call (copy it).
typedef void (*Libp2pGifterRegisterCallback)(uint64_t handle,
                                             const char *idCommitmentHex,
                                             uint64_t rateLimit, void *userData);

// Mount the gifter protocol (/logos/rln/membership/1.0.0) on the switch,
// alongside mix. mountCb is invoked once mounted (callerRet 0 on success).
// registerCb is invoked for each authenticated allocation request.
//
// config JSON keys:
//   allowlist : array<string>  (0x-hex Ethereum addresses; omit/empty = open,
//                               no authentication required)
//
// Returns 0 if the mount request was dispatched (mountCb reports the result).
int libp2p_gifter_serve(libp2p_ctx_t *ctx, const char *config_json,
                        Libp2pCallback mountCb, void *mountUserData,
                        Libp2pGifterRegisterCallback registerCb,
                        void *registerUserData);

// Complete a pending registration started by registerCb. resultJson is either
//   {"ok":true,"leaf_index":<n>,"config_account":"<id>"}  or
//   {"ok":false,"error":"<message>"}
// Safe to call from any thread. Returns 0 if the handle matched a pending slot.
int libp2p_gifter_complete(uint64_t handle, const char *result_json);

// Request a membership allocation from a gifter. args JSON keys:
//   gifterPeerId     : string (base58 peer id, required)
//   gifterMultiaddr  : string (required)
//   idCommitment     : string (64-char hex, required)
//   rate             : int    (optional, default 100)
//   authType         : string (optional, e.g. "eth-allowlist")
//   authPayload      : string (optional, 130-char hex = 65-byte EIP-191 sig)
// resultCb receives {"leaf_index":<n>,"config_account":"<id>"} on success, or
// an error string on failure. Returns 0 if the request was dispatched.
int libp2p_gifter_request(libp2p_ctx_t *ctx, const char *args_json,
                          Libp2pCallback resultCb, void *resultUserData);

#ifdef __cplusplus
}
#endif

#endif  // LIBP2P_GIFTER_H
