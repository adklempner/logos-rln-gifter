# RLN membership allocation message types (LIP-158 wire format)
# FEATURE: RLN membership gifter request/response RPC

## Ported verbatim from the nwaku rln_gifter implementation. The tag-100
## configAccountId field on MembershipAllocationSuccess is a non-spec
## extension: the LEZ config account that owns the membership, required so
## the client can route on-chain queries.

import std/options

type
  MembershipAllocationSuccess* = object
    leafIndex*: uint64
    merkleRoot*: seq[byte]
    blockNumber*: uint64
    transactionHash*: seq[byte]
    configAccountId*: Option[string]

  MembershipAllocationFailure* = object
    errorMessage*: string

  RlnGifterRequest* = object
    requestId*: string
    authenticationType*: seq[byte]
    authenticationPayload*: seq[byte]
    identityCommitment*: seq[byte]
    rateLimit*: Option[uint64]

  RlnGifterResponse* = object
    requestId*: string
    authSuccess*: bool
    error*: Option[string]
    success*: Option[MembershipAllocationSuccess]
    failure*: Option[MembershipAllocationFailure]

const
  EthAllowlistAuthType* = "eth-allowlist"
  RlnGifterCodec* = "/logos/rln/membership/1.0.0"
