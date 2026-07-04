# Protobuf helpers over nim-libp2p minprotobuf (ported from nwaku common)
# FEATURE: RLN membership gifter wire codec support

## Minimal port of nwaku's common/protobuf extensions (write3/finish3 +
## typed decode errors) so rpc_codec.nim stays byte-identical to the
## original rln_gifter implementation without any waku dependency.

{.push raises: [].}

import std/options, libp2p/protobuf/minprotobuf, libp2p/varint

export minprotobuf, varint

type
  ProtobufErrorKind* {.pure.} = enum
    DecodeFailure
    MissingRequiredField

  ProtobufError* = object
    case kind*: ProtobufErrorKind
    of DecodeFailure:
      error*: minprotobuf.ProtoError
    of MissingRequiredField:
      field*: string

  ProtobufResult*[T] = Result[T, ProtobufError]

converter toProtobufError*(err: minprotobuf.ProtoError): ProtobufError =
  case err
  of minprotobuf.ProtoError.RequiredFieldMissing:
    ProtobufError(kind: ProtobufErrorKind.MissingRequiredField, field: "unknown")
  else:
    ProtobufError(kind: ProtobufErrorKind.DecodeFailure, error: err)

proc missingRequiredField*(T: type ProtobufError, field: string): T =
  ProtobufError(kind: ProtobufErrorKind.MissingRequiredField, field: field)

proc write3*(proto: var ProtoBuffer, field: int, value: auto) =
  when value is Option:
    if value.isSome():
      proto.write(field, value.get())
  else:
    proto.write(field, value)

proc finish3*(proto: var ProtoBuffer) =
  if proto.buffer.len > 0:
    proto.finish()
  else:
    proto.offset = 0

proc `$`*(err: ProtobufError): string =
  case err.kind
  of ProtobufErrorKind.DecodeFailure:
    $err.error
  of ProtobufErrorKind.MissingRequiredField:
    "MissingRequiredField " & err.field

{.pop.}
