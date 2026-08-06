# Authenticated broker IPC slice

## Completed protocol

The filesystem read flow can now cross a real Unix domain socket using bounded,
length-delimited JSON frames. This is a narrow protocol rather than serialized
internal Rust types. Each request contains only a protocol version, request ID,
session token, normalized resource, and trusted-clock timestamp.

Principal identity, workspace identity, capability, and action are deliberately not
client-controlled fields. The supervisor creates a `BrokerSession` after sandbox
startup and binds those attributes to the connection. Unknown JSON fields are
rejected, so a client cannot add a `principal_id` and ask the policy engine to evaluate
it as a more privileged extension or agent.

Before dispatch, the session:

1. rejects unsupported protocol versions;
2. compares a fixed-size, high-entropy session token in constant time;
3. constructs the complete policy request from supervisor-bound identity;
4. calls the confined filesystem broker;
5. returns file bytes as base64 or a stable, non-secret error code.

Frames use a four-byte big-endian length and default to a 64 KiB maximum. The receiver
checks the advertised length before allocating the payload. Truncated and malformed
frames terminate the request instead of reaching the broker.

## Current boundary and deployment requirements

The library proves protocol behavior using an actual Unix socket pair, but it does not
yet create a persistent public listener. The supervisor must create sockets inside a
private runtime directory, verify peer OS credentials, set owner-only permissions,
generate session tokens from the OS CSPRNG, rate-limit authentication failures, and
delete sockets during revocation. Session tokens are defense in depth, not a
replacement for peer credentials and filesystem permissions.

One request per test connection is intentional for this slice. A production server
needs bounded concurrent sessions, idle/read/write deadlines, cancellation, request ID
replay protection, graceful revocation, and a handshake that negotiates only supported
versions. Those controls belong in the supervisor runtime, not in the editor process.

## Next slice

The next slice is the supervisor-owned Unix listener and session lifecycle: secure
socket creation, peer credential verification, CSPRNG token issuance, concurrency and
deadline enforcement, revocation, and multi-request replay protection.
