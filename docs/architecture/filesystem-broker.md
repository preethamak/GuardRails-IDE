# Filesystem broker slice

## Completed behavior

The first vertical security slice takes a request from a real CLI through policy
evaluation, audit recording, capability-confined filesystem access, and output. The
broker opens a workspace directory once during trusted bootstrap and performs later
reads relative to that directory authority. It never joins user input to an ambient
host path.

The current read operation:

1. validates the `workspace/<relative-path>` resource format;
2. evaluates principal, workspace, capability, action, glob, deny, approval, and
   expiration policy;
3. records a secret-safe authorization event and fails closed if recording fails;
4. rejects absolute, parent-relative, dot, empty-segment, and backslash paths;
5. opens through `cap-std`, which prevents a symlink from escaping the directory
   authority;
6. requires a regular file and enforces a configured byte limit before returning data.

Tests execute allowed reads, default/explicit denial, approval gating, malformed-path
attacks, symlink escape, oversized files, audit failure, and the packaged CLI. The CLI
also installs explicit root and nested `.env*` deny rules so a broad demo allow cannot
print an environment file.

## Security boundary

This slice deliberately supports reads only. Adding writes safely requires temporary
files, no-follow destination traversal, atomic replacement, permission preservation,
review-digest binding, and rollback semantics. Those controls will be implemented and
tested together rather than exposing a partial write API.

The in-memory audit sink is for development and tests. A production sink must be a
separate append-only writer with authenticated IPC, chained hashes, bounded metadata,
backpressure behavior, and organization export. The `AuditSink` interface already
causes sink failure to stop access.

## Next slice

The next vertical slice is authenticated, versioned broker IPC. It will move requests
out of the caller's process, bind each connection to a supervisor-issued principal,
enforce message and concurrency limits, and prove that a client cannot claim another
principal identity. Only then will the editor shell call this filesystem broker.
