# Redis writer credential preparation prototype

`redis_auth_prepare.py` is the dormant host-side part of the Redis writer
authentication design. It creates or validates one local security-domain
credential and stages the two forms needed later by clients and Redis ACL
rendering. The host image installs it as `/usr/bin/redis_auth_prepare.py`, but
no service invokes it yet.

## Invocation contract

The eventual root-owned systemd oneshot can use:

```text
redis_auth_prepare.py --domain local-system
```

Normal invocation requires a complete existing generation. It never treats a
missing file or directory as a first boot. A trusted provisioning step must
make the first invocation explicit:

```text
redis_auth_prepare.py --domain local-system --initialize
```

`--initialize` authorizes generation only while the published domain is absent.
If an earlier explicit initialization stopped, repeating the command can resume
an exact, safely owned `.initializing-<domain>` transaction. It does not repair,
replace, or rotate a published domain, so repeating a completed command is
idempotent. The state and runtime roots can be changed with `--state-root` and
`--runtime-root` for tests. The command-line entry point requires UID 0; the
Python API accepts an expected owner solely so unit tests can exercise the same
checks without root.

The normal boot unit must never add `--initialize` and will not resume a staged
initialization. Only a trusted provisioning or first-boot step may create or
resume the staged transaction. That step must run after `/host` is mounted and
before the ordinary no-flag invocation, Redis, and authenticated clients.

The same roots can hold multiple independent domains. Invoke the helper once
for each expected domain. Generation and runtime validation remain isolated by
domain, and a lock on the persistent root serializes concurrent preparation.

## Files created

The default persistent layout is:

```text
/host/redis-auth/                              root:root 0700
  local-system/                               root:root 0700
    active                                    root:root 0600
    generations/                              root:root 0700
      0000000000000001/                       root:root 0700
        manifest.json                         root:root 0600
        writer.secret                         root:root 0400
```

`writer.secret` is exactly 32 operating-system random bytes encoded as 43
canonical, unpadded base64url ASCII bytes, with no trailing newline. This is
the exact format accepted by `RedisAuthConfig`. `active` is a regular file,
never a symlink. The versioned manifest records the schema, domain, generation,
encoding, source, transaction identifier, and SHA-256 digest of the exact
ASCII password Redis clients send.

The derived volatile layout is:

```text
/run/redis-auth/                               root:root 0711
  clients/                                    root:root 0711
    local-system/                             root:root 0700
      writer.secret                           root:root 0400
  server/                                     root:root 0700
    local-system/                             root:root 0700
      writer.sha256                           root:root 0400
```

The clear runtime copy is intended for a later service-specific staging step.
The lowercase hash is the only credential-derived value intended for the
database ACL renderer. The program reports only the domain, active generation,
and whether it initialized or reused state. It does not print the credential or
hash.

During the first explicit initialization, the same complete domain tree is
built under `/host/redis-auth/.initializing-local-system`. The final domain
directory does not exist until the staged tree validates and is atomically
renamed to `local-system`. The hidden sibling is therefore an uncommitted
transaction, while the published domain path is the commit point.

## Failure behavior

Every owned directory and file is checked for its exact type, owner, group,
mode, expected entries, and (for files) single link. Existing symlinks,
hard-linked files, unknown or interrupted generation directories, malformed
encoding, digest mismatch, and a bad active selector cause failure. The runtime
tree is staged only after persistent state passes validation. Because `/run`
contains derived state, securely owned missing artifacts and recognized atomic
write temporaries are reconstructed on the next invocation. Wrong content,
metadata, symlinks, hard links, and unknown runtime entries still fail closed.

New files use exclusive temporary files, `fsync`, and rename. Generation data
and `active` are synchronized inside the deterministic hidden sibling before
the complete domain is published with one directory rename. The state root is
synchronized after that rename. An explicit `--initialize` retry resumes only
exact initialization prefixes and recognized, safely owned write temporaries.
Existing secrets are validated and reused. Unknown entries, bad content or
metadata, symlinks, hard links, multiple temporaries, a published domain plus a
staging sibling, and every other impossible state fail closed.

A published domain is never repaired, even when `--initialize` is repeated. If
it is malformed or its `active` selector is missing, the command fails. This
keeps post-commit damage distinct from a recoverable pre-commit interruption
and prevents recovery from silently replacing a credential that clients may
already use.

Runtime domain directories are completed under deterministic
`.incoming-<domain>` names and atomically renamed into place. If execution stops
between publishing the server hash and client secret, the next invocation
validates the published side and completes only the missing side. Concurrent
first initialization calls safely converge on one persistent credential before
the root-directory lock serializes domain preparation.

This prototype does not implement import, rekey, policy-state floors,
service-group copies, client profile maps, ACL rendering, systemd ordering, or
container mounts. Those components must be added and tested before enabling
authentication in an image.

## Tests

Run the standard-library unit tests from the repository root:

```text
python3 -m unittest discover \
  -s files/image_config/redis-auth/tests \
  -p 'test_*.py' -v
```

The tests use temporary configurable roots and the invoking UID/GID while
asserting the same exact modes and ownership relationships used in production.
They include process-level concurrent initialization, injected persistent and
runtime interruptions, explicit-resume enforcement, and hostile staging
symlink and hard-link cases.
