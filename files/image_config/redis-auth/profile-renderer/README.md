# Redis host client-profile renderer prototype

`redis_client_profile_renderer.py` creates the non-secret profile map consumed
by `RedisAuthConfig.fromProfile("local-system")`. The host image installs this
dormant prototype as `/usr/bin/redis_client_profile_renderer.py`, but no
service invokes it and no container receives its output yet.

The output is `/run/redis-auth/client-profiles.json`, owned by `root:root` with
mode `0444`. Its fixed profile contains:

- user `sonic-trusted-writer`;
- security domain `local-system`;
- credential path
  `/run/redis-auth/clients/local-system/writer.secret`; and
- exact TCP and Unix endpoints from the finalized database maps.

The renderer checks the credential file's owner, type, link count, and mode,
but never opens it. It never reads the server-side hash.

An instance with a nonzero Redis port contributes both its TCP endpoint and,
when configured, its Unix-socket endpoint. A local-only instance can set its
port to `0`; the renderer then requires a Unix socket and emits only that
endpoint. This keeps the same profile format usable after TCP is disabled for
a proven local-only Redis process.

## Endpoint inputs

If `/var/run/redis/sonic-db/database_global.json` exists, it is authoritative
for the base, ASIC namespace, and DPU-container maps. Otherwise the renderer
uses `/var/run/redis/sonic-db/database_config.json`. Additional finalized maps
can be passed with repeated `--database-config` options. This is needed when a
topology's global map does not enumerate every locally launched database
container.

The eventual startup caller must pass the single-DPU map explicitly, for
example by passing `/var/run/redisdpu0/sonic-db/database_config.json` with
`--database-config`, because a one-DPU system may not create the default global
map. When this device owns the chassis Redis process, the caller must also pass
its finalized map with `--local-chassis-config`; normal base/global discovery
deliberately excludes the ambiguous `redis_chassis` entry.

`remote_redis` is always excluded. `redis_chassis` is also excluded from the
normal maps because the same entry describes either a local chassis process or
an independently imaged remote chassis. A launcher may pass
`--local-chassis-config /var/run/redis-chassis/sonic-db/database_config.json`
only when that local database-chassis service owns the process and uses the
same local credential.

The Switch-BMC link address is not present in `database_config.json`; it is
added later to the Redis bind list. This host profile therefore covers the
local BMC Redis endpoints, not a client on the other side of the device link.
Cross-device chassis, DPU, and BMC authentication requires its own provisioned
identity and profile.

## Required ordering

1. Prepare or validate the `local-system` credential.
2. Finalize every selected `database_config.json` and the optional global map.
3. Render the server ACL for each Redis process and start the process.
4. Render this host profile after every selected map is valid and before the
   first host command uses `--writer-profile local-system`.

For multi-ASIC and multi-DPU systems, step 4 must wait for all includes. It may
be invoked more than once: identical output is left unchanged, while a safe
topology change is committed by atomic rename. Activation must not make the
passwordless Redis identity read-only until every writer has its profile.

## Failure behavior

The renderer rejects malformed or partial maps, duplicate JSON keys, include
escapes, symlinks below the database root, untrusted or writable map files,
duplicate sources or contexts, missing local endpoints, and unsafe existing
output metadata. Byte-identical endpoint strings are emitted once because
multi-ASIC namespace maps intentionally repeat `127.0.0.1:6379`. The profile is
written atomically and contains no credential value or hash.

## Tests

Run the standard-library tests from this directory:

```text
python3 -m unittest discover -s tests -p 'test_*.py' -v
```
