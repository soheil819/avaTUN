# Tunnel rebuild lifecycle

Edits and restarts use one controller transaction for exactly two managed
endpoints. Restart keeps the saved configuration; edits use the submitted
configuration while preserving credentials when appropriate.

1. Read both current configs and check endpoint identity, transport, inverse
   addresses, shared keys, and role pairing.
2. Validate both configs on their respective servers before changing either.
3. Save both old and desired configs in a private `rebuild-journals` file under
   the controller data directory. Checkpoints are written atomically, mode 0600.
4. Stop and disable each managed service, explicitly clean its resources, remove
   its profile/unit registration and owned interface, then remove its inventory
   row. Both endpoints must finish this phase before creation starts.
5. Create both endpoints from scratch, responder before initiator when roles
   apply, and register their new state.
6. On failure, remove attempted replacements and restore both saved configs.
   A failed rollback retains the recovery journal and reports the failed sides.

Backhaul secrets are reused and are not deleted during rebuild. A restart never
reuses a running interface: it recreates the device using its saved name and IPs.
Native edits retain the saved interface/address values unless explicitly changed.
The shared systemd templates and global StrongSwan daemon belong to multiple
profiles; cleanup removes the target instance, not those shared services.

The web UI uses `/api/v1/tunnels/rebuild` for paired config/MTU edits and
`/api/v1/tunnels/ID/restart` for restarts. Requests include both server IDs.
The central API also coordinates links whose endpoints are both remote.
Each endpoint needs the updated lifecycle code and privileged helper. An old or
unreachable endpoint fails validation before teardown starts.

Checks:

```sh
python3 scripts/check-tunnel-lifecycle.py
python3 scripts/check-telegram.py
# Root on Linux; uses disposable namespaces and no live tunnel profiles:
python3 scripts/check-tunnel-lifecycle-netns.py
```
