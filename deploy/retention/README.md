# Helper release retention

This host policy applies to the Rust service `vozen-helper.service`, independently
of which publication script activates its `current` symlink. It does not replace
the legacy Node service template in `deploy/vozen-helper.service`.

Install `retention.py` root-owned at
`/usr/local/lib/vozen-helper-release-retention/retention.py` and the accompanying
oneshot unit under `/etc/systemd/system/`. Install `release-retention.conf` in
`/etc/systemd/system/vozen-helper.service.d/`. Initialize a root-owned 0750
`/var/lib/vozen-helper-release-retention` directory with a 0600 `state.json`:

```json
{"current":"<verified active 40-character revision>","rollback":"<verified previous healthy revision>"}
```

Never initialize rollback from directory ordering alone. Use the publication
receipt and verify both retained binaries before enabling the hook. Reload
systemd; installing the hook does not require restarting Helper. Start the
retention unit explicitly for an initial cleanup. Inspect its journal for the
removed/protected/skipped revisions or a warning.

Every subsequent service start queues maintenance. Once the running executable
matches `current` and local health succeeds, a changed current revision moves
the last healthy revision into rollback. Maintenance retains both revisions,
process executable/working-directory references, extra root deployment symlinks,
and directories as new as or newer than current (potential staged publications).
An ordinary restart keeps the same rollback. A rollback swaps the two retained
revisions when the previous binary passes health.

Only exact SHA-named directories containing the recognized ELF binary and two
deployment files are eligible. Symlinks, hardlinks, mount points, archives and
unknown layouts are skipped. Missing state, missing retained binaries, failed
health or a detected concurrent deployment cancels cleanup. There is no global
prune, backup expiration, database cleanup, forced process stop or bot restart.
Release-directory deletion is confined to `releases`; state writes use the
control-state directory. `shared`, Helper data and its backups remain read-only.
A warning does not fail Helper.

The same healthy-start job also expires old publication packages under immediate
`/home/ubuntu/helper-<name>-YYYYMMDD/` staging directories. It reads the same current
and rollback state, preserving matching packages in every staging directory.
Only regular single-link `vozen-helper-rust-<40-character revision>.tar.gz` files
with the exact ELF/deploy-only archive layout are eligible. Archives are inspected
without extraction. Newer staged packages, open files, active staging working
directories, symlinks, mount points, malformed archives and unknown layouts stay.
Directories whose names include backup/snapshot/restore/data are excluded.

The unit needs write access to `/home/ubuntu` to unlink packages from dynamically
named staging directories; code restricts deletion to those validated archive
files and does not remove directories or scripts. No cache cleanup, database or
backup expiration is included. Paths outside the existing writable roots and
`/home/ubuntu` remain read-only. The rollout receipt and journal record exact
removed/skipped files. A detected change to current or retention state stops
further package deletion.

Publication scripts must retain the current release until the new service has
started and must not replace the installed systemd drop-in. Preserve the state
directory across publications. If state is lost or publication skips this hook,
reconcile it from deployment receipts before re-enabling cleanup. Do not run
parallel activation/retention commands; current changes are checked before each
deletion, but external deploy scripts do not share the retention lock.

Run on Linux: `python3 -B -m unittest discover -s deploy/retention -p 'test_*.py' -v`.
