# APT and npm cache maintenance

This independent weekly systemd job removes only `/var/cache/apt/pkgcache.bin`,
`/var/cache/apt/srcpkgcache.bin` and recognized `content-vN`, `index-vN`, `tmp`
children of `/home/ubuntu/.npm/_cacache`. It preserves the npm cache root and its
ownership. Packages installed on the system, `node_modules`, npm settings/logs,
application data, backups, publication packages and rollback releases are outside
this policy. Indexes/cache contents can be rebuilt or downloaded when next needed.

The APT phase takes nonblocking shared POSIX locks on all four package-manager
lock files, excluding exclusive package-manager writers. Busy/missing locks or
open cache files defer that phase. The npm phase defers if npm/npx processes or
open cache references are detected, repeating the check before each removal.
Unknown cache children stay; symlinks, hardlinks, mounts and concurrent changes
stop the affected phase. The cache writer process checks are conservative;
npm does not participate in this job's private lock. Do not force cleanup during
an installation. Busy phases are retried by the next weekly run, not by stopping
the installer. No apt update, upgrade, autoremove, npm install or global prune.

Install the root-owned script at `/usr/local/lib/vozen-cache-cleanup/cache_cleanup.py`,
both units in `/etc/systemd/system/`, and a root-owned 0750 control directory
`/var/lib/vozen-cache-cleanup`. Reload systemd, run the service once for validation,
then enable/start `vozen-cache-cleanup.timer`. No application restart is needed.
The timer runs Sunday at 04:00 UTC with up to 30 minutes jitter and catches up
after downtime. Check `systemctl list-timers vozen-cache-cleanup.timer`, the service
journal and `/var/lib/vozen-cache-cleanup/last-run.json`. Warnings fail only the
maintenance unit and are recorded in its result; busy phases report a skip.

The unit's writable paths are restricted to the two cache locations and its own
control state. Data/backups and the rest of both home directories are read-only.
The optional npm writable path allows an absent cache to be skipped; it does not
create a cache or change ownership. To disable: stop/disable the timer; this does
not restore already removed rebuildable cache contents.

Linux validation: `python3 -B -m unittest discover -s deploy/cache-cleanup -v`.
