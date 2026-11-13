# GitHub updates

The installer enables a timer that checks the `main` branch of
`soheil819/avaTUN` every six hours. It compares the GitHub `APP_VERSION` with
the installed version and stores the result in `/var/lib/tunnelmgr/github-update.json`.

Admins can check immediately and install an available version from **Settings →
avaTUN update**. Telegram admins receive one notification for each new version;
send `/update` to refresh the GitHub check, then confirm the installation.
Installing downloads the checked commit over HTTPS, verifies the source version,
and runs the repository's rollback-capable `scripts/update-release.sh`. A
snapshot is kept under `/var/backups/tunnelmgr`.

Increase `APP_VERSION` for each published change on the tracked branch. Updates
are offered only when the GitHub version is newer than the installed version.
