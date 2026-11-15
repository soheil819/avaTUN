# GitHub updates

The installer enables a timer that checks the `main` branch of
`soheil819/avaTUN` every six hours. It compares the GitHub `APP_VERSION` with
the installed version and stores the result in `/var/lib/tunnelmgr/github-update.json`.

Admins can check immediately and install an available version from **Settings →
avaTUN update**. Telegram admins receive one notification for each new version;
send `/update` to refresh the GitHub check, then confirm the installation.
Installing downloads the archive attached to the matching GitHub release,
fetches the attestation bundle from the public GitHub API, decompresses it, and
verifies it offline with GitHub CLI (including the repository, release tag, and
dedicated release workflow). This avoids requiring a GitHub login on the managed
server. It checks the tag points
to the current `main` commit, verifies the source version, and runs the
repository's rollback-capable `scripts/update-release.sh`. Unsigned archives or
archives from any other workflow are refused. A
rollback snapshot is kept under `/var/backups/tunnelmgr`; the updater also snapshots
and restores account MFA state and its encryption key before starting the new panel.

Publishing a release triggers `.github/workflows/release-assets.yml`. It builds
the source archive from the release tag, creates a GitHub artifact attestation,
and attaches the archive to that release. The updater requires GitHub CLI 2.102.0
or newer and `python3-snappy`; the installer installs both from signed package
repositories.

Increase `APP_VERSION` for each published change on the tracked branch. Updates
are offered only when the GitHub version is newer than the installed version.
