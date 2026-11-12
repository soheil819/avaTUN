#!/bin/sh
# Keep a rollback copy of the managed application and unit files.
set -eu
[ "$(id -u)" -eq 0 ]
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec 9>/run/lock/tunnelmgr-update.lock
flock -n 9
restore(){
 backup=$1
 [ -f "$backup/ready" ]
 cp -a "$backup/app/." /opt/tunnelmgr/
 for src in "$root"/packaging/systemd/*.service; do
   name=$(basename "$src")
   if [ -f "$backup/$name" ]; then cp -a "$backup/$name" "/etc/systemd/system/$name"; else rm -f "/etc/systemd/system/$name"; fi
 done
 systemctl daemon-reload
 systemctl restart tunnelmgr-privd tunnelmgr
}
case "${1:-update}" in
 rollback) restore "${2:?provide snapshot path}"; exit;;
 update) ;;
 *) exit 2;;
esac
[ -d /opt/tunnelmgr ]
install -d -m 0700 /var/backups/tunnelmgr
backup=$(mktemp -d /var/backups/tunnelmgr/release.XXXXXX)
cp -a /opt/tunnelmgr "$backup/app"
for src in "$root"/packaging/systemd/*.service; do
 name=$(basename "$src"); if [ -f "/etc/systemd/system/$name" ]; then cp -a "/etc/systemd/system/$name" "$backup/"; fi
done
touch "$backup/ready"
if sh "$root/scripts/install-preview.sh" && curl -fsS --retry 4 --retry-connrefused http://127.0.0.1:8765/health && systemctl is-active --quiet tunnelmgr-privd; then
 echo "Rollback snapshot: $backup"
else
 restore "$backup"; exit 1
fi
