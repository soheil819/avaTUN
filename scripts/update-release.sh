#!/bin/sh
# Keep a rollback copy of the managed application and unit files.
set -eu
[ "$(id -u)" -eq 0 ]
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec 9>/run/lock/tunnelmgr-update.lock
flock -n 9
data_dir=/var/lib/tunnelmgr
snapshot_mfa_state(){
 snapshot=$1
 install -d -m 0700 "$snapshot"
 python3 - "$data_dir/state.sqlite3" "$snapshot/accounts.json" <<'PY'
import json,os,sqlite3,sys
database,output=sys.argv[1:]
fields=('name','totp_secret','totp_pending','totp_pending_at','totp_enabled','totp_last_step','recovery_codes')
rows=[]
if os.path.isfile(database):
    connection=sqlite3.connect('file:'+database+'?mode=ro',uri=True)
    tables={row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'accounts' in tables:
        columns={row[1] for row in connection.execute('PRAGMA table_info(accounts)')}
        selected=[field for field in fields if field in columns]
        if 'name' in selected:
            rows=[dict(zip(selected,row)) for row in connection.execute('SELECT '+','.join(selected)+' FROM accounts')]
    connection.close()
fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as stream:json.dump(rows,stream,separators=(',',':'))
PY
 if [ -f "$data_dir/mfa.key" ]; then cp -a "$data_dir/mfa.key" "$snapshot/mfa.key"; fi
requires_key=$(python3 - "$snapshot/accounts.json" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1]))
print(sum(bool(row.get('totp_enabled') or row.get('totp_secret') or row.get('totp_pending')) for row in rows))
PY
)
 if [ "$requires_key" -gt 0 ] && [ ! -f "$snapshot/mfa.key" ]; then
   echo 'MFA credentials exist but /var/lib/tunnelmgr/mfa.key is missing; refusing to update without the key.' >&2
   return 1
 fi
}
restore_mfa_state(){
 snapshot=$1
 [ -f "$snapshot/accounts.json" ] || return 0
 if [ -f "$snapshot/mfa.key" ]; then
   install -o tunnelmgr -g tunnelmgr -m 0600 "$snapshot/mfa.key" "$data_dir/mfa.key"
 fi
 python3 - "$data_dir/state.sqlite3" "$snapshot/accounts.json" <<'PY'
import json,os,sqlite3,sys
database,snapshot=sys.argv[1:]
if not os.path.isfile(database):
    raise SystemExit('account database disappeared during update; MFA state was not restored')
rows=json.load(open(snapshot))
connection=sqlite3.connect(database)
columns={row[1] for row in connection.execute('PRAGMA table_info(accounts)')}
fields=('totp_secret','totp_pending','totp_pending_at','totp_enabled','totp_last_step','recovery_codes')
selected=[field for field in fields if field in columns]
if selected:
    sql='UPDATE accounts SET '+','.join(field+'=?' for field in selected)+' WHERE name=?'
    enabled_names={row['name'] for row in rows if row.get('totp_enabled')}
    restored=set()
    for row in rows:
        if all(field in row for field in selected):
            cursor=connection.execute(sql,tuple(row[field] for field in selected)+(row['name'],))
            if cursor.rowcount:
                restored.add(row['name'])
    missing=enabled_names-restored
    if missing:
        connection.rollback();connection.close()
        raise SystemExit('enabled MFA accounts are missing after update: '+', '.join(sorted(missing)))
connection.commit();connection.close()
PY
 chown tunnelmgr:tunnelmgr "$data_dir/state.sqlite3"
 chmod 0600 "$data_dir/state.sqlite3"
}
restore(){
 backup=$1
 [ -f "$backup/ready" ]
 cp -a "$backup/app/." /opt/tunnelmgr/
 for src in "$root"/packaging/systemd/*.service "$root"/packaging/systemd/*.timer; do
   name=$(basename "$src")
   if [ -f "$backup/$name" ]; then cp -a "$backup/$name" "/etc/systemd/system/$name"; else rm -f "/etc/systemd/system/$name"; fi
 done
 restore_mfa_state "$backup/panel-data"
 systemctl daemon-reload
 systemctl restart tunnelmgr-privd tunnelmgr
 if [ -f /etc/avatun/telegram.json ] && systemctl is-enabled --quiet avatun-telegram.service; then
   systemctl restart avatun-telegram.service
 fi
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
for src in "$root"/packaging/systemd/*.service "$root"/packaging/systemd/*.timer; do
 name=$(basename "$src"); if [ -f "/etc/systemd/system/$name" ]; then cp -a "/etc/systemd/system/$name" "$backup/"; fi
done
touch "$backup/ready"
snapshot_mfa_state "$backup/panel-data"
systemctl stop avatun-telegram.service tunnelmgr.service tunnelmgr-privd.service 2>/dev/null || true
if AVATUN_INSTALL_DEFER_START=1 sh "$root/scripts/install-preview.sh" && restore_mfa_state "$backup/panel-data" && systemctl enable --now frr.service tunnelmgr-privd.service tunnelmgr.service tunnelmgr-github-update-check.timer && systemctl restart frr.service tunnelmgr-privd.service tunnelmgr.service && { [ ! -f /etc/avatun/telegram.json ] || ! systemctl is-enabled --quiet avatun-telegram.service || systemctl restart avatun-telegram.service; } && curl -fsS --retry 4 --retry-connrefused http://127.0.0.1:8765/health && systemctl is-active --quiet tunnelmgr-privd; then
 echo "Rollback snapshot: $backup"
else
 restore "$backup"; exit 1
fi
