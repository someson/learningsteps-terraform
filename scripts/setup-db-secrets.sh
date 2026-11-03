#!/bin/bash
# F-09 / F-10 — DB secrets from Key Vault, least-privilege app role
#
# Before: the PostgreSQL ADMIN password sat in plaintext in
#   - the systemd unit (Environment=DATABASE_URL=..., world-readable),
#   - the VM's custom_data (cloud-init, readable via the Azure API),
# and the app connected AS the admin (F-10).
#
# After:
#   - Both passwords live only in Key Vault (keyvault.tf). The VM reads them
#     with its managed identity (IMDS token -> Key Vault REST API); nothing
#     secret is written to disk or into a unit file.
#   - The app connects as a dedicated role (default learningsteps_app) that
#     may only SELECT/INSERT/UPDATE/DELETE on table entries.
#   - The app binds to 127.0.0.1 directly (F-08), not 0.0.0.0 at boot.
#
# Used in two ways (single source of truth):
#   - new VMs: cloud-init writes this file and runs it on first boot
#     (scripts/cloud-init.yaml, base64-embedded by vm.tf);
#   - existing VMs: run it once over SSH (see security/07-secrets.md):
#       sudo bash setup-db-secrets.sh <key-vault-name> <db-host> <db-name> <admin-user> <app-user>
#
# Idempotent: re-running re-applies the role password and grants.

set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <key-vault-name> <db-host> <db-name> <admin-user> <app-user>" >&2
  exit 2
fi
KEY_VAULT_NAME=$1
DB_HOST=$2
DB_NAME=$3
DB_ADMIN_USER=$4
DB_APP_USER=$5

echo "==> Writing /etc/learningsteps/db.conf (no secrets)..."
install -d -m 0755 /etc/learningsteps
cat > /etc/learningsteps/db.conf << CONF
KEY_VAULT_NAME=${KEY_VAULT_NAME}
DB_HOST=${DB_HOST}
DB_NAME=${DB_NAME}
DB_APP_USER=${DB_APP_USER}
CONF
chmod 0644 /etc/learningsteps/db.conf

echo "==> Writing /usr/local/bin/kv-secret..."
cat > /usr/local/bin/kv-secret << 'PY'
#!/usr/bin/env python3
"""Print one Key Vault secret, using the VM's managed identity.

usage: kv-secret [--wait SECONDS] <vault-name> <secret-name>

--wait retries on errors (e.g. 403 while the access policy for a brand-new
VM identity is still being created, or no network yet at first boot).
The value goes to stdout only; it is never logged.
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

args = sys.argv[1:]
wait = 0
if len(args) >= 2 and args[0] == "--wait":
    wait = int(args[1])
    args = args[2:]
if len(args) != 2:
    sys.exit(__doc__)
vault, name = args

IMDS = ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
        + urllib.parse.quote("https://vault.azure.net", safe=""))


def fetch():
    req = urllib.request.Request(IMDS, headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=10) as r:
        token = json.load(r)["access_token"]
    url = f"https://{vault}.vault.azure.net/secrets/{urllib.parse.quote(name)}?api-version=7.4"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)["value"]


deadline = time.time() + wait
while True:
    try:
        sys.stdout.write(fetch())
        break
    except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
        code = getattr(exc, "code", None)
        if time.time() >= deadline:
            sys.exit(f"kv-secret: cannot read {name} from {vault}: {code or exc}")
        print(f"kv-secret: {name} not readable yet ({code or exc}), retrying...", file=sys.stderr)
        time.sleep(10)
PY
chmod 0755 /usr/local/bin/kv-secret

echo "==> Writing /usr/local/bin/learningsteps-start..."
cat > /usr/local/bin/learningsteps-start << 'SH'
#!/bin/bash
# Fetches the app role's password from Key Vault at every start and passes it
# to the app in its environment only (not in the unit file, not on disk).
set -euo pipefail
. /etc/learningsteps/db.conf
PW=$(/usr/local/bin/kv-secret --wait 600 "$KEY_VAULT_NAME" db-app-password)
export DATABASE_URL="postgresql://${DB_APP_USER}:${PW}@${DB_HOST}/${DB_NAME}?sslmode=require"
unset PW
cd /opt/learningsteps/api
exec /opt/learningsteps/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
SH
chmod 0755 /usr/local/bin/learningsteps-start

echo "==> Reading secrets from Key Vault ${KEY_VAULT_NAME} (managed identity)..."
ADMIN_PW=$(/usr/local/bin/kv-secret --wait 900 "$KEY_VAULT_NAME" db-admin-password)
APP_PW=$(/usr/local/bin/kv-secret --wait 900 "$KEY_VAULT_NAME" db-app-password)

# libpq environment instead of a URL on the command line (would show in `ps`).
export PGHOST="$DB_HOST" PGDATABASE="$DB_NAME" PGUSER="$DB_ADMIN_USER" PGSSLMODE=require
export PGOPTIONS="-c client_min_messages=warning"   # hide "already exists, skipping"
export PGPASSWORD="$ADMIN_PW"

echo "==> Waiting for PostgreSQL..."
for _ in $(seq 1 120); do
  psql -qtAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 5
done
psql -qtAc 'SELECT 1' >/dev/null

if [ -f /opt/learningsteps/database_setup.sql ]; then
  echo "==> Applying database_setup.sql (idempotent)..."
  psql -q -v ON_ERROR_STOP=1 -f /opt/learningsteps/database_setup.sql >/dev/null
fi

echo "==> Creating / updating role ${DB_APP_USER} (least privilege)..."
# SQL and the password go through stdin, never through argv.
psql -q -v ON_ERROR_STOP=1 -v app_user="$DB_APP_USER" -v db="$DB_NAME" << SQL
\set app_pw '${APP_PW}'
SELECT format('CREATE ROLE %I LOGIN', :'app_user')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user') \gexec
-- No NOSUPERUSER here: only a superuser may set that attribute, and the Azure
-- admin is not one (found by testing). A CREATEROLE admin cannot create a
-- superuser anyway, so the role is never one.
ALTER ROLE :"app_user" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'app_pw';
GRANT CONNECT ON DATABASE :"db" TO :"app_user";
GRANT USAGE ON SCHEMA public TO :"app_user";
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE entries TO :"app_user";
SQL
unset PGPASSWORD ADMIN_PW APP_PW

echo "==> Writing systemd unit (no secrets in it)..."
cat > /etc/systemd/system/learningsteps.service << 'UNIT'
[Unit]
Description=LearningSteps API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/learningsteps-start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/learningsteps.service

systemctl daemon-reload
systemctl enable learningsteps >/dev/null 2>&1
systemctl restart learningsteps

echo "==> Waiting for the API on 127.0.0.1:8000..."
for _ in $(seq 1 30); do
  if curl -s -o /dev/null http://127.0.0.1:8000/; then
    echo "Done. API is up, connected as ${DB_APP_USER}."
    exit 0
  fi
  sleep 2
done
echo "API did not answer on 127.0.0.1:8000 within 60 s; check: journalctl -u learningsteps -n 50" >&2
exit 1
