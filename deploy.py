#!/usr/bin/env python3
"""
LearningSteps — deploy and test
Requires: Python 3.8+, Terraform >= 1.5, Azure CLI
Works on macOS, Linux, and Windows.

Usage:
  python3 deploy.py                         # interactive
  python3 deploy.py --password MyPass1      # skip password prompt
  python3 deploy.py --password MyPass1 --prefix myenv --location northeurope
"""

import argparse
import getpass
import json
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── colours ───────────────────────────────────────────────────────────────────

def _ansi_enabled():
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        except Exception:
            return False
    return True

_USE_COLOUR = _ansi_enabled()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def info(msg):   print(f"\n{_c('1;33', '▶')} {msg}", flush=True)
def ok(msg):     print(f"  {_c('0;32', '✓')} {msg}", flush=True)
def warn(msg):   print(f"  {_c('1;33', '!')} {msg}", flush=True)
def error(msg):  print(f"  {_c('0;31', '✗')} {msg}", flush=True)
def header(msg): print(f"\n{_c('1;36', '═' * 60)}\n  {_c('1;36', msg)}\n{_c('1;36', '═' * 60)}", flush=True)

FAILURES = []

def fail(msg):
    error(msg)
    FAILURES.append(msg)

SCRIPT_DIR = Path(__file__).parent.resolve()

def _resolve_cmd(cmd):
    if isinstance(cmd, (list, tuple)) and cmd:
        binary = cmd[0]
        if isinstance(binary, str) and not Path(binary).is_absolute():
            resolved = shutil.which(binary)
            if resolved:
                return [resolved, *cmd[1:]]
    return cmd

def run(cmd, cwd=SCRIPT_DIR, **kwargs):
    cmd = _resolve_cmd(cmd)
    try:
        return subprocess.run(cmd, check=True, cwd=cwd, **kwargs)
    except FileNotFoundError as exc:
        error(f"Command not found: {cmd[0]}")
        raise SystemExit(1) from exc

def run_out(cmd, cwd=None, exit_on_error=True):
    """Run a command and return its stdout.

    By default, a failure prints a clean error and hard-exits the whole
    script (used for one-shot calls like reading terraform output, where a
    failure is unrecoverable). Pass exit_on_error=False for calls a caller
    intends to retry/handle itself (e.g. polling loops using az run-command,
    which can transiently fail with Azure's "Conflict: Run command extension
    execution is in progress" — only one run-command execution is allowed
    per VM at a time) — in that case the original subprocess.CalledProcessError
    is re-raised so the caller's own try/except can catch it.
    """
    cmd = _resolve_cmd(cmd)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=cwd)
    except FileNotFoundError as exc:
        error(f"Command not found: {cmd[0]}")
        raise SystemExit(1) from exc
    except subprocess.CalledProcessError as exc:
        if not exit_on_error:
            raise
        error(f"Command failed with exit code {exc.returncode}")
        if exc.stderr:
            print(f"  stderr: {exc.stderr}", file=sys.stderr)
        if exc.stdout:
            print(f"  stdout: {exc.stdout}", file=sys.stderr)
        raise SystemExit(1) from exc
    return r.stdout.strip()

def tf(cmd):
    """Run a terraform command with output, always from SCRIPT_DIR."""
    return run_out(cmd, cwd=SCRIPT_DIR)

# ── SSH helper ──────────────────────────────────────────────────────────────
# `az vm run-command invoke` (the old approach) was found during testing to be
# unreliable when polled repeatedly: Azure's non-managed "immediate" run-command
# API can intermittently return a stale/default placeholder result ("This is a
# sample script") instead of actually executing the submitted script, even with
# no concurrent invocations in flight. Direct SSH with the key deploy.py already
# generates is simpler and was confirmed reliable during this migration's
# testing, so it's used for all VM-side polling and setup-script execution.

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
]

def ssh_run(vm_ip, key_path, remote_cmd, timeout=120):
    """Run a command on the VM over SSH. Returns (returncode, stdout, stderr)."""
    cmd = ["ssh", "-i", str(key_path), *SSH_OPTS, f"azureuser@{vm_ip}", remote_cmd]
    cmd = _resolve_cmd(cmd)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "ssh timed out"
    except FileNotFoundError as exc:
        error(f"Command not found: {cmd[0]}")
        raise SystemExit(1) from exc

def ssh_run_script(vm_ip, key_path, script_text, timeout=600):
    """Pipe a script's contents into `sudo bash` over SSH (stdin, no temp files
    needed on either side). Returns (returncode, stdout, stderr)."""
    cmd = ["ssh", "-i", str(key_path), *SSH_OPTS, f"azureuser@{vm_ip}", "sudo bash -s"]
    cmd = _resolve_cmd(cmd)
    # Send as bytes with LF-only line endings. With text=True, Python would
    # translate every \n to os.linesep (\r\n on Windows) when writing to stdin,
    # and the VM's bash would fail on the stray \r ($'\r': command not found).
    payload = script_text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    try:
        r = subprocess.run(cmd, input=payload, capture_output=True, timeout=timeout)
        return (r.returncode,
                r.stdout.decode("utf-8", "replace"),
                r.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return 124, "", "ssh timed out"
    except FileNotFoundError as exc:
        error(f"Command not found: {cmd[0]}")
        raise SystemExit(1) from exc

def need(binary, install_hint):
    if not shutil.which(binary):
        error(f"'{binary}' not found. {install_hint}")
        sys.exit(1)

# ── step 1 — prerequisites ────────────────────────────────────────────────────

def check_prerequisites():
    info("Checking prerequisites")
    need("terraform", "Install from https://developer.hashicorp.com/terraform/install")
    ok("terraform found")
    need("az", "Install from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli")
    ok("az CLI found")
    need("ssh-keygen", "Install OpenSSH (built-in on macOS/Linux; enable via Windows Optional Features)")
    ok("ssh-keygen found")

    try:
        account = run_out(["az", "account", "show", "--query", "{name:name}", "-o", "json"], exit_on_error=False)
        parsed = json.loads(account)
        ok(f"Logged in — subscription: {parsed['name']}")
    except subprocess.CalledProcessError:
        warn("Not logged in to Azure — launching az login")
        run(["az", "login"])
        account = run_out(["az", "account", "show", "--query", "{name:name}", "-o", "json"])
        ok(f"Logged in — subscription: {json.loads(account)['name']}")

    try:
        run_out(["az", "extension", "show", "--name", "ssh"], exit_on_error=False)
        ok("az ssh extension present")
    except subprocess.CalledProcessError:
        warn("az ssh extension missing — installing")
        run(["az", "extension", "add", "--name", "ssh", "--yes"])

# ── step 2 — ssh key ──────────────────────────────────────────────────────────

def ensure_ssh_key():
    info("SSH key")
    key_path     = SCRIPT_DIR / ".learningsteps_key"
    pub_key_path = SCRIPT_DIR / ".learningsteps_key.pub"

    if pub_key_path.exists():
        ok(f"Using existing key: {pub_key_path.name}")
    else:
        run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", str(key_path), "-N", "", "-C", "learningsteps"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok(f"Generated new key: {pub_key_path.name}")

    return pub_key_path.read_text().strip()

# ── step 3 — config ───────────────────────────────────────────────────────────

_URL_UNSAFE = set('@#$%&+=?/ \\\'\"')

def _validate_db_password(pw):
    if len(pw) < 8:
        return "must be at least 8 characters"
    if not any(c.isupper() for c in pw):
        return "must contain at least one uppercase letter"
    if not any(c.islower() for c in pw):
        return "must contain at least one lowercase letter"
    if not any(c.isdigit() for c in pw):
        return "must contain at least one digit"
    bad = [c for c in pw if c in _URL_UNSAFE]
    if bad:
        return f"must not contain {' '.join(set(bad))} (breaks the database connection URL)"
    return None

def detect_public_ipv4():
    """Day 1: the NSG only allows SSH from this IP. Force IPv4 — the VM's
    public IP is IPv4-only, so an IPv6 source prefix would lock you out."""
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                ip = r.read().decode().strip()
            if ip.count(".") == 3:
                return ip
        except Exception:
            continue
    return None

def ensure_admin_source_ip(tfvars):
    """Add admin_source_ip to an existing terraform.tfvars if it's missing."""
    text = tfvars.read_text()
    if re.search(r"^\s*admin_source_ip\s*=", text, re.M):
        return
    ip = detect_public_ipv4()
    if not ip:
        error("Could not detect your public IPv4. Add admin_source_ip = \"<your-ip>\" to terraform.tfvars")
        sys.exit(1)
    tfvars.write_text(text.rstrip("\n") + f'\nadmin_source_ip   = "{ip}"\n')
    ok(f"SSH will be allowed only from {ip} (admin_source_ip)")

def collect_config(public_key, args):
    info("Configuration")

    tfvars = SCRIPT_DIR / "terraform.tfvars"
    if tfvars.exists() and args.password is None:
        reuse = input("  terraform.tfvars already exists. Reuse it? [Y/n]: ").strip().lower()
        if reuse in ("", "y", "yes"):
            ok("Reusing existing terraform.tfvars")
            ensure_admin_source_ip(tfvars)
            return
    elif tfvars.exists() and args.password is not None:
        ok("Overwriting terraform.tfvars with provided flags")

    prefix   = args.prefix
    location = args.location

    if args.password is not None:
        pw = args.password
        err_msg = _validate_db_password(pw)
        if err_msg:
            error(f"--password rejected: {err_msg}")
            sys.exit(1)
    else:
        print()
        print("  Press Enter to accept the default shown in [brackets].")
        print()
        prefix   = input(f"  Resource name prefix [{prefix}]: ").strip() or prefix
        location = input(f"  Azure region         [{location}]: ").strip() or location
        while True:
            pw = getpass.getpass("  PostgreSQL password  (required): ")
            err_msg = _validate_db_password(pw)
            if err_msg:
                warn(f"Password rejected — {err_msg}")
                continue
            pw2 = getpass.getpass("  Confirm password:                ")
            if pw != pw2:
                warn("Passwords do not match, try again")
            else:
                break

    tfvars.write_text(
        f'prefix            = "{prefix}"\n'
        f'location          = "{location}"\n'
        f'vm_admin_username = "azureuser"\n'
        f'vm_admin_ssh_key  = "{public_key}"\n'
        f'db_admin_username = "psqladmin"\n'
        f'db_admin_password = "{pw}"\n'
        f'db_name           = "learning_journal"\n'
    )
    ensure_admin_source_ip(tfvars)
    ok(f"terraform.tfvars written  (prefix={prefix}, location={location})")

# ── step 4 — deploy ───────────────────────────────────────────────────────────

def deploy():
    info("Terraform init")
    run(["terraform", "init", "-upgrade"])

    info("Terraform apply")
    try:
        run(["terraform", "apply", "-auto-approve"])
    except subprocess.CalledProcessError:
        error("terraform apply failed — see errors above")
        sys.exit(1)
    ok("Infrastructure deployed")

# ── step 5 — outputs ──────────────────────────────────────────────────────────

def read_outputs():
    info("Deployment summary")
    raw = tf(["terraform", "output", "-json"])
    out = json.loads(raw)

    vm_ip      = out["vm_public_ip"]["value"]
    rg         = out["resource_group_name"]["value"]
    db_fqdn    = out["postgresql_fqdn"]["value"]
    ssh_cmd    = out["ssh_command"]["value"]
    vm_name    = out["vm_name"]["value"]
    az_ssh_cmd = out["az_ssh_command"]["value"]
    app_url    = out["app_url"]["value"]
    domain     = out["domain_name"]["value"]

    print(f"  VM IP        : {vm_ip}")
    print(f"  Domain       : {domain}")
    print(f"  API (HTTPS)  : {app_url}/docs")
    print(f"  DB           : {db_fqdn}")
    print(f"  SSH key      : {ssh_cmd} -i {SCRIPT_DIR / '.learningsteps_key'}")
    print(f"  SSH AAD      : {az_ssh_cmd}")

    return vm_ip, rg, db_fqdn, vm_name, app_url, domain

# ── step 6 — azure checks ─────────────────────────────────────────────────────

def check_azure_resources(rg, db_fqdn):
    info("Azure resource checks")

    state = run_out(["az", "group", "show", "--name", rg,
                     "--query", "properties.provisioningState", "-o", "tsv"])
    if state == "Succeeded":
        ok(f"Resource group '{rg}'")
    else:
        fail(f"Resource group state: {state}")

    vm_name = run_out(["az", "vm", "list", "--resource-group", rg,
                       "--query", "[0].name", "-o", "tsv"])
    vm_state = run_out(["az", "vm", "show", "--resource-group", rg, "--name", vm_name,
                        "--query", "provisioningState", "-o", "tsv"])
    if vm_state == "Succeeded":
        ok(f"VM '{vm_name}' provisioned")
    else:
        fail(f"VM provisioning state: {vm_state}")

    power = run_out(["az", "vm", "get-instance-view",
                     "--resource-group", rg, "--name", vm_name,
                     "--query", "instanceView.statuses[?contains(code, 'PowerState')].displayStatus | [0]",
                     "-o", "tsv"])
    if power == "VM running":
        ok("VM is running")
    else:
        fail(f"VM power state: {power}")

    db_server = db_fqdn.split(".")[0]
    try:
        db_state = run_out(["az", "postgres", "flexible-server", "show",
                            "--resource-group", rg, "--name", db_server,
                            "--query", "state", "-o", "tsv"], exit_on_error=False)
    except subprocess.CalledProcessError as exc:
        stderr = getattr(exc, "stderr", "") or ""
        if "ServerStoppedError" in stderr or "Stopped" in stderr:
            warn(f"PostgreSQL '{db_server}' is stopped. Start the server and retry checks.")
            return
        fail(f"Failed to query PostgreSQL server state: {stderr.strip() or exc}")
        return

    if db_state == "Ready":
        ok(f"PostgreSQL '{db_server}' ready")
    elif db_state == "Stopped":
        warn(f"PostgreSQL '{db_server}' is stopped. Start the server and retry checks.")
    else:
        fail(f"PostgreSQL state: {db_state}")

# ── step 8 — wait for api ─────────────────────────────────────────────────────

def wait_for_service(vm_ip, key_path):
    info("Waiting for API service to start on VM over SSH (cloud-init takes ~10-15 min)")
    for _ in range(80):
        rc, out, _ = ssh_run(vm_ip, key_path,
            "curl -sf localhost:8000/entries > /dev/null && echo READY || echo NOT_READY",
            timeout=20)
        if rc == 0 and "READY" in out:
            print()
            ok("API service is running on VM")
            return True
        print(".", end="", flush=True)
        time.sleep(15)
    print()
    fail("API service not ready after ~20 min — SSH in and check: sudo journalctl -u learningsteps -f")
    return False

def _run_setup_script(vm_ip, key_path, script_name, label):
    """Run one of the scripts/*.sh setup scripts on the VM over SSH (piped to sudo bash -s)."""
    script_path = SCRIPT_DIR / "scripts" / script_name
    rc, out, err = ssh_run_script(vm_ip, key_path, script_path.read_text(), timeout=600)
    for line in out.split("\n"):
        line = line.strip()
        if line:
            print(f"  {line}")
    if rc == 0:
        ok(f"{label} complete")
        return True
    fail(f"{label} failed (exit {rc}): {err.strip()[-500:] if err else ''}")
    warn(f"SSH in and run manually: sudo bash /tmp/{script_name} (scp it up first)")
    return False


def run_npmplus_setup(vm_ip, key_path):
    info("Docker + NPMplus + CrowdSec baseline (runs on VM over SSH, ~3-5 min: pulls 2 images)")
    return _run_setup_script(vm_ip, key_path, "setup-npmplus.sh", "NPMplus/CrowdSec setup")


def run_oauth2_proxy_setup(vm_ip, key_path):
    info("oauth2-proxy binary + systemd unit (not started — OIDC creds are the Day 3 live demo)")
    return _run_setup_script(vm_ip, key_path, "setup-oauth2-proxy.sh", "oauth2-proxy install")


def run_json_logging_setup(vm_ip, key_path):
    info("Day 5 — NPMplus access-log -> syslog local0 JSON forwarder")
    return _run_setup_script(vm_ip, key_path, "setup-json-logging.sh", "Log forwarder setup")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """NPMplus's default host 301-redirects http -> https out of the box (before
    any Proxy Host exists). Following that redirect hits NPMplus's self-signed
    dummy cert and raises an unhandled SSL verification error — discovered
    during this migration's testing, since it made this check silently spin
    for the full timeout instead of recognizing NPMplus was already up.
    Returning None here makes urllib raise HTTPError instead of following the
    redirect, which the caller already treats as "server answered"."""
    def redirect_request(self, *args, **kwargs):
        return None

_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)

def wait_for_npmplus(app_url_base):
    """NPMplus listens on :80/:443 immediately, but with no Proxy Host configured
    yet (that's created live in the Day 2 demo) it serves its own default/dead
    page rather than the app. This just confirms NPMplus itself answered."""
    info("Waiting for NPMplus to accept connections on :80")
    url = f"{app_url_base.replace('https://', 'http://')}"
    for _ in range(40):
        try:
            _NO_REDIRECT_OPENER.open(urllib.request.Request(url), timeout=5)
            print()
            ok(f"NPMplus is answering on {url}")
            return True
        except urllib.error.HTTPError:
            # Any HTTP response (even a 301/404/444) means nginx inside NPMplus is up
            print()
            ok(f"NPMplus is answering on {url}")
            return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(15)
    print()
    warn("NPMplus did not respond on :80 — check: docker ps / docker logs npmplus")
    return False

# ── step 9 — api tests ────────────────────────────────────────────────────────

def run_api_tests(vm_ip, key_path):
    info("API tests (running inside VM over SSH)")
    script = r"""
BASE=http://localhost:8000
PASS=0
FAIL_COUNT=0

check() {
    local label=$1 expected=$2 actual=$3
    if [ "$actual" = "$expected" ]; then
        echo "PASS: $label"
        PASS=$((PASS+1))
    else
        echo "FAIL: $label (expected $expected got $actual)"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
}

STATUS=$(curl -sf -o /dev/null -w "%{http_code}" $BASE/entries 2>/dev/null || echo 000)
check "GET /entries" 200 $STATUS

RESP=$(curl -sf -X POST $BASE/entries -H 'Content-Type: application/json' \
    -d '{"work":"deploy test","struggle":"none","intention":"verify"}' 2>/dev/null || echo '{}')
HAS_ID=$(echo $RESP | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'entry' in d else 'no')" 2>/dev/null || echo no)
check "POST /entries" yes $HAS_ID
ID=$(echo $RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['entry']['id'])" 2>/dev/null || echo "")

if [ -n "$ID" ]; then
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -X PATCH $BASE/entries/$ID \
        -H 'Content-Type: application/json' -d '{"intention":"verified"}' 2>/dev/null || echo 000)
    check "PATCH /entries/$ID" 200 $STATUS
fi

STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -X DELETE $BASE/entries 2>/dev/null || echo 000)
check "DELETE /entries" 200 $STATUS

echo "Results: $PASS passed, $FAIL_COUNT failed"
[ $FAIL_COUNT -eq 0 ] && exit 0 || exit 1
"""
    rc, out, err = ssh_run_script(vm_ip, key_path, script, timeout=60)
    if rc not in (0, 1):
        fail(f"API tests could not run (ssh exit {rc}): {err.strip()}")
        return
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("PASS:"):
            ok(line[5:].strip())
        elif line.startswith("FAIL:"):
            fail(line[5:].strip())
        elif line.startswith("Results:"):
            print(f"  {line}")

# ── step 10 — seed sample data ────────────────────────────────────────────────

def seed_sample_data(vm_ip, key_path, db_fqdn):
    # Must run after run_api_tests(): its own smoke test calls DELETE /entries
    # with no id, which the app treats as "clear the whole table" — seeding
    # any earlier (e.g. from cloud-init, before the smoke test runs) gets
    # silently wiped out before a student ever sees it.
    info("Seeding sample journal entries")
    tfvars = SCRIPT_DIR / "terraform.tfvars"
    pw = None
    for line in tfvars.read_text().splitlines():
        if line.strip().startswith("db_admin_password"):
            pw = line.split("=", 1)[1].strip().strip('"')
    if not pw:
        warn("could not read db_admin_password from terraform.tfvars — skipping seed")
        return
    db_url = f"postgresql://psqladmin:{pw}@{db_fqdn}/learning_journal?sslmode=require"
    script = f"""
psql "{db_url}" -c "INSERT INTO entries (id, data, created_at, updated_at) VALUES
('seed-1', '{{\\"work\\": \\"Deployed the LearningSteps environment\\", \\"struggle\\": \\"None yet\\", \\"intention\\": \\"Complete this week''s walkthrough\\"}}', now(), now()),
('seed-2', '{{\\"work\\": \\"Reviewed the handbook\\", \\"struggle\\": \\"Lots of new Azure concepts\\", \\"intention\\": \\"Ask questions during the demos\\"}}', now(), now())
ON CONFLICT (id) DO NOTHING;"
"""
    rc, out, err = ssh_run_script(vm_ip, key_path, script, timeout=30)
    if rc == 0:
        ok("sample entries seeded")
    else:
        warn(f"could not seed sample entries: {err.strip()}")

# ── main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Deploy and test LearningSteps on Azure")
    p.add_argument("--password", help="PostgreSQL admin password (skips interactive prompt)")
    p.add_argument("--prefix",   default="learningsteps", help="Resource name prefix (default: learningsteps)")
    p.add_argument("--location", default="westeurope",    help="Azure region (default: westeurope)")
    return p.parse_args()

def main():
    args = parse_args()
    header("LearningSteps — Deploy and Test")

    check_prerequisites()
    public_key = ensure_ssh_key()
    key_path = SCRIPT_DIR / ".learningsteps_key"
    collect_config(public_key, args)
    deploy()
    vm_ip, rg, db_fqdn, vm_name, app_url, domain = read_outputs()
    check_azure_resources(rg, db_fqdn)
    if wait_for_service(vm_ip, key_path):
        run_api_tests(vm_ip, key_path)
        seed_sample_data(vm_ip, key_path, db_fqdn)

    if run_npmplus_setup(vm_ip, key_path):
        wait_for_npmplus(app_url)
    run_oauth2_proxy_setup(vm_ip, key_path)
    run_json_logging_setup(vm_ip, key_path)

    print()
    print(_c("1;36", "  Baseline is up. Days 2-5 are live demo steps, not automated — see handbook.md."))
    if not FAILURES:
        print(_c("0;32", "  All checks passed. Deployment is working."))
    else:
        print(_c("0;31", f"  {len(FAILURES)} check(s) failed:"))
        for f in FAILURES:
            print(f"    - {f}")
        sys.exit(1)

if __name__ == "__main__":
    main()
