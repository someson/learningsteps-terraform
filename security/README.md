# LearningSteps — Security Hardening Log

This folder documents how the intentionally insecure "Base Deployment" is
turned into a hardened, production-ready architecture: what was wrong, what
was changed, how, and how the fix was verified.

## Documents

| # | Document | Status |
|---|---|---|
| 00 | [Baseline security assessment](00-baseline-assessment.md): threat model, findings F-01…F-17, roadmap | ✅ done |
| 01 | Day 1: Management access (Entra ID SSH, SSH restricted to a trusted IP) | ⏳ |
| 02 | Day 2: TLS + Web Application Firewall (NPMplus, Let's Encrypt, CrowdSec/CRS) | ⏳ |
| 03 | Day 3: Identity-based API access (Entra ID + oauth2-proxy) | ⏳ |
| 04 | Day 4: Data isolation (PostgreSQL VNet integration, private DNS) | ⏳ |
| 05 | Day 5: Detection and response (Sentinel + auto-block playbook) | ⏳ |

## Structure of each day's document

1. **Problem**: which findings from `00-baseline-assessment.md` it addresses
2. **Threat**: how an attacker exploits it
3. **Change**: code diff (Terraform / scripts) or manual steps, with the reason for each
4. **Verification**: before/after commands and their output (e.g. `curl`, `psql`, `nmap`)
5. **Residual risk**: what is still not covered and how the managed Azure service would do it (Bastion, Application Gateway WAF, Key Vault, Private Endpoint, Defender for Cloud)

## Findings tracker

| ID | Short name | Severity | Fixed in |
|---|---|---|---|
| F-01 | SSH open to the internet | High | |
| F-02 | Static SSH key only | Medium | |
| F-03 | Public DB, firewall allows all IPs | Critical | |
| F-04 | VM→DB over the public internet | High | |
| F-05 | API without authentication | Critical | |
| F-06 | No TLS | High | |
| F-07 | No WAF | High | |
| F-08 | API bound to 0.0.0.0 at boot | Medium | |
| F-09 | DB password in plaintext (state, custom_data, unit file) | High | |
| F-10 | App uses DB admin account | Medium | |
| F-11 | Default NPMplus admin credentials | High | |
| F-12 | SSH host key verification disabled in deploy.py | Low | |
| F-13 | Unpinned images / dependencies | Low–Medium | |
| F-14 | No detection / response | Medium | |
| F-15 | Local unencrypted Terraform state | Medium | |
| F-16 | Flat network, VM with public IP | Medium | |
| F-17 | oauth2-proxy allows any tenant user | Low–Medium | |
