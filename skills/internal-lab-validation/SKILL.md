---
name: internal-lab-validation
description: Use when validating vulnerabilities or detector baselines on a registered internal lab (your WordPress lab, self-hosted LXC/VM), not on a client. Triggers on внутренний стенд, лаборатория, lab scan, validate exploit, reset lab, detector baseline, test on a stand. Enforces private-only targets, `--i-own-the-lab`, GET/HEAD-only baseline, reset between runs, and no client packets.
metadata:
  short-description: Registered internal-lab baseline and validation
---

# Internal Lab Validation

## Scope

Use for active validation on a **registered internal lab** owned by you
or your team: your WordPress lab, a local LXC/VM, or a self-hosted
service. This is where vulnerability checks, detector tests, and exploit
PoCs are allowed to run.

Not for client infrastructure. A client retest needs current written
authorization (target, technique class, source host, window) and an
approved source host in your lab subnet (e.g. `10.0.0.0/24`); until
then, client work is document-only.

Maintain a lab registry (allowed targets and reset commands) and a small
runner script; the examples below assume flags `--i-own-the-lab`,
`--target`, `--out`.

## Hard rules

1. **Private and yours only.** The target must be RFC1918 or loopback
   and listed in the registry. The runner refuses anything else and
   requires `--i-own-the-lab`. Never point it at a client or a
   third-party SaaS, even read-only.
2. **Baseline is read-only.** GET/HEAD only. No POST, no login, no
   default-credential sweep, no fuzzing at volume. A baseline is not an
   exploit run.
3. **Exploit runs are separate.** If a PoC is needed, record the lab,
   the exact payload, the expected state change, and the reset command.
   Reset before and after.
4. **Reset between runs.** Use the lab's documented reset command
   (e.g. `pct exec <CTID> /root/reset.sh`). A dirty lab makes the next
   result meaningless.
5. **Sanitize.** Lab flags and test credentials are artifacts, not
   production secrets; still do not paste live client secrets, real PII,
   or private chat content.
6. **Evidence.** Status + bytes + content type for HTTP; config line for
   host controls. Label lab findings `lab`, not client severity.

## Detector and snapshot discipline

Three rules for any long-running lab with detectors and snapshots:

- **Rearm storm detectors daily, not once per run.** A one-shot detector
  flag goes blind on long runs: a 10,000-request XML-RPC multicall
  storm can go undetected because the flag had already fired.
  Date-stamp flags (`flag_YYYYMMDD`) and rearm them daily.
- **Snapshot `clean` AFTER instrumenting logs.** Rollback preserves the
  configuration present at snapshot time; a snapshot taken before log
  instrumentation erases it on rollback (request-body and header logging
  can be silently lost on reset).
- **Egress detection counts only SYN** (new connections), never ACK/FIN
  tails of closed connections — a conntrack-expired tail hits LOG+DROP
  and fakes a compromise.

## Workflow

1. Pick a registered lab and read its reset line.
2. Run the baseline:

```bash
python3 lab-scan.py --i-own-the-lab \
  --target 10.0.0.110 \
  --out lab-eval
```

3. Read `report.md` / `findings.json`:
   - open ports and service banners;
   - WordPress version, `/wp-json/` identity, `/wp-json/wp/v2/users`
     enumeration, `install.php` state, `readme.html`, XML-RPC;
   - classic exposure paths (`.env`, `.git`, backups);
   - security headers and TLS (if any).
4. If the run was an exploit validation, record the flag/effect and
   reset the lab. Re-run the baseline to confirm the reset.
5. Write one report per run under `lab-reports/<lab-name>/`; add the
   reset result. Do not commit real secrets.
6. Update your task tracker. All active validation stays on the lab.

## What to test

| Area | Check | Lab expectation |
|---|---|---|
| Reachability | ports 22/80/443/DBs | only the lab's documented services |
| HTTP identity | `/`, title, `Server`, `X-Powered-By` | known lab stack |
| WordPress | `/wp-json/`, `/wp-json/wp/v2/users`, `/readme.html`, `/wp-admin/install.php` | intentionally exposed; confirms detector |
| XML-RPC | `/xmlrpc.php` | 405/disabled or documented |
| Exposures | `.env`, `.git/HEAD`, `wp-config.php.bak`, backups | 404/403 unless the lab is testing exposure |
| Headers/TLS | CSP/HSTS/frame/referrer; cert if HTTPS | lab may be weak by design |
| SSH | banner, auth methods | lab-only key/password as designed |
| Reset | documented reset command | webroot clean, flag rotated, log cleared |

## Pitfalls

- A lab may be rebuilt or repurposed between runs — a wizard-style
  install can be replaced by a stock WordPress, and vice versa.
  Re-check the title before assuming the stack.
- `/wp-json/wp/v2/users` returning 200 can be expected lab user
  enumeration by design; label it `lab`, not a client finding.
- `install.php` returning 200 may be the "already installed" page; read
  the body before calling it a setup wizard.
- The runner's `--full` scan is for the lab only; do not reuse it on a
  client.
