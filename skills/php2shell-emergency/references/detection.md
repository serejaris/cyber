# PHP2Shell detection & compromise-hunt runbook

Status labels: CONFIRMED = published for this event; GENERIC = standard IR
practice. All commands run on the client host (with authorization) unless
noted; network probes from a dedicated operator/jump host.

## 1. Filesystem webshell hunt (GENERIC, tuned for this event)

```bash
# recently modified php (tune the date to the event window)
find /var/www -name '*.php' -newermt 2026-10-20 -ls

# classic webshell patterns
grep -rEl 'eval\(|base64_decode|gzinflate|str_rot13|shell_exec|system\(|passthru|assert\(' \
  /var/www --include='*.php'

# wordpress: verify core + find non-WP php in webroot (CONFIRMED wp-cli)
wp core verify-checksums --include-root
wp plugin verify-checksums --all --strict --format=json
find /var/www/*/wp-content/uploads -name '*.php'   # any hit = red flag
```

Bitrix-specific paths: see `ru-market.md` §Bitrix.

## 2. Access-log analysis

**Event-specific request shape to hunt first (CONFIRMED, multi-source):**
an anonymous POST with `Content-Type: multipart/form-data` (the parser
also accepts comma variants), carrying a **self-chosen session cookie**
plus a `PHP_SESSION_UPLOAD_PROGRESS` form field — that combination trips
the pre-app session-write path. Any such POST outside expected upload
flows = treat as an exploit attempt. A hard-block rule implementation:
github.com/syhunt/php2shell-protection (rejects all multipart POSTs).

```bash
# POSTs to php endpoints, excluding expected WP endpoints
grep -E 'POST.*\.php' /var/log/nginx/access.log \
  | grep -vE '(wp-login|xmlrpc|admin)' | awk '{print $7}' | sort | uniq -c

# small-body POSTs (tool probes) across rotated logs
zgrep -h POST /var/log/nginx/access.log* | awk '$10>0 && $10<1500 {print $1,$7,$10}'

# multipart traffic volume per endpoint (the attack content-type)
grep -i 'multipart/form-data' /var/log/nginx/access.log* | head   # only if CT logged

# if bodies/CT not logged: enable logging $content_type + $request_body
# (size-capped) on the internet-facing vhost during the event window
```

## 3. Runtime detection — the event-specific layer

### process-watcher (CONFIRMED, primary tool for this event)

Florian Roth shipped an `emerging-threats/php-rce-october-26` config set:
eBPF, single static binary, Linux amd64/arm64, kernel 5.15+ with BTF, root,
runs on the HOST and sees containerized php-fpm. Logs every process PHP
spawns; optional SIGKILL mode (kill config ships `dry_run: true`).

```bash
# install (from the repo's emerging-threats/php-rce-october-26 README)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VERSION=$(curl -fsSI -o /dev/null -w '%{url_effective}' \
  https://github.com/Neo23x0/process-watcher/releases/latest | sed 's#.*/##')
# download tarball + SHA256SUMS for that version/arch, verify, extract
sudo ./process-watcher --config php/php-observe.yaml
# events -> /var/log/process-watcher/events.jsonl
```

Alerts on: shells/interpreters under php (sh/dash/bash/zsh, python, perl,
ruby), net tools (nc/socat/curl/wget), argv signatures incl. `/dev/tcp`.
Watch php-fpm itself (php-fpm → child), not just nginx.
**Blind spot:** in-process PHP (`fsockopen` without a child process).

### Sigma (CONFIRMED; no php2shell-specific rules exist yet — 2026-10-21)

- `proc_creation_lnx_webshell_detection.yml` (SigmaHQ, id
  818f7b24-0fba-4c49-a073-8b755573b9c7) — webshell children of
  httpd/nginx/etc. **php-fpm is NOT in its parent list — extend
  ParentImage with `/php-fpm` before deploying.**
- `proc_creation_lnx_php_reverse_shell.yml` (id c6714a24-d7d5-4283-a36b-3ffd091d5f7e)
  — `php -r` + `fsockopen` + shell names.

## 4. Scanners (CONFIRMED availability; licensing varies)

| Tool | Command | Notes |
|---|---|---|
| eComScan (Sansec) | `curl ecomscan.com \| sh` | commercial core, e-comm focus |
| LOKI (Neo23x0) | venv + `pip install colorama yara-python psutil rfc5424-logging-handler netaddr netaddr`; `sudo <venv>/bin/python loki.py -p /var/www` | inactive maintenance |
| php-malware-finder | `sudo apt-get install yara`; `yara -r ./php.yar /var/www` | Weevely3, P.A.S. etc. |
| Wordfence CLI | `pip install wordfence`; `wordfence malware-scan /var/www` | free tier EOL 2026-10-14 — check license |

## 5. Persistence sweep (GENERIC)

```bash
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u; done
ls -la /etc/cron* /var/spool/cron/
find / -name authorized_keys -exec sh -c 'echo {}; cat {}' \; 2>/dev/null
awk -F: '$3>=1000' /etc/passwd && getent group sudo
ls -la /etc/systemd/system | tail -20   # new units in the event window
```

Confirmed webshell or php-fpm-spawned shell → IR mode (SKILL.md Phase B.7):
isolate, preserve logs, rotate creds + DB passwords.
