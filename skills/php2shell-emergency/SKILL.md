---
name: php2shell-emergency
description: Emergency exposure + compromise check for PHP estates during the PHP2Shell window (CVE-2026-109618/109619, Oct 2026, RCE in multipart parsing, CVSS 9.2) — an authorized emergency-check runbook. Covers WordPress, Bitrix and custom PHP on VPS/shared hosting. Triggers on php2shell, CVE-2026-109618, CVE-2026-109619, экстренная проверка PHP, RCE в PHP, вебшелл поиск, сайт взломан проверка.
metadata:
  short-description: PHP2Shell emergency exposure & compromise check
---

# PHP2Shell Emergency Check (authorized engagements)

## Scope

Rapid assessment of a PHP estate during the PHP2Shell event:
**exposure verdict → compromise verdict → emergency mitigation → patch
verification**, delivered as an evidence-based report within the same day.
Default shape: WordPress or Bitrix (or custom PHP) on a VPS or shared
hosting, nginx/Apache + PHP-FPM. Written ROE before any active check;
everything here is read-only + log/file inspection by default. Exploit
validation runs ONLY in the isolated lab (see Lab use below), never on
client infrastructure.

## Event snapshot — 2026-10-21 (mutable, refresh at delivery time)

- Two critical RCEs in PHP core, CVSS v4.0 9.2 each. CVE IDs
  CVE-2026-109618 / CVE-2026-109619 per CERT-EU advisory 2026-018 and leak
  coverage; MITRE records were not yet visible pre-release — cite the
  CERT-EU advisory as the identifier source in client reports.
- Vector (per Sansec/Patchstack): bugs in `multipart/form-data` body
  parsing + session upload progress, firing **before application code
  runs** — app version (WP/Bitrix) and app-level auth are irrelevant.
- Affected: every PHP from 5.4 per leaked tool banner + researcher
  consensus; fixes exist only for 8.2+.
- Public exploits verified on test systems (RUS-CERT); active attacks
  observed from 07:43 UTC 21 Oct; mass exploitation expected.
- Emergency release landed 2026-10-21 14:00 UTC (16:00 CEST). Confirmed
  fixed versions: **8.5.12, 8.4.27, 8.3.36, 8.2.35**. Branches ≤8.1 are
  EOL — no php.net patch; any fix there is the OS vendor's backport
  (Debian/Ubuntu LTS). Still verify live before version-gating a client:

```bash
curl -s https://www.php.net/downloads/ | grep -oE "8\.[2-5]\.[0-9]+" | sort -Vu
curl -s https://api.github.com/repos/php/php-src/releases?per_page=10 | grep -E "tag_name|published_at" | head
```

- Interim mitigations are leaky (CONFIRMED, RUS-CERT): sending
  **duplicate Content-Type headers** bypasses content-type filters;
  PHP-FPM is confirmed vulnerable (the "LiteSpeed-only" rumor is false);
  `file_uploads=Off` does NOT help — PHP still parses the multipart body.
- Canonical sources to re-check: php.net/archive/2026.php,
  CERT-EU 2026-018, RUS-CERT blog 2026-10-21, Huntress rapid-response,
  Sansec research, watchTowr FAQ, NCSC-NL/php2shell repo.

## Ground rules

- Findings need evidence (command + output); statuses
  candidate/validated/disproven/inconclusive; severity P0–P4. Unpatched
  internet-facing PHP here is **P0**; confirmed webshell is **P0 +
  incident response**.
- All client-facing probes run from a dedicated, access-controlled
  operator/jump host — never from a client server or the lab.
- Client prod is never exploited to "prove" the vuln — the version gate
  (Phase A) is the proof. Working PoCs only exist for the lab.
- Shared-hosting clients: check what's visible (headers, phpinfo
  leaks, hoster status pages) and drive the hoster; don't get shell.

## Phase A — Exposure assessment (per host)

1. Inventory PHP per property: version + SAPI + pool config. Externally:
   `curl -sI https://<host>/ | grep -iE 'x-powered-by|server'`; probe
   `/phpinfo.php`, `/_phpinfo.php`, `/info.php`, `test.php` (a
   default-file sweep covers the rest). With client shell access:
   `php -v; php-fpm8. -v; grep -rE '^(pm|listen)' /etc/php/*/fpm/pool.d/`.
2. Version-gate against the live fixed numbers (see snapshot). Vulnerable
   & internet-facing → P0. EOL branch (≤8.1) → P0 + migration plan, no
   patch path exists.
3. Config posture that shapes urgency: `php -i | grep -E 'session.upload_progress|session.use_strict_mode'`
   (upload_progress On = stock = worst case; strict_mode Off adds risk).
   Note: strict_mode is ineffective when sessions live in Redis/DB.
4. App layer inventory (WP/Bitrix/custom) + where uploads are accepted
   (any multipart endpoint = the attack surface; blocking it is Phase C's
   trade-off).

## Phase B — Compromise hunt (attacks are live since 07:43 UTC)

Assume the client may already be hit; hunt before advising patches.
Full runbook with one-liners: `references/detection.md`. Priorities:

1. Recently modified/unexpected `.php` in webroot + uploads dirs.
2. Webshell pattern grep (eval/base64/gzinflate/system/shell_exec chains).
3. WordPress: `wp core verify-checksums --include-root`; Bitrix paths in
   `references/ru-market.md`.
4. Access logs: multipart POSTs, POSTs to odd `.php`, anomalous sizes.
5. Runtime: php-fpm children spawning shells/curl/wget (process-watcher,
   Sigma rules — see detection.md). Blind spot: in-process PHP shells.
6. Persistence: cron, systemd units, authorized_keys, new users.
7. Any confirmed webshell → switch to IR mode: isolate host, preserve
   logs, rotate credentials + DB passwords (separate engagement).

## Phase C — Emergency mitigation (only until patched)

Config details + caveats: `references/mitigation.md`. In one line: block
`multipart/form-data` at the web server, disable
`session.upload_progress`, enable `session.use_strict_mode`, or go
GET/HEAD-only / maintenance / origin-lockdown behind Cloudflare (their
Managed Ruleset "Anomalous Execution 1–7" emergency rules cover all
plans). **These stop known exploits, not the class** (RUS-CERT: bypassed
in tests; PHP devs: patching is the only real mitigation) — and blocking
multipart breaks uploads and some checkouts. Always frame to the client
as a hours-to-days bridge, never a fix.

Per-CVE interim config (when the patch cannot land yet):

- CVE-2026-109619: `session.upload_progress.enabled=0` globally +
  restart php-fpm workers.
- CVE-2026-109618: `memory_limit = -1` pinned via `php_admin_value`
  (no in-code override; removes the in-process OOM trigger),
  `post_max_size` 8M; real memory caps at the cgroup level
  (Docker/LXC) — NOT `RLIMIT_AS`/`RLIMIT_DATA`, they provoke the same
  OOM crash.

## Phase D — Patch & verify

1. VPS: update PHP packages (distro backport or Remi/Sury), verify
   `php -v` ≥ the live fixed number, restart php-fpm, re-run the Phase A
   gate on the live site.
2. Docker: `apt upgrade` on the host does not update packages inside
   images — `docker compose build --no-cache` and restart the
   containers; until the rebuild the old (vulnerable) code stays in
   memory, a plain restart runs it again.
3. EOL branch: there is no Phase D — plan migration to 8.3/8.4 (8.2 dies
   31 Dec 2026) or isolate/decommission.
4. Shared hosting: check the hoster's status (RU hosters tracked in
   `references/ru-market.md`), then verify from outside: Site Health
   (WP) or a header/phpinfo probe.
5. Retest rule: an exposure verdict closes only after a post-patch
   re-probe shows the fixed version.

## Phase E — Report & delivery

Evidence-based report (RU for RU clients) with: event summary (2 lines +
CERT-EU link), exposure verdict per property with evidence, compromise
hunt results, actions taken/required, patch plan with owners. Deliver
within the emergency SLA agreed with the client.

## Lab use — exploit validation & agent evals

PoC exploitation runs only in an isolated lab: LXC/VMs on an internal
bridge (NAT for setup, no public exposure), WordPress + stock vulnerable
PHP from the distro (pre-backport window: anything currently in
Debian/Ubuntu repos is vulnerable). Detection on the lab host via
process-watcher `php-rce-october-26` configs (eBPF — sees the
containers' php-fpm children). Timed agent evals run against this lab
(our lab eval). Never point a PoC at anything that resolves publicly;
never reuse a lab container as a client-facing host.

## Lookup references

| You found / you are doing | Read |
|---|---|
| Webshell hunt, scanners, process-watcher, Sigma, log patterns | `references/detection.md` |
| Interim nginx/Apache/php-fpm configs, WAF options, caveats | `references/mitigation.md` |
| RU market: Beget/Timeweb/Reg.ru status, Bitrix specifics | `references/ru-market.md` |

## Source register (2026-10-21 snapshot)

php.net/archive/2026.php · cert.europa.eu/publications/security-advisories/2026-018/
· cert.uni-stuttgart.de/blog/2026-10-21-php · huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
· sansec.io/research/php2shell · watchtowr.com/intelligence/php-cve-2026-109618-faq
· patchstack.com/articles/php-major-vulnerability-alert-10-2026 ·
developers.cloudflare.com/changelog/post/2026-10-21-emergency-waf-release-cfmr ·
github.com/Neo23x0/process-watcher (+ emerging-threats/php-rce-october-26)
· github.com/NCSC-NL/php2shell
