# RU market: hoster status + Bitrix specifics (2026-10-21)

## Shared-hosting status

| Hoster | Status (2026-10-21) | Evidence |
|---|---|---|
| Beget | CONFIRMED mitigating: disabled `session.upload_progress`, limited multipart POST uploads, temporarily blocked 80/443 to cloud DBs (phpMyAdmin/Adminer offline); VPS clients told to update to PHP 8.2+ | beget.com/news «Уязвимость в PHP от 21.10.2026» |
| Timeweb | NOT VERIFIABLE as of 2026-10-21 — no public notice found | — |
| Reg.ru | NOT VERIFIABLE as of 2026-10-21 — news page rendered empty, no notice found | — |

Client playbook for shared hosting: ask the hoster directly which PHP
build they run now; verify from outside (headers/phpinfo/Site Health)
after they claim the update. RU technical coverage of the event is
news-level only (Habr news 1097016, anti-malware.ru 21 Oct) — no RU
write-ups to lean on; carry the evidence yourself.

## Bitrix (1C-Bitrix)

- **Vendor silent** as of 2026-10-21 evening: no advisory on
  dev.1c-bitrix.ru; Bitrix unmentioned by EN sources. The risk is the
  PHP layer, identical to WordPress; Bitrix-as-app adds nothing and
  shields nothing.
- Legacy Bitrix farms are the exposure gap: they commonly ride EOL PHP
  (≤8.1) — the branch that will never get a patch. Priority segment for
  remediation outreach.

### Bitrix webshell hunt paths (from BQadro IR guidance, CONFIRMED pre-existing; no php2shell-specific artifacts published yet)

```bash
# random-named php in admin/tools
find /bitrix/admin -name '*.php' -mtime -10
ls -la /bitrix/tools/            # xmlrpcs.php, .cas.php = known-bad names
# kernel tamper — verify these against a clean same-version tarball:
#   prolog_after.php, security_file_verifier.php, bx_root.php
grep -Ril 'eval(base64_decode' /bitrix
find . -name '*.php' -mtime -10
# persistence: Bitrix agents (agents table) + cron jobs
# cache dirs to sweep: /bitrix/cache/, /bitrix/managed_cache/
# official scanner module: bitrix.xscan
```

Also check `/upload/*.php` and `bitrix/php_interface` (standard triage,
not in the BQadro source — mark as GENERIC).
