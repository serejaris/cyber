# PHP2Shell interim mitigations — configs & caveats

Everything here is a **bridge until PHP is patched**, never a fix.
RUS-CERT (RUS-CERT-2026-010, 21.10.2026): active exploitation underway;
the published workarounds "can be bypassed" — a published bypass sends
**multiple Content-Type headers** to slip past content-type matching;
PHP-FPM is confirmed vulnerable; PHP team: patching is the only real
mitigation.

## 1. Block multipart/form-data at the web server (ma.ttias.be, verbatim)

nginx — prefer the `map` form over an inline `if`:

```nginx
map $http_content_type $block_multipart {
    default 0;
    ~*multipart  1;
}

server {
    ...
    if ($block_multipart) {
        return 403;
    }
    ...
}
```

"If you use error_page ... with a path that re-enters PHP, return 444
instead."

Apache:

```apache
<If "req('Content-Type') =~ /multipart/i">
    Require all denied
</If>
```

("Do not use %{CONTENT_TYPE}, as that is not what Apache matches
against.")

**Breaks (ma.ttias caveats):** upload progress bars built on the PHP
feature stop working; all file uploads break unless you allowlist
specific paths — and allowlisted paths stay exposed until you patch; an
FPM reload causes a short burst of 502s.

**Known bypass:** duplicate Content-Type headers defeat the match
(RUS-CERT, CONFIRMED) — treat this filter as best-effort noise reduction,
not protection.

## 2. php-fpm settings (downgraded expectations)

```
; /etc/php/<ver>/fpm/pool.d/www.conf
php_admin_flag[session.upload_progress.enabled] = off
php_admin_flag[session.use_strict_mode] = on
```

Then reload php-fpm (repeat per installed PHP version; for mod_php put
the ini drop-in in apache2/conf.d). heise's lab called
`session.upload_progress.enabled = 0` **ineffective**; Ondřej Surý calls
it "at best an interim incomplete stopgap, not a substitute for
upgrading"; Sansec still recommends it. Apply (cheap, might shrink some
exploit paths), never rely. `session.use_strict_mode` has no effect when
sessions live in Redis/DB.

## 3. Harder options (precautionary-outage tier — used by NL gov sites, JP shops)

- GET/HEAD only (return 503 otherwise) or a static maintenance page with
  php-fpm stopped. RUS-CERT's last resort: **reject all POSTs**.
- Behind Cloudflare: emergency Managed Ruleset rules "Generic Rules —
  Anomalous Execution 1–7" (Block) shipped 2026-10-21 for **all plans
  including free** (changelog: 2026-10-21-emergency-waf-release-cfmr) —
  described by their CTO as a stopgap. Pair with origin lockdown:
  firewall the origin to Cloudflare IP ranges only, so nobody bypasses
  the CDN straight to origin PHP.
- Behind other WAFs: no vendor-specific php2shell rulesets confirmed
  published as of 2026-10-21 evening UTC — treat WAF-only posture as
  unprotected and push to patch.

## 4. What does NOT work

- WordPress maintenance mode / taking WP down — irrelevant: PHP parses
  the multipart body before app code runs.
- `file_uploads = Off` — PHP still parses the multipart body (RUS-CERT,
  CONFIRMED). Do not let a client believe this is a mitigation.
- "Only LiteSpeed/lsphp8 is exploitable" — false/unconfirmed; PHP-FPM
  confirmed vulnerable (RUS-CERT), heise could not reproduce only the
  circulating LiteSpeed-specific PoC.
- App-level fixes (WP/Bitrix/plugin updates) — the bug is below the app.
- Waiting for distro backports while exposed — Debian/Ubuntu/RHEL
  trackers were empty on release day; Remi did not ship same-day. If the
  hoster/distro has no fixed package yet, apply §1–§3 and isolate.

## 5. Patch = end state

Update PHP to ≥ the fixed release (8.2.35 / 8.3.36 confirmed floors;
verify the current numbers live via the SKILL.md snapshot commands),
restart php-fpm, re-probe the site. EOL branches (≤8.1) have no patch
path: migrate (8.2 is security-only and dies 2026-12-31 — target
8.3/8.4) or keep isolated indefinitely.

Sources: ma.ttias.be/php-cve-2026-109618-early-mitigation ·
cert.uni-stuttgart.de/blog/2026-10-21-php (RUS-CERT-2026-010) ·
heise.de/news/Wichtige-PHP-Updates-am-21-Oktober (11495072) ·
developers.cloudflare.com changelog 2026-10-21
