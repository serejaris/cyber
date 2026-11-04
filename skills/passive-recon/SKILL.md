---
name: passive-recon
description: Use when doing strictly-passive reconnaissance of prospect domains WITHOUT written authorization — lead-generation / prospecting batches, perimeter check-ups. Triggers on passive recon, разведка, периметр-чек, perimeter check, prospecting, проспектинг, enhanced pass, CT logs, subdomain enum, DMARC check, SPF check, email auth check, batch recon, волна, wave. NOT for authorized active testing — that is `web-pentest`.
metadata:
  short-description: Passive-only recon of domains without written authorization
---

# Passive Recon (prospecting — no written authorization)

## Scope

Prospect domains whose owner has NOT given written authorization:
community/product targets, lead-generation scans, perimeter check-ups.
Output is sales-conversation material and responsible-disclosure pre-work —
not a client report. Default batch: N domains from `scope.md`, run in
waves of parallel subagents.

If the owner DOES authorize (keep the written evidence on file) — stop,
open an engagement, and switch to `web-pentest` for the active phase.

## Hard rules

1. **Passive only.** Allowed: DNS queries, public CT log lookups, one
   paced HTTPS GET series to the apex host only (homepage + robots.txt +
   /.well-known/security.txt), TLS certificate read of the apex, DNS
   A/AAAA resolution of CT-discovered names. FORBIDDEN: HTTP to any
   subdomain, path brute-force, port scans, POST/PUT/DELETE, logins, test
   purchases, exploitation, vulnerability probes.
2. **Dedicated egress host.** All traffic originates from one designated
   egress host you control (e.g. a small VPS), never from a personal
   laptop — a single consistent source IP for the whole batch:
   `ssh -o BatchMode=yes <egress-host> '<cmd>'`. If ssh to the egress
   host fails, stop — no fallback.
3. One domain = one personal report, `findings/<domain>-<date>.md`.
   Nothing gets published without the owner's consent — the private
   report in a DM is the differentiator from scam "we found a hole" mail.
4. **Ownership triage before delivery:** confirm the domain really is the
   person's (the site names them / WHOIS / they presented the company in
   chat). Employer domain → do NOT DM the person, official channel only.
5. Human pacing (~1.5 s between HTTPS requests; back off on 429). Secrets
   redacted first4…last4. Every finding carries evidence and one status:
   `candidate → validated / disproven / inconclusive`.
6. Severity rubric P0–P4 (single vocabulary): P0 live secret/unauth RCE ·
   P1 authed RCE or data access · P2 brand spoofing (DMARC `p=none` or
   missing on a mail-capable domain) or actively-exploited CVE on an
   exposed component · P3 single control broken · P4 hardening only.

## Workflow (wave batch)

1. Targets from `scope.md` — Tier A (personal products) first, Tier B
   (companies) needs ownership/role triage before anything else.
2. Waves of parallel subagents (reference pattern: 4 agents × 2 targets
   each). Blind-run rule (model-compare runs): the subagent must not
   read prior findings for its target.
3. Standard checklist per domain — all via the egress host:
   - DNS: A/AAAA/MX/NS/TXT/CAA/SOA + DNSKEY/DS + AD flag (DNSSEC verdict:
     DS empty + DNSKEY present = signed island, no chain of trust).
   - Email auth: SPF (WALK the include chain — one NXDOMAIN include
     evaluates the whole SPF as `permerror`; `~all` vs `-all` matters),
     DMARC (`_dmarc`, note `p=`, `pct=`, `rua`, `sp=`, alignment),
     DKIM — the standard nine selectors (`google`, `default`, `selector1`,
     `selector2`, `k1`, `s1`, `s2`, `mail`, `dkim`) PLUS vendor-derived
     ones from MX host and SPF includes (`mailru`, `smtpbz`, `yandex`,
     `amocrmmail`, `sendgrid`…). Missing vendor selectors = false
     "no DKIM" verdicts.
   - CT: crt.sh + Cert Spotter both (union the names — one source misses
     whole naming schemes); aggregate naming patterns, don't paste name
     lists. crt.sh is flaky (404/502/429): retry once, fall back to
     certspotter, record the source gap as a deviation.
   - Apex HTTPS GET ×3 (/, /robots.txt, /.well-known/security.txt) with
     browser UA + one `http://` redirect check + TLS leaf via openssl.
4. Enhanced pass layer (below) after the standard checklist.
5. Per-domain findings file: Infrastructure / Email / CT logs / Headers &
   TLS / Enhanced layer / Public surface / Preliminary findings table /
   Notes. Then a **sales angle** paragraph — what remediation path the
   findings support (scan → fix-verify → recurring audit), grounded in
   that domain's findings.
6. Delivery: 5–10-line DM mini-report + one offer line + request for
   written authorization for an active phase (handoff per Scope).

## Enhanced passive pass (second layer)

1. **CT-name DNS resolution** — resolve A/AAAA for every CT name, DNS
   only. Resolving is not probing: no HTTP to these hosts without
   written authorization. Count live hosts; flag juicy labels: admin,
   staging, dev, vpn, panel, n8n, metabase, passwork, jenkins, grafana,
   old, backup, api, app\d, mcp, meet, files, crm, lms, hooks, brain,
   cpanel, mail, test, demo, beta, developers. **Catch-all caveat:**
   wildcard DNS makes "resolvable" meaningless — resolve a random probe
   label first; if it resolves too, only off-edge IPs and distinct
   fingerprints are interesting.
2. **MTA-STS** (`TXT _mta-sts.<domain>`), **BIMI** (`TXT
   default._bimi.<domain>`), **TLSRPT** (`TXT _smtp._tls.<domain>`) — DNS
   only. Absence on mail-heavy domains = SMTP-downgrade interception
   surface (P3–P4).
3. **Wildcard-cert note:** wildcard CT entries hide real structure — plan
   DNS wordlists for the authorized phase instead of trusting CT
   enumeration. Trust served TLS SANs over CT names for reachability.
4. **GitHub code-search OSINT** for `"<domain>"` + password / api_key /
   secret (`gh api -X GET search/code -f q=...`). Shared 5 k/hr rate
   limit — batch after recon, never during.

## CT and naming gotchas

- The richest CT bucket is not necessarily the live spelling: on
  multi-tenant platforms `{slug}--preview` may be live while the
  far-larger `preview--{slug}` set is stale. Sample-verify spellings
  before counting.
- Same-day cert clusters = provisioning churn, not compromise — pair CT
  timing with DNS reachability (and RDAP/ASN) before hypothesizing.
- Two runs of the same dig disagree only across time: label
  contradictory recon `as-of <timestamp>`; one lookup records truth, not
  history.

## NOT passive — needs written authorization (`web-pentest` territory)

Email spoof PoC (actually sending mail), form submissions (even marked
test leads), auth-flow probing, JWT attacks, function/API probing, any
HTTP to subdomains or paths beyond the apex GET series. DNS-truth checks
of SPF/DMARC/DKIM/MTA-STS ARE passive and live here; the sending test
itself is active work and lives in `web-pentest`.
