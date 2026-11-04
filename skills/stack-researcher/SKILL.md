---
name: stack-researcher
description: >-
  Mandatory post-fingerprint research round for a security engagement.
  Use when a client's technology stack has been identified: record it in
  engagements/<client>/stack.md, then research each component for known
  CVEs, advisories, and hardening guidance, and produce applicability
  findings. Triggers on stack research, фаза ресерча, CVE round, стека ресеч.
---

# Stack Researcher

After fingerprinting a client, a **research round on the identified stack is
mandatory** before active testing conclusions are finalized — fingerprinting
without research is an incomplete engagement.

## Step 1 — Stack dossier (`engagements/<client>/stack.md`)

Record every identified component with evidence and role:

| Column | Meaning |
|---|---|
| Component | tech + version if fingerprinted (e.g. "Next.js App Router (Turbopack), version unknown") |
| Evidence | where it was observed (header, cookie, cert, chunk hash, behavior) |
| Role | what it serves in the client's architecture |
| Exposure | internet-facing? behind CDN? auth-walled? |
| Research status | pending / done (link to findings file) |

After the table, add an **Attack paths & trust boundaries** section (threat
model BEFORE discovery/prioritization): where trust boundaries sit (CDN
edge, auth walls, tenant borders), 3–7 realistic attack paths through the
stack, and which components each path crosses. Unknown areas get an
explicit `UNKNOWN` marker — they become priority questions for the client,
not silent gaps.

Version discipline: record version only with evidence (banners, health
endpoints, changelog-probing behavior). "Unknown" is a valid entry — it
itself is a finding (version hiding is good; banner disclosure is not).

## Step 2 — Research round (per component)

For each component in the dossier:

1. **Known CVEs and advisories** (current years first): search NVD/GitHub
   advisories/vendor blogs. Note version ranges — say explicitly whether the
   client's observed state falls in a vulnerable range or "unknown".
2. **Default exposures**: panels, debug endpoints, docs routes that ship
   enabled by default (cross-check your default-exposure checklist).
3. **Hardening guidance**: official hardening docs, CIS benchmarks, reputable
   write-ups. One or two authoritative links each, not a link dump.
4. **Probe candidates**: safe, single-request, read-only checks that would
   confirm/deny applicability on this client (e.g. a crafted header on one
   GET). Every probe must be PoC-grade: no destructive verbs, no auth
   bypass beyond demonstrating, no repeated attempts.

## Step 3 — Findings file

`engagements/<client>/findings/<date>-stack-research.md`:

- per component: relevant CVEs (severity + version-range applicability),
  hardening recommendations, probe candidates;
- a final section: **"Applicable now"** — items where observed evidence
  matches a vulnerable range or default-exposed surface, each with a
  proposed single-request PoC if one exists;
- feed "Applicable now" items into the engagement: run PoCs per your
  authorization rules, then convert confirmed ones into report findings
  with the standard evidence discipline.

## Manual mode vs the product pipeline

Routine version checking and CVE matching can be automated by your own
pipeline (see your pipeline spec for its contracts) — do not run that
loop by hand when the pipeline is deployed. This skill remains the
manual mode for one-off dossiers and checks when the pipeline is not
in place.

## Rules

- Research is read-only internet work: web search, vendor docs, advisories.
  No scanning during research.
- Prefer primary sources (vendor advisories, NVD, GitHub GHSA) over aggregators.
- Every claim gets a link; every applicability verdict gets an evidence line
  from the client dossier.
- The dossier and findings are committed to the repo; secrets never are.
