# About

This repository is a **reproducible lab** for two cross-tenant authorization findings in EJBCA Community
Edition 9.3.7, packaged so a reviewer can verify them end-to-end against the official
`keyfactor/ejbca-ce` container in a few minutes.

## What EJBCA is
EJBCA is a widely deployed open-source PKI / certificate-authority platform. In multi-tenant deployments
operators run several CAs as separate administrative or tenant boundaries and expose enrollment/revocation
protocols (CMP, SCEP, REST, ACME). CMP RA-mode with an HMAC (PBM) shared secret is a common integration
pattern: each CA is given its own `cmpRaAuthSecret`, and possession of that secret is meant to authorize
operations **for that CA**.

## The through-line
Both findings reduce to one design gap: EJBCA's CMP **HMAC / RA-mode** handlers execute EJB calls under an
internal `AlwaysAllowLocalAuthenticationToken` (a super-token matching every access rule) instead of a
token scoped to the CA the presented secret authorizes. The per-CA secret is checked at the door, but once
past it every downstream CA/EEP authorization check is a no-op. CVE-2021-40088 recognised this class and
fixed it for the *certificate-authenticated* CMP path; the HMAC/RA paths were not brought along, and
EJBCA's own CA-migration and rename code shows the CA-scoped check the enrollment edit path omits.

## Scope & method
- **Target:** EJBCA Community Edition, tag `r9.3.7` (commit `bff4252ae9`), matching `keyfactor/ejbca-ce:latest` (app 9.3.7).
- **In scope:** cross-tenant authorization, trust-boundary bypass, certificate mis-issuance. Denial-of-service and purely local hardening were out of scope for the assessment.
- **Method:** source review with file:line tracing, live reproduction against the container, and each finding independently re-reviewed by a separate model for a vuln-vs-by-design judgment before it was called confirmed. Every PoC ships with controls (a negative control on authentication; E-02 also a positive control on ownership) so a reviewer can see the boundary being crossed, not just an operation succeeding.

## Deployment note
A **single-operator** deployment where every CMP RA is intentionally trusted across every CA — or one that
configures a single global HMAC secret rather than per-CA secrets — does not meet the preconditions and is
not affected. The findings apply where distinct CAs are used as tenant/administrative boundaries with
per-CA secrets.

Findings are documented for defensive and disclosure purposes.
