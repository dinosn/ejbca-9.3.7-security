# EJBCA Community Edition 9.3.7 — Cross-Tenant CMP Authorization Findings (reproduction lab)

Two live-reproducible authorization findings in **EJBCA Community Edition 9.3.7** (`keyfactor/ejbca-ce`),
both rooted in the same gap: EJBCA's CMP **HMAC / RA-mode** paths run under an internal
`AlwaysAllowLocalAuthenticationToken` super-token, so **one CA's per-CA CMP secret authorizes
operations against a *different* CA's objects**. This is the same class as CVE-2021-40088, whose fix
was wired through only the *certificate-authenticated* CMP path and never extended to the HMAC/RA paths.

| ID | Finding | Impact | CWE |
|----|---------|--------|-----|
| **E-01** | Cross-CA CMP revocation & reactivation | A CMP RA with CA-A's secret revokes — or un-revokes — CA-B's certificates | CWE-863 |
| **E-02** | Cross-tenant end-entity takeover via CMP RA enrollment | A CMP RA with CA-A's secret overwrites a CA-B end entity and mints a cert for that identity | CWE-863 |

Both are **High severity** in a multi-tenant deployment (separate CAs used as tenant/administrative
boundaries, per-CA CMP secrets). They do **not** disclose the target CA's private key or mint under the
target CA; the impact is cross-tenant revocation-state control (E-01) and end-entity record takeover +
availability (E-02).

## Quick start

```bash
# needs: docker (+ compose plugin) and openssl on the host
git clone <this-repo> && cd ejbca-9.3.7-security
./pocs/run-all.sh          # starts the container, configures two tenants, runs all PoCs
```

`run-all.sh` brings up EJBCA CE, creates a second CA (`CA-B` = "Tenant B") alongside the built-in
`ManagementCA` ("Tenant A"), sets per-CA CMP RA secrets (`secretA`, `secretB`), configures two CMP
RA-mode HMAC aliases, and runs the three PoCs. Each PoC carries its own **negative control** (wrong
secret ⇒ rejected) and, for E-02, a **positive control** (a CA-B baseline certificate proving Tenant-B
ownership before the attack).

### Expected output (abridged)

```
E-01 revoke:   [1] OCSP after wrong-secret: victimB3.pem: good      <- auth enforced
               [2] OCSP after attack:       victimB3.pem: revoked   <- cross-CA revoke (only secretA held)
E-01 react:    [2] after removeFromCRL:     victimB4.pem: good      <- cross-CA un-revoke
E-02 takeover: BASELINE cert issuer = CN=CA-B ...                   <- victim owned by Tenant B
               neg-control cert issued? NO-good
               ATTACK cert issuer = CN=ManagementCA ...             <- minted with only secretA
               1 Issuer: CN=CA-B,...   1 Issuer: CN=ManagementCA,... <- takeover
```

## Layout

```
lab/docker-compose.yml       EJBCA CE 9.3.7, public web on :8080 (TLS_SETUP_ENABLED=simple)
lab/setup.sh                 two CAs, per-CA secrets, CMP RA aliases (ratest=revoke, enrA=enroll)
pocs/e01_cross_ca_revoke.sh        E-01 revoke (OCSP oracle + negative control)
pocs/e01_cross_ca_reactivate.sh    E-01 hold + reactivate
pocs/e02_cross_tenant_takeover.sh  E-02 takeover (positive + negative control)
pocs/run-all.sh              orchestrates everything
findings/E-01-*.md, E-02-*.md      root-cause writeups with file:line
evidence/EVIDENCE.md         captured transcripts
ABOUT.md, DISCLOSURE.md
```

See `ABOUT.md` for scope/method and `DISCLOSURE.md` for the disclosure posture.
Remediation and exact source lines are in `findings/`.
