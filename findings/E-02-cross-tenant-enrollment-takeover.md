# E-02 — Cross-tenant end-entity takeover via CMP RA-mode enrollment (CWE-863, High)

## Summary
The enrollment sibling of E-01, same AlwaysAllow amplifier. A CMP `ir`/`cr` in RA-mode with HMAC auth
runs under `AlwaysAllowLocalAuthenticationToken`. When the request's (generated) username collides with an
**existing** end entity — including one owned by a **different** CA — EJBCA takes the *edit* branch and
overwrites that record. A CMP RA holding only CA-A's per-CA secret thereby takes over a CA-B end entity and
mints a CA-A certificate for that identity.

## Root cause (EJBCA CE 9.3.7)
- `modules/ejbca-cmp-war/.../CmpServlet.java:161` — the servlet mints an `AlwaysAllowLocalAuthenticationToken` for every request.
- `HMACAuthenticationModule.java:344` — the HMAC module deliberately returns **no** administrator token.
- `CrmfMessageHandler.java:460,473` — with no module token, `adminForEjb = this.admin` (AlwaysAllow); it calls `certificateRequestSession.processCertReq(adminForEjb, …)`.
- `CertificateRequestSessionBean.java:349,365` — `addOrEditUser` checks only the **incoming** CA (`CAACCESS`) + generic `REGULAR_CREATECERTIFICATE` (both no-ops under AlwaysAllow); then on a **global** `existsUser(username)` it calls `changeUser`.
- `EndEntityManagementSessionBean.java:897` — `changeUser` authorizes only the **request** `caId` / EEP; it loads the existing row at `:930` and overwrites CA/EEP/certProfile/DN/status/password at `:1103`. `originalCopy` (`:936`) is used only for the audit diff — the stored CA/EEP is **never** authorized against.

That the omission is a bug and not RA-mode intent is proved inside EJBCA itself: the dedicated CA-migration
function authorizes against the **stored old CA** before changing it
(`EndEntityManagementSessionBean.java:1785`), and the certificate-authenticated CMP path authorizes the
issuer CA (`EndEntityCertificateAuthenticationModule.java:736`, regression test
`EndEntityCertAuthModuleSystemTest.java:948`).

## Reproduction
`pocs/e02_cross_tenant_takeover.sh`.
- **Positive control:** a fresh username is created **only under CA-B**; its baseline certificate issuer is `CN=CA-B` — proving Tenant-B ownership before the attack.
- **Negative control:** the identical CMP `ir` with a wrong secret issues no certificate.
- **Attack:** CMP `ir`, subject `CN=<victim>`, PBM-protected with **`secretA` = ManagementCA's per-CA secret only** → a certificate is issued under **ManagementCA**, and `getendentitycert` then lists certs from **both** CA-B and ManagementCA. The attacker never held CA-B's secret.

## Impact
Cross-tenant end-entity record takeover + availability disruption (CWE-863): repoint/reset another
tenant's end entity (CA, EEP, DN, status, password) and mint a certificate for its identity under the
attacker's CA. It does **not** disclose CA-B's key, mint under CA-B, or revoke CA-B certs — hence High, not
Critical. Preconditions: reachable RA-mode HMAC CMP alias pinned to CA-A using CA-A's **per-CA** secret
(not a global/shared alias secret), CA-A uses user storage, a guessable colliding username, EEP/cert
profile accept the data, no blocking approval policy, CA-A/CA-B are intended tenant boundaries.

## Remediation
Authorize `changeUser` against the **existing** entity's stored CA/EEP before overwriting — EJBCA already
does this in its CA-migration path (`:1785`) and rename path; the enrollment edit path skips it. And stop
using AlwaysAllow for HMAC-authenticated CMP (run under a CA-scoped token).
