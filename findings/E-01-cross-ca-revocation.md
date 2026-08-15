# E-01 — Cross-CA CMP revocation & reactivation (CWE-863, High)

## Summary
A CMP RA that legitimately holds **one CA's** per-CA CMP RA secret can revoke — or, via
`certificateHold` + `removeFromCRL`, un-revoke — certificates issued by a **different** CA whose secret
it does not hold. The message is authenticated against the CA named in the request **header** (recipient),
while the certificate acted upon is taken from the request **body**; the two are never required to match.

## Root cause (EJBCA CE 9.3.7, `modules/ejbca-ejb/.../cmp/RevocationMessageHandler.java`)
- `getRecipientCA` resolves the auth CA from the request header recipient DN (`caId = recipient DN hashCode`), and the HMAC secret is verified against **that** CA.
- The revocation target CA + serial come from the body `RevDetails.issuer` / serial — decoupled from the auth CA.
- For the HMAC module, `getAuthenticationToken()` returns null, so the handler falls back to
  `adminForEjb = AlwaysAllowLocalAuthenticationToken`, and `endEntityManagementSession.revokeCert(adminForEjb, serno, issuer, reason)` runs under that super-token. Every per-CA / multi-tenant authorization check downstream passes because AlwaysAllow matches `/`.

CVE-2021-40088 fixed exactly this decoupling — but only for the `EndEntityCertificate` authentication
module (which even has a cross-CA regression test). The HMAC module was left on AlwaysAllow.

## Reproduction
`pocs/e01_cross_ca_revoke.sh` and `pocs/e01_cross_ca_reactivate.sh`. Oracle is OCSP (real-time, not the
possibly-stale CRL). Negative control: the identical request with a wrong secret fails authentication and
leaves the certificate `good`.

Observed:
- wrong secret → `good` (auth is real);
- `secretA` (ManagementCA's secret) targeting a **CA-B** cert → `revoked`;
- cross-CA `certificateHold` then `removeFromCRL` with `secretA` → `revoked` → `good` (reactivation; limited to certs currently on hold).

## Impact
Cross-tenant revocation-state control: a tenant can revoke another tenant's certificates (targeted DoS /
trust disruption) or un-revoke a certificate the other tenant intended to keep revoked. Preconditions:
multi-tenant CMP with per-CA secrets, a reachable RA-mode HMAC alias, attacker holds some CA's secret.

## Remediation
Do not use AlwaysAllow for HMAC-authenticated CMP. Bind the revocation to the **target** certificate's CA
— authenticate against the body-target CA, or run `revokeCert` under a token scoped to the CA the secret
actually authorizes (mirror the `EndEntityCertificateAuthenticationModule` fix).
