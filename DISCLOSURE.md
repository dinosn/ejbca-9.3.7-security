# Disclosure

This material documents two cross-tenant authorization findings in EJBCA Community Edition 9.3.7 and
exists for **defensive review and coordinated disclosure**. It is a private working repository.

## Posture
- The findings and PoCs are intended for the maintainer (Keyfactor) and the operator community to
  reproduce, confirm, and remediate.
- The PoCs run only against a **local throwaway lab** you start yourself (`lab/docker-compose.yml`). They
  create their own CAs, secrets, and end entities and act only on those. Do **not** run them against any
  system you are not authorized to test.
- No third-party or production system was tested in producing this material.

## Coordinated disclosure
If you are redistributing or acting on this, please coordinate with Keyfactor
(https://www.keyfactor.com/) through their security contact before any public release, and allow
reasonable time for a fix. Both issues are the same class as CVE-2021-40088 and the appropriate remedy is
to route CMP HMAC/RA-mode operations through a CA-scoped authentication token rather than
`AlwaysAllowLocalAuthenticationToken`, and to authorize `changeUser` against the existing entity's stored
CA/EEP.

## Affected / not affected
- **Affected:** multi-tenant EJBCA CE 9.3.7 deployments that use distinct CAs as tenant/administrative
  boundaries with **per-CA** CMP RA secrets and a reachable RA-mode HMAC CMP alias.
- **Not affected:** single-operator deployments where every CMP RA is intentionally trusted across all CAs,
  or deployments using a single global HMAC secret.
