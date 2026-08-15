#!/usr/bin/env bash
# Prepare a multi-tenant EJBCA CE lab: two CAs (ManagementCA = "Tenant A", CA-B = "Tenant B"),
# per-CA CMP RA secrets, and two CMP RA-mode HMAC aliases (one for revocation, one for enrollment).
# Re-runnable. Requires: docker (container named per $C), openssl on the host.
set -u
C="${EJBCA_CONTAINER:-ejbca}"
WORK="${WORK:-/tmp/ejbca-poc}"
J() { docker exec "$C" /opt/keyfactor/bin/ejbca.sh "$@" 2>&1 | grep -viE "cannot find name for user ID"; }
mkdir -p "$WORK"; cd "$WORK" || exit 1

echo "== waiting for EJBCA to answer on :8080 =="
for i in $(seq 1 60); do
  curl -sf -o /dev/null "http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth" && break
  sleep 5
done

echo "== 1. create CA-B (Tenant B), distinct from the built-in ManagementCA (Tenant A) =="
J ca init --caname CA-B --dn "CN=CA-B,O=Tenant B" --tokenType soft --tokenPass foo123 \
  --keyspec 2048 --keytype RSA -v 3650 --policy null -s SHA256WithRSA | grep -iE "created|already|error" | head -1

echo "== 2. per-CA CMP RA secrets: secretA on ManagementCA, secretB on CA-B =="
J ca editca --caname ManagementCA --field cmpRaAuthSecret --value secretA | grep -iE "returned value|error" | head -1
J ca editca --caname CA-B         --field cmpRaAuthSecret --value secretB | grep -iE "returned value|error" | head -1

echo "== 3. export CA certs + derive the ManagementCA subject DN (instance-specific UID) =="
J ca getcacert --caname ManagementCA -f /tmp/mca.pem >/dev/null 2>&1; docker cp "$C:/tmp/mca.pem" "$WORK/mca.pem" >/dev/null 2>&1
J ca getcacert --caname CA-B         -f /tmp/cab.pem >/dev/null 2>&1; docker cp "$C:/tmp/cab.pem" "$WORK/cab.pem" >/dev/null 2>&1
# openssl -recipient wants the slash form; build it from the RFC2253 subject (reverse RDN order).
MCA_RFC=$(openssl x509 -in mca.pem -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject= *//')
MCA_SLASH="/$(echo "$MCA_RFC" | awk -F', *' '{for(i=NF;i>=1;i--) printf "%s%s", $i, (i>1?"/":"")}')"
echo "$MCA_SLASH" > "$WORK/mca_dn.txt"
echo "  ManagementCA recipient DN: $MCA_SLASH"

echo "== 4a. CMP RA alias 'ratest' for REVOCATION (KeyId-derived CA) =="
J config cmp addalias ratest >/dev/null 2>&1
J config cmp updatealias --alias ratest --key operationmode          --value ra   >/dev/null
J config cmp updatealias --alias ratest --key authenticationmodule   --value HMAC >/dev/null
J config cmp updatealias --alias ratest --key authenticationparameters --value -  >/dev/null   # '-' => fall through to per-CA secret
J config cmp updatealias --alias ratest --key ra.caname              --value KeyId >/dev/null
J config cmp updatealias --alias ratest --key ra.endentityprofile    --value KeyId >/dev/null
J config cmp updatealias --alias ratest --key ra.certificateprofile  --value KeyId >/dev/null
J config cmp updatealias --alias ratest --key allowraverifypopo      --value true  >/dev/null

echo "== 4b. CMP RA alias 'enrA' for ENROLLMENT, pinned to ManagementCA =="
J config cmp addalias enrA >/dev/null 2>&1
J config cmp updatealias --alias enrA --key operationmode            --value ra    >/dev/null
J config cmp updatealias --alias enrA --key authenticationmodule     --value HMAC  >/dev/null
J config cmp updatealias --alias enrA --key authenticationparameters --value -     >/dev/null
J config cmp updatealias --alias enrA --key ra.caname                --value ManagementCA >/dev/null
J config cmp updatealias --alias enrA --key defaultca                --value ManagementCA >/dev/null
J config cmp updatealias --alias enrA --key ra.endentityprofile      --value EMPTY   >/dev/null
J config cmp updatealias --alias enrA --key ra.certificateprofile    --value ENDUSER >/dev/null
J config cmp updatealias --alias enrA --key ra.namegenerationscheme  --value DN    >/dev/null
J config cmp updatealias --alias enrA --key ra.namegenerationparameters --value CN >/dev/null
J config cmp updatealias --alias enrA --key allowraverifypopo        --value true  >/dev/null

echo "== setup complete. CAs: =="; J ca listcas | grep -i "CA Name:" | head
