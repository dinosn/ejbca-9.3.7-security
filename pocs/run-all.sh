#!/usr/bin/env bash
# One-shot: start the lab, configure it, and run all three PoCs.
# Usage:  ./pocs/run-all.sh        (from the repo root)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export EJBCA_CONTAINER="${EJBCA_CONTAINER:-ejbca}"
export WORK="${WORK:-/tmp/ejbca-poc}"

echo "==================== 0. start EJBCA CE 9.3.7 ===================="
( cd "$ROOT/lab" && docker compose up -d )

echo "==================== 1. configure tenants + CMP aliases ===================="
bash "$ROOT/lab/setup.sh" || { echo "setup failed"; exit 1; }

echo; echo "==================== 2. E-01  cross-CA revocation ===================="
bash "$ROOT/pocs/e01_cross_ca_revoke.sh"

echo; echo "==================== 3. E-01  cross-CA reactivation ===================="
bash "$ROOT/pocs/e01_cross_ca_reactivate.sh"

echo; echo "==================== 4. E-02  cross-tenant end-entity takeover ===================="
bash "$ROOT/pocs/e02_cross_tenant_takeover.sh"

echo; echo "==================== done ===================="
