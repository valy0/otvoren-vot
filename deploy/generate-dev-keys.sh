#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$SCRIPT_DIR/keys"
openssl genpkey -algorithm Ed25519 -out "$SCRIPT_DIR/keys/auth-private.pem"
openssl pkey -in "$SCRIPT_DIR/keys/auth-private.pem" -pubout -out "$SCRIPT_DIR/keys/auth-public.pem"
echo "Generated Ed25519 key pair in deploy/keys/"
echo "  Private: keys/auth-private.pem"
echo "  Public:  keys/auth-public.pem"
