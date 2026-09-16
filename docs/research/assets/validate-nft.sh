#!/bin/bash
# Read-only nftables syntax validator for MyVpn design snippets.
# nft -c -f parses+validates the whole batch WITHOUT committing it.
# Semantics of results (verified on nftables v1.0.2, no root):
#   stderr contains "Error:"          -> SYNTAX/semantic error in the ruleset
#   empty output, exit 1              -> ruleset PARSED OK; commit needs root
#   exit 0                            -> parsed OK (rare without root)
# So: treat "no stderr output" as PASS.
f="$1"
out=$(nft -c -f "$f" 2>&1)
if [ -n "$out" ]; then
  echo "FAIL: $f"
  echo "$out" | sed 's/^/      /'
  exit 1
fi
echo "PASS: $f"
