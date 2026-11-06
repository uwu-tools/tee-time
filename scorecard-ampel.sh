#!/usr/bin/env bash

# Copyright 2026 The uwu-tools Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Scorecard collects evidence; AMPEL decides. Runs each case and checks
# AMPEL's exit status against the expected result.
set -euo pipefail

SCORECARD=${SCORECARD:-scorecard}
AMPEL=${AMPEL:-ampel}
BND=${BND:-bnd}
POLICIES=https://raw.githubusercontent.com/carabiner-dev/policies/e0a2c0a55e711359e9ba786cf157f2267f71f9ed/scorecard
: "${GITHUB_AUTH_TOKEN:?set GITHUB_AUTH_TOKEN}"
for t in "$SCORECARD" "$AMPEL" "$BND" go curl; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$(mktemp -d)"

for p in sast token-permissions code-review; do
  curl -fsSL -o "$p.hjson" "$POLICIES/$p.hjson"
done
# Local variants: enforce the advisory token-permissions policy, require
# the SAST check to be present, and require a verified signature.
sed '/enforce: "OFF"/d' token-permissions.hjson >token-permissions-enforced.hjson
sed 's/outputs.sast.all(/size(outputs.sast) > 0 \&\& outputs.sast.all(/' sast.hjson >sast-require-present.hjson
sed 's/code: "outputs.sast.all(/code: "predicates[0].verification.verified \&\& outputs.sast.all(/' sast.hjson >sast-require-signed.hjson

# 1. Collect: one Scorecard run per repo, saved as an in-toto statement.
collect() { # repo checks out
  "$SCORECARD" --repo="github.com/$1" --checks="$2" --format=intoto >"$3" 2>/dev/null
}
collect ossf/scorecard SAST,Token-Permissions,Code-Review scorecard.intoto.json
collect ossf/allstar SAST,Token-Permissions,Code-Review allstar.intoto.json
collect ossf/scorecard License license-only.intoto.json

commit() { sed -n 's/.*"gitCommit":"\([0-9a-f]\{40\}\)".*/\1/p' "$1"; }
SC=$(commit scorecard.intoto.json)
AS=$(commit allstar.intoto.json)
[ -n "$SC" ] && [ -n "$AS" ] || { echo "no gitCommit in Scorecard output" >&2; exit 2; }

# Sign the evidence with a throwaway key; a second key stands in for
# anyone else.
go run "$HERE/keygen.go" signer
go run "$HERE/keygen.go" other
"$BND" statement --signing-backend key -K signer.key --signing-timestamp=false \
  -o scorecard.bundle.json scorecard.intoto.json

# 2. Decide: AMPEL evaluates saved evidence offline; no repository token.
failures=0
check() { # name expected-exit subject evidence policy [public-key]
  local got=0 key=()
  [ -n "${6:-}" ] && key=(-k "$6")
  env -u GITHUB_AUTH_TOKEN "$AMPEL" verify --policy-verify=false -f summary \
    --subject-hash "gitCommit:$3" -a "$4" -p "$5" ${key[@]+"${key[@]}"} >"$1.out" 2>&1 || got=$?
  if { [ "$2" = 0 ] && [ "$got" = 0 ]; } || { [ "$2" != 0 ] && [ "$got" != 0 ]; }; then
    echo "ok   $1 (exit $got)"
  else
    echo "FAIL $1: expected exit $2, got $got"; cat "$1.out"; failures=$((failures + 1))
  fi
}
check pass-sast 0 "$SC" scorecard.intoto.json sast.hjson
# Upstream marks this policy enforce: "OFF": a failure is reported, not fatal.
check advisory-token-perms 0 "$SC" scorecard.intoto.json token-permissions.hjson
check fail-token-perms 1 "$SC" scorecard.intoto.json token-permissions-enforced.hjson
check fail-code-review 1 "$AS" allstar.intoto.json code-review.hjson
check wrong-subject 1 "$SC" allstar.intoto.json sast.hjson
# Evidence that never ran SAST should not pass a "SAST in use" policy.
check missing-check 1 "$SC" license-only.intoto.json sast.hjson
check missing-check-fixed 1 "$SC" license-only.intoto.json sast-require-present.hjson
check pass-sast-fixed 0 "$SC" scorecard.intoto.json sast-require-present.hjson
# Signatures: -a admits evidence whatever its signature, so a policy must
# require one.
check signed 0 "$SC" scorecard.bundle.json sast-require-signed.hjson signer.pub
check signed-wrong-key 1 "$SC" scorecard.bundle.json sast-require-signed.hjson other.pub
check unsigned 1 "$SC" scorecard.intoto.json sast-require-signed.hjson
check signed-wrong-key-not-required 0 "$SC" scorecard.bundle.json sast.hjson other.pub

exit "$failures"
