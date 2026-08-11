#!/usr/bin/env bash
# Deploy attest-proxy to a tee-daemon CVM, from published source.
#
#   TEE_DAEMON_TOKEN=... CVM=https://pod.dstack.soc1024.com bash deploy.sh
#
# This deploys what is on GitHub at REF, not your working tree. That is the
# point: the daemon records the repo and commit it built from, and publishes
# them on the verification record, so a counterparty can clone that commit and
# read the code that handled their credential. A tarball deploy leaves `repo`
# and `commit_sha` empty, which reduces "runs the published code" to a bare hash
# that corresponds to nothing anyone can fetch. Push first, then deploy.
#
# Secrets travel only in the deploy POST's manifest, never in the committed
# source, and are redacted on the daemon's public verifier path. Note they are
# NOT redacted on the authenticated project path, so avoid echoing the response.
set -euo pipefail
: "${TEE_DAEMON_TOKEN:?set TEE_DAEMON_TOKEN}"
: "${CVM:?set CVM=https://your-cvm}"

REPO="${REPO:-https://github.com/amiller/attest-proxy}"
REF="${REF:-main}"

# Invite token gates session creation. This endpoint is reachable from the
# internet, so the app refuses to open sessions at all when it is unset.
# Generated once and kept locally so it never lands in a transcript.
TOKF="$HOME/.claude/attest-proxy-invite-token"
if [ -z "${SESSION_TOKEN:-}" ]; then
  [ -s "$TOKF" ] || { umask 077; openssl rand -hex 16 > "$TOKF"; }
  SESSION_TOKEN=$(cat "$TOKF")
fi

# The handler sees the daemon's internal address, so every URL it mints — invite
# links, relay base_urls — is unreachable without this. The app refuses to mint
# one rather than handing out an address naming its own container.
PUBLIC_BASE="${PUBLIC_BASE:-$CVM/attest-proxy}"
KEY="${ANTHROPIC_API_KEY:-skip}"
MAX_CALLS="${MAX_CALLS:-50}"

umask 077
MF=$(mktemp)
REPO="$REPO" REF="$REF" SESSION_TOKEN="$SESSION_TOKEN" KEY="$KEY" \
MAX_CALLS="$MAX_CALLS" PUBLIC_BASE="$PUBLIC_BASE" python3 -c "
import json, os
print(json.dumps({'name':'attest-proxy','runtime':'deno',
  'source': os.environ['REPO'], 'ref': os.environ['REF'],
  # 'public' controls whether the project shows in the daemon's unauthenticated
  # listing. It does NOT control reachability — an unlisted project is still
  # served at its path, which is why session creation is gated separately.
  'public': os.environ.get('PUBLIC','1') == '1',
  'env':{
  'ANTHROPIC_API_KEY': os.environ['KEY'],
  'SESSION_TOKEN':     os.environ['SESSION_TOKEN'],
  'MAX_CALLS':         os.environ['MAX_CALLS'],
  'PUBLIC_BASE':       os.environ['PUBLIC_BASE']}}))" > "$MF"

curl -sS -m 300 -X POST "$CVM/_api/projects" \
  -H "Authorization: Bearer $TEE_DAEMON_TOKEN" -H "Content-Type: application/json" \
  --data-binary "@$MF" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('deployed', d['name'],
      'commit', d.get('commit_sha','')[:12], 'tree_hash', d.get('tree_hash','')[:16])"
rm -f "$MF"

# A redeploy resets the project to dev; new code has not earned the old code's
# attestation. Until promoted there is no quote and bundles say so.
echo
echo "now promote it, or every receipt will correctly report itself unattested:"
echo "  curl -X POST $CVM/_api/projects/attest-proxy/promote -H \"Authorization: Bearer \$TEE_DAEMON_TOKEN\""
echo
echo "landing: $CVM/attest-proxy/"
echo "invite token is in $TOKF"
