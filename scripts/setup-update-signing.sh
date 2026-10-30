#!/bin/sh
# One-time setup of signed updates. Run it yourself, in a terminal, from anywhere inside the repository:
#
#   scripts/setup-update-signing.sh
#
# It makes a new Ed25519 key pair, stores the PRIVATE key as the GitHub secret UPDATE_SIGNING_KEY, and writes the PUBLIC key into
# Sources/UpdateKey.swift. Then commit that file and publish a release: the app checks every update against that public key.
#
# Needs the GitHub CLI, signed in as someone who can edit this repository's secrets (brew install gh && gh auth login).
# The private key is never saved on disk except for a moment in a private temporary folder. You are offered it once so you can put a
# backup in your password manager: if the secret is ever lost, a new key means shipping a new app before updates work again.
set -eu

REPO="YashDayani/ArchiveX"
cd "$(dirname "$0")/.."

command -v gh >/dev/null 2>&1 || { echo "Install the GitHub CLI first:  brew install gh   then   gh auth login" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in to GitHub first:  gh auth login" >&2; exit 1; }
if grep -Eq 'publicKeyBase64 = "[A-Za-z0-9+/=]{40,}"' Sources/UpdateKey.swift; then
  echo "A public key is already set in Sources/UpdateKey.swift. Replacing it means every installed copy of ArchiveX stops accepting updates until" >&2
  echo "people reinstall. If you really want a new key, empty publicKeyBase64 in that file and run this again." >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

swift scripts/generate_update_key.swift "$tmp"
gh secret set UPDATE_SIGNING_KEY --repo "$REPO" < "$tmp/private.b64"

pub="$(cat "$tmp/public.b64")"
sed -i '' "s|publicKeyBase64 = \"\"|publicKeyBase64 = \"$pub\"|" Sources/UpdateKey.swift
grep -q "$pub" Sources/UpdateKey.swift || { echo "Could not write the public key into Sources/UpdateKey.swift" >&2; exit 1; }

echo
echo "Done."
echo "  - The private key is stored as the GitHub secret UPDATE_SIGNING_KEY."
echo "  - The public key is now in Sources/UpdateKey.swift."
echo
printf "Show the private key once, so you can save a backup in your password manager? [y/N] "
read -r answer
case "$answer" in
  y|Y) echo; cat "$tmp/private.b64"; echo; echo "Save it somewhere safe. Anyone with it can sign updates."; ;;
esac
echo
echo "Next: commit and push Sources/UpdateKey.swift, then publish a release."
