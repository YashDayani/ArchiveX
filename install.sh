#!/bin/sh
# Installs the latest ArchiveX release into /Applications.
#
#   curl -fsSL https://raw.githubusercontent.com/YashDayani/ArchiveX/main/install.sh | sh
#
# The zip is downloaded with curl, which (unlike a browser) does not mark the app as "downloaded from the internet", so macOS opens
# it without the Gatekeeper warning. The zip is checked against the SHA-256 published with the release before anything is installed.
set -eu

REPO="YashDayani/ArchiveX"
DEST="${ARCHIVEX_DEST:-/Applications}"
APP="$DEST/ArchiveX.app"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Finding the latest ArchiveX release…"
json="$(curl -fsSL -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/releases/latest")"
base="$(printf '%s' "$json" | grep -o '"browser_download_url": *"[^"]*ArchiveX.zip"' | head -n1 | sed 's/.*"\(https[^"]*\)"/\1/')"
[ -n "$base" ] || { echo "No ArchiveX.zip found in the latest release." >&2; exit 1; }
sums="${base%ArchiveX.zip}SHA256SUMS"
case "$base" in https://github.com/"$REPO"/releases/download/*) ;; *) echo "Unexpected download location." >&2; exit 1 ;; esac

echo "Downloading…"
curl -fsSL "$base" -o "$tmp/ArchiveX.zip"
curl -fsSL "$sums" -o "$tmp/SHA256SUMS"

want="$(grep ' ArchiveX.zip$' "$tmp/SHA256SUMS" | awk '{print $1}' | head -n1)"
have="$(shasum -a 256 "$tmp/ArchiveX.zip" | awk '{print $1}')"
[ -n "$want" ] && [ "$want" = "$have" ] || { echo "Checksum mismatch; nothing was installed." >&2; exit 1; }

ditto -x -k "$tmp/ArchiveX.zip" "$tmp/out"
[ -d "$tmp/out/ArchiveX.app" ] || { echo "The download does not contain ArchiveX.app." >&2; exit 1; }

osascript -e 'tell application "ArchiveX" to quit' >/dev/null 2>&1 || true
sleep 1
if [ -d "$APP" ]; then mv "$APP" "$tmp/old.app"; fi
ditto "$tmp/out/ArchiveX.app" "$APP"

echo "Installed ArchiveX $(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || true) in $DEST."
open "$APP"
