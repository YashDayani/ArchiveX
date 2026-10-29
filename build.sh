#!/bin/zsh
# Builds ArchiveX.app as a universal binary (Apple Silicon + Intel), macOS 13 or later.
#
# ArchiveX has no third-party runtime dependencies: the archive engine (Sources/Core) is part of the
# app. You only need Xcode (or its Command Line Tools); Xcode 26+ is needed for the Liquid Glass icon,
# older toolchains fall back to AppIcon.icns.
set -euo pipefail
cd "$(dirname "$0")"
APP="build/ArchiveX.app"
MIN="13.0"
VERSION="${ARCHIVEX_VERSION:-1.0}"

rm -rf build
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" build/slices

for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -parse-as-library -target "$arch-apple-macos$MIN" \
    Sources/*.swift Sources/Core/*.swift -o "build/slices/ArchiveX-$arch"
done
lipo -create build/slices/ArchiveX-arm64 build/slices/ArchiveX-x86_64 -output "$APP/Contents/MacOS/ArchiveX"
rm -rf build/slices

sed "s/__VERSION__/$VERSION/g" Info.plist > "$APP/Contents/Info.plist"
[ -f logo.svg ] && cp logo.svg "$APP/Contents/Resources/logo.svg"


# App icon: Icon Composer file (Liquid Glass on macOS 26+, flat .icns on older systems), compiled by Xcode's actool.
if xcrun actool ArchiveX.icon --compile "$APP/Contents/Resources" --output-format human-readable-text \
     --notices --warnings --errors --output-partial-info-plist build/icon-partial.plist \
     --app-icon ArchiveX --include-all-app-icons --target-device mac --platform macosx \
     --minimum-deployment-target "$MIN" >/dev/null 2>&1; then
  :
else
  echo "warning: actool failed; falling back to AppIcon.icns" >&2
  [ -f AppIcon.icns ] && cp AppIcon.icns "$APP/Contents/Resources/ArchiveX.icns"
fi

# Signing: with ARCHIVEX_SIGN_IDENTITY (a "Developer ID Application: ..." certificate) the app is signed for
# distribution with the hardened runtime, ready for notarization. Without it, an ad-hoc signature is used.
if [ -n "${ARCHIVEX_SIGN_IDENTITY:-}" ]; then
  codesign --force --deep --options runtime --timestamp -s "$ARCHIVEX_SIGN_IDENTITY" "$APP"
else
  codesign --force --deep -s - "$APP" >/dev/null 2>&1 || true
fi
echo "Built $APP ($(lipo -archs "$APP/Contents/MacOS/ArchiveX"))"
