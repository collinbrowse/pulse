#!/bin/bash
# Builds Pulse.app (self-contained) and installs it to /Applications (or ~/Applications).
#   ./build_app.sh            build + install
#   ./build_app.sh --no-install
set -euo pipefail
cd "$(dirname "$0")"
BUILD=build
APP="$BUILD/Pulse.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "• Compiling native parts"
clang -O2 -w -o "$APP/Contents/Resources/probe" probe.c -framework IOKit -framework CoreFoundation
clang -O2 -w -o "$APP/Contents/Resources/pulse-fand" fand.c -framework IOKit -framework CoreFoundation
swiftc -O -o "$APP/Contents/MacOS/Pulse" app/main.swift -framework AppKit -framework WebKit 2>&1 | grep -v warning || true

echo "• Copying the monitor"
cp server.py storage.py fans.py index.html probe.c fand.c smc.h scanner.c "$APP/Contents/Resources/"

echo "• Drawing the icon"
swiftc -O -o "$BUILD/make_icon" app/make_icon.swift -framework AppKit 2>/dev/null
"$BUILD/make_icon" "$BUILD/Pulse.iconset"
iconutil -c icns "$BUILD/Pulse.iconset" -o "$APP/Contents/Resources/Pulse.icns"

echo "• Pulse Scanner (read-only helper that can be given Full Disk Access)"
# macOS ties Full Disk Access to the scanner's exact code signature. It is only rebuilt when
# scanner.c (or this recipe) changes, so the access you grant survives normal Pulse updates.
SC_KEY=$( (cat scanner.c; echo "scanner-recipe-v2") | shasum -a 256 | cut -c1-16)
SC_CACHE="$BUILD/scanner-cache/$SC_KEY/Pulse Scanner.app"
if [ ! -d "$SC_CACHE" ]; then
  echo "  scanner changed - rebuilding (Full Disk Access will need to be granted again)"
  rm -rf "$BUILD/scanner-cache"
  mkdir -p "$SC_CACHE/Contents/MacOS" "$SC_CACHE/Contents/Resources"
  clang -O2 -w -o "$SC_CACHE/Contents/MacOS/pulse-scanner" scanner.c
  cp "$APP/Contents/Resources/Pulse.icns" "$SC_CACHE/Contents/Resources/"
  cat > "$SC_CACHE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Pulse Scanner</string>
  <key>CFBundleIdentifier</key><string>local.pulse.scanner</string>
  <key>CFBundleExecutable</key><string>pulse-scanner</string>
  <key>CFBundleIconFile</key><string>Pulse</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSBackgroundOnly</key><true/>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
  codesign --force --sign - --identifier local.pulse.scanner "$SC_CACHE" >/dev/null
fi
# Pulse Scanner is installed as its own app next to Pulse (not inside it) and is only replaced
# when the scanner itself changes - so Pulse updates never disturb its Full Disk Access.

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Pulse</string>
  <key>CFBundleDisplayName</key><string>Pulse</string>
  <key>CFBundleIdentifier</key><string>local.pulse.monitor</string>
  <key>CFBundleExecutable</key><string>Pulse</string>
  <key>CFBundleIconFile</key><string>Pulse</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict></plist>
PLIST

# Sign the app; the nested scanner keeps its own (cached) signature.
codesign --force --sign - "$APP" >/dev/null 2>&1 || true

if [ "${1:-}" != "--no-install" ]; then
  DEST=/Applications
  [ -w "$DEST" ] || DEST="$HOME/Applications"
  mkdir -p "$DEST"
  rm -rf "$DEST/Pulse.app"
  cp -R "$APP" "$DEST/"
  echo "✓ Installed $DEST/Pulse.app"
  hash_of() { codesign -dvvv "$1" 2>&1 | grep '^CDHash=' || true; }
  if [ "$(hash_of "$DEST/Pulse Scanner.app")" != "$(hash_of "$SC_CACHE")" ]; then
    rm -rf "$DEST/Pulse Scanner.app"
    cp -R "$SC_CACHE" "$DEST/"
    echo "✓ Installed $DEST/Pulse Scanner.app (new version: grant it Full Disk Access again)"
  else
    echo "✓ Pulse Scanner unchanged - its Full Disk Access is kept"
  fi
else
  echo "✓ Built $APP (scanner: $SC_CACHE)"
fi
