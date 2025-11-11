#!/usr/bin/env bash
set -euo pipefail

ROOT="$PWD"

# 1) Download static FFmpeg (amd64) and place it in ./bin
mkdir -p "$ROOT/bin"
cd /tmp
curl -fsSL https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz -o ffmpeg.tar.xz
tar -xJf ffmpeg.tar.xz
D=$(find . -maxdepth 1 -type d -name "ffmpeg-*-amd64-static" | head -n1)
cp "$D/ffmpeg" "$D/ffprobe" "$ROOT/bin/"
chmod +x "$ROOT/bin/ffmpeg" "$ROOT/bin/ffprobe"

# 2) Install Node deps (Puppeteer must be in dependencies)
cd "$ROOT"
npm ci
# If you have a build step, uncomment:
# npm run build
