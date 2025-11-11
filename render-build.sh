#!/usr/bin/env bash
set -e

# 1) System deps for ffmpeg + headless Chromium
apt-get update
apt-get install -y ffmpeg \
  fonts-liberation libasound2 libatk1.0-0 libatk-bridge2.0-0 \
  libcups2 libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
  libxrandr2 libgbm1 libgtk-3-0 ca-certificates

# 2) Install Node deps (Puppeteer downloads Chromium here)
npm ci

# 3) Optional: if you have a build step
#  npm run build
