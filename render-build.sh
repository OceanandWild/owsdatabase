  #!/usr/bin/env bash
  set -e
  apt-get update
  apt-get install -y ffmpeg \
    fonts-liberation libasound2 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxrandr2 libgbm1 libgtk-3-0 ca-certificates
  npm ci
