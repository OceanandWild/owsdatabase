const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const packageJsonPath = path.join(rootDir, 'package.json');
const packageLockPath = path.join(rootDir, 'package-lock.json');

function pad2(n) {
  return String(n).padStart(2, '0');
}

function buildVersionFromNow(date) {
  const year = date.getFullYear();
  const month = date.getMonth() + 1;
  const day = date.getDate();
  const hh = pad2(date.getHours());
  const mm = pad2(date.getMinutes());
  const ss = pad2(date.getSeconds());
  return `${year}.${month}.${day}-t${hh}${mm}${ss}`;
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

function main() {
  const now = new Date();
  const newVersion = buildVersionFromNow(now);

  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  pkg.version = newVersion;
  writeJson(packageJsonPath, pkg);

  if (fs.existsSync(packageLockPath)) {
    const lock = JSON.parse(fs.readFileSync(packageLockPath, 'utf8'));
    lock.version = newVersion;
    if (lock.packages && lock.packages['']) {
      lock.packages[''].version = newVersion;
    }
    writeJson(packageLockPath, lock);
  }

  console.log(`[version:stamp] Savage Space Animals -> ${newVersion}`);
}

main();
