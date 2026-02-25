const fs = require("fs");
const path = require("path");

const packagePath = path.join(__dirname, "..", "package.json");
const pkg = JSON.parse(fs.readFileSync(packagePath, "utf8"));

const now = new Date();
const yyyy = now.getFullYear();
const mm = now.getMonth() + 1;
const dd = now.getDate();
const hh = String(now.getHours()).padStart(2, "0");
const min = String(now.getMinutes()).padStart(2, "0");
// Semver-safe prerelease: avoid purely numeric identifiers with leading zeroes.
const version = `${yyyy}.${mm}.${dd}-t${hh}${min}`;

pkg.version = version;
fs.writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
console.log(`[version:stamp] Ocean Pay -> ${version}`);
