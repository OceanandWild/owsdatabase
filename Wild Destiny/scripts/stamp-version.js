const fs = require("fs");
const path = require("path");

const pkgPath = path.join(__dirname, "..", "package.json");
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
const now = new Date();

const major = now.getUTCFullYear();
const minor = now.getUTCMonth() + 1;
const patch = now.getUTCDate();
const hh = String(now.getUTCHours()).padStart(2, "0");
const mm = String(now.getUTCMinutes()).padStart(2, "0");

pkg.version = `${major}.${minor}.${patch}-t${hh}${mm}`;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n", "utf8");
console.log(`Stamped Wild Destiny version: ${pkg.version}`);
