
import fs from 'fs';
import path from 'path';
import process from 'process';

const filePath = path.join(process.cwd(), 'index.html');

try {
    const data = fs.readFileSync(filePath, 'utf8');
    const lines = data.split(/\r?\n/);

    // Lines to remove are 11211 to 12552 (1-based)
    // 0-based index: 11210 to 12551

    // Check context (safety check)
    // Line 11210 (0-based) should be empty '        ' (line 11211 in file) or close to the garbage start
    // The previous check showed line 11211 starts with "// ════"

    // We want to KEEP lines 0 to 11209 (indices)
    // We want to KEEP lines from 12552 onwards (indices)

    // Keep 0..11209 (which is lines 1..11210)
    // Skip 11210..12551 (which is lines 11211..12552)
    // Keep 12552.. (which is lines 12553..)

    const keepStart = lines.slice(0, 11210);
    const keepEnd = lines.slice(12552);

    console.log("Last kept line (expect empty/brace):", keepStart[keepStart.length - 1]);
    console.log("First kept line (expect empty):", keepEnd[0]);
    console.log("Next kept line (expect drawCone):", keepEnd[1]);

    const newContent = keepStart.concat(keepEnd).join('\n');

    fs.writeFileSync(filePath, newContent, 'utf8');
    console.log('Successfully cleaned up index.html');

} catch (err) {
    console.error('Error:', err);
    process.exit(1);
}
