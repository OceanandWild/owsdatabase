const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'index.html');
let content = fs.readFileSync(filePath, 'utf8');
const lines = content.split(/\r?\n/);

// Helper to replace lines
function replaceLines(startLine, endLine, newContent) {
    // startLine and endLine are 1-based
    // array is 0-based
    const startIndex = startLine - 1;
    const deleteCount = endLine - startLine + 1;
    lines.splice(startIndex, deleteCount, ...newContent.split('\n'));
}

// 1. Eco Carmesi (7790-7794)
const ecoCarmesiNew = `            } else if (fw.name === "Eco Carmesi") {
                svgContent = \`
            <defs>
                <radialGradient id="echoCore\${fw.name.replace(/\\s+/g, '')}" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" style="stop-color:#ff6b6b;stop-opacity:1" />
                    <stop offset="50%" style="stop-color:#dc2626;stop-opacity:0.8" />
                    <stop offset="100%" style="stop-color:#7f1d1d;stop-opacity:0.4" />
                </radialGradient>
                <filter id="echoGlow\${fw.name.replace(/\\s+/g, '')}">
                    <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>
            \${Array.from({ length: 5 }).map((_, i) => {
                const radius = w * (0.15 + i * 0.12);
                const opacity = 0.8 - i * 0.15;
                return \`<circle cx="0" cy="\${-h / 2}" r="\${radius}" fill="none" stroke="#ef4444" stroke-width="\${2 - i * 0.3}" opacity="\${opacity}" filter="url(#echoGlow\${fw.name.replace(/\\s+/g, '')})"/>\`;
            }).join('')}
            <rect x="\${-w / 2}" y="\${-h}" width="\${w}" height="\${h}" rx="\${w * 0.1}" fill="url(#echoCore\${fw.name.replace(/\\s+/g, '')})" stroke="#dc2626" stroke-width="1.5"/>
            \${Array.from({ length: 3 }).map((_, i) => {
                const y = -h + h * (0.25 + i * 0.25);
                return \`<ellipse cx="0" cy="\${y}" rx="\${w * 0.35}" ry="\${h * 0.08}" fill="none" stroke="#ff6b6b" stroke-width="1.5" opacity="\${0.6 - i * 0.15}"/>\`;
            }).join('')}
            <circle cx="0" cy="\${-h / 2}" r="\${w * 0.18}" fill="#ff6b6b" opacity="0.6" filter="url(#echoGlow\${fw.name.replace(/\\s+/g, '')})"/>
            <circle cx="0" cy="\${-h / 2}" r="\${w * 0.1}" fill="#ffffff" opacity="0.8"/>
        \`;`;

// 2. Nebula Symphony (7877-7882)
const nebulaSymphonyNew = `            } else if (fw.name === "Nebula Symphony") {
                svgContent = \`
            <defs>
                <radialGradient id="nebulaCore\${fw.name.replace(/\\s+/g, '')}" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" style="stop-color:#e0b3ff;stop-opacity:1" />
                    <stop offset="50%" style="stop-color:#9d4edd;stop-opacity:0.8" />
                    <stop offset="100%" style="stop-color:#4a0072;stop-opacity:0.3" />
                </radialGradient>
                <filter id="nebulaGlow\${fw.name.replace(/\\s+/g, '')}">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>
            <ellipse cx="0" cy="\${-h / 2}" rx="\${w * 0.48}" ry="\${h * 0.35}" fill="url(#nebulaCore\${fw.name.replace(/\\s+/g, '')})" filter="url(#nebulaGlow\${fw.name.replace(/\\s+/g, '')})" opacity="0.6" />
            \${Array.from({ length: 3 }).map((_, i) => {
                const rotation = i * 120;
                return \`<path d="M 0 \${-h / 2} Q \${w * 0.3} \${-h * 0.7} \${w * 0.4} \${-h * 0.5}" fill="none" stroke="#c4b5fd" stroke-width="2" opacity="\${0.6 - i * 0.15}" transform="rotate(\${rotation}, 0, \${-h / 2})"/>\`;
            }).join('')}
            <circle cx="0" cy="\${-h / 2}" r="\${w * 0.2}" fill="#fff" opacity="0.8" filter="url(#nebulaGlow\${fw.name.replace(/\\s+/g, '')})"/>
            \${Array.from({ length: 12 }).map((_, i) => {
                const angle = Math.random() * Math.PI * 2;
                const dist = Math.random() * w * 0.4;
                const x = Math.cos(angle) * dist;
                const y = -h / 2 + Math.sin(angle) * dist * 0.7;
                const size = 0.8 + Math.random() * 1.5;
                return \`<circle cx="\${x.toFixed(2)}" cy="\${y.toFixed(2)}" r="\${size}" fill="#fff" opacity="\${0.5 + Math.random() * 0.5}" />\`;
            }).join('')}
        \`;`;

// 3. Lluvia Sideral (7907-7911)
const lluviaSideralNew = `            } else if (fw.name === "Lluvia Sideral") {
                svgContent = \`
            <defs>
                <linearGradient id="meteorTrail\${fw.name.replace(/\\s+/g, '')}" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#ffffff;stop-opacity:1" />
                    <stop offset="50%" style="stop-color:#87ceeb;stop-opacity:0.6" />
                    <stop offset="100%" style="stop-color:#4a90e2;stop-opacity:0" />
                </linearGradient>
                <filter id="meteorGlow\${fw.name.replace(/\\s+/g, '')}">
                    <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>
            \${Array.from({ length: 6 }).map((_, i) => {
                const x = -w * 0.4 + i * (w * 0.16);
                const startY = -h * (0.75 + Math.random() * 0.15);
                const length = h * (0.6 + Math.random() * 0.2);
                return \`<line x1="\${x}" y1="\${startY}" x2="\${x}" y2="\${startY + length}" stroke="url(#meteorTrail\${fw.name.replace(/\\s+/g, '')})" stroke-width="\${2 + Math.random() * 1.5}" stroke-linecap="round" filter="url(#meteorGlow\${fw.name.replace(/\\s+/g, '')})"/><circle cx="\${x}" cy="\${startY}" r="\${2 + Math.random()}" fill="#ffffff" filter="url(#meteorGlow\${fw.name.replace(/\\s+/g, '')})"/>\`;
            }).join('')}
            \${Array.from({ length: 5 }).map((_, i) => {
                const x = -w * 0.3 + i * (w * 0.15);
                return \`<circle cx="\${x}" cy="\${-h * 0.1}" r="\${1.5 + Math.random()}" fill="#fff" opacity="0.8"/>\`;
            }).join('')}
        \`;`;

// 4. Amanecer Nova (7912-7917)
const amanecerNovaNew = `            } else if (fw.name === "Amanecer Nova") {
                svgContent = \`
            <defs>
                <radialGradient id="novaCore\${fw.name.replace(/\\s+/g, '')}" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" style="stop-color:#fffbeb;stop-opacity:1" />
                    <stop offset="30%" style="stop-color:#ffeb3b;stop-opacity:1" />
                    <stop offset="70%" style="stop-color:#ff8c00;stop-opacity:0.8" />
                    <stop offset="100%" style="stop-color:#ff4500;stop-opacity:0.3" />
                </radialGradient>
                <filter id="novaGlow\${fw.name.replace(/\\s+/g, '')}">
                    <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>
            \${Array.from({ length: 16 }).map((_, i) => {
                const angle = (i / 16) * 360;
                const length = w * (0.35 + Math.random() * 0.15);
                return \`<line x1="0" y1="\${-h * 0.5}" x2="\${Math.cos(angle * Math.PI / 180) * length}" y2="\${-h * 0.5 + Math.sin(angle * Math.PI / 180) * length}" stroke="#ffeb3b" stroke-width="\${1.5 + Math.random() * 0.5}" opacity="\${0.6 + Math.random() * 0.3}" stroke-linecap="round"/>\`;
            }).join('')}
            <circle cx="0" cy="\${-h * 0.5}" r="\${w * 0.4}" fill="none" stroke="#ff8c00" stroke-width="2" opacity="0.4" filter="url(#novaGlow\${fw.name.replace(/\\s+/g, '')})"/>
            <circle cx="0" cy="\${-h * 0.5}" r="\${w * 0.25}" fill="url(#novaCore\${fw.name.replace(/\\s+/g, '')})" filter="url(#novaGlow\${fw.name.replace(/\\s+/g, '')})"/>
            <circle cx="0" cy="\${-h * 0.5}" r="\${w * 0.12}" fill="#ffffff" opacity="0.9"/>
        \`;`;

// 5. Vector Prisma (7918-7922)
const vectorPrismaNew = `            } else if (fw.name === "Vector Prisma") {
                svgContent = \`
            <defs>
                <linearGradient id="prism1\${fw.name.replace(/\\s+/g, '')}" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#ff0000;stop-opacity:0.7" />
                    <stop offset="33%" style="stop-color:#00ff00;stop-opacity:0.7" />
                    <stop offset="66%" style="stop-color:#0000ff;stop-opacity:0.7" />
                    <stop offset="100%" style="stop-color:#ff00ff;stop-opacity:0.7" />
                </linearGradient>
                <linearGradient id="prism2\${fw.name.replace(/\\s+/g, '')}" x1="100%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#00ffff;stop-opacity:0.6" />
                    <stop offset="50%" style="stop-color:#ffff00;stop-opacity:0.6" />
                    <stop offset="100%" style="stop-color:#ff00ff;stop-opacity:0.6" />
                </linearGradient>
                <filter id="prismGlow\${fw.name.replace(/\\s+/g, '')}">
                    <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>
            <polygon points="0,\${-h * 0.9} \${w * 0.4},\${-h * 0.1} \${-w * 0.4},\${-h * 0.1}" fill="url(#prism1\${fw.name.replace(/\\s+/g, '')})" stroke="#ffffff" stroke-width="1.5" filter="url(#prismGlow\${fw.name.replace(/\\s+/g, '')})"/>
            \${['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ff00ff', '#00ffff'].map((color, i) => {
                const spread = (i - 2.5) * 8;
                return \`<line x1="0" y1="\${-h * 0.5}" x2="\${spread}" y2="\${-h * 0.05}" stroke="\${color}" stroke-width="2" opacity="0.6" stroke-linecap="round"/>\`;
            }).join('')}
            <polygon points="0,\${-h * 0.75} \${w * 0.25},\${-h * 0.2} \${-w * 0.25},\${-h * 0.2}" fill="url(#prism2\${fw.name.replace(/\\s+/g, '')})" stroke="#ffffff" stroke-width="1" opacity="0.8"/>
            <circle cx="0" cy="\${-h * 0.9}" r="2" fill="#ffffff" filter="url(#prismGlow\${fw.name.replace(/\\s+/g, '')})"/>
            <circle cx="\${w * 0.4}" cy="\${-h * 0.1}" r="1.5" fill="#ffffff" opacity="0.8"/>
            <circle cx="\${-w * 0.4}" cy="\${-h * 0.1}" r="1.5" fill="#ffffff" opacity="0.8"/>
        \`;`;

// Perform replacements in reverse order to keep line numbers valid
replaceLines(7918, 7922, vectorPrismaNew);
replaceLines(7912, 7917, amanecerNovaNew);
replaceLines(7907, 7911, lluviaSideralNew);
replaceLines(7877, 7882, nebulaSymphonyNew);
replaceLines(7790, 7794, ecoCarmesiNew);

fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
console.log('Successfully updated fireworks!');
