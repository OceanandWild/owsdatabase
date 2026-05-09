"""
Fix text corruption (mojibake) in index.html
The issue is UTF-8 characters being incorrectly encoded.
"""

# Read file with UTF-8 encoding
with open('index.html', 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Dictionary of corrupted text -> correct HTML entity replacements
replacements = {
    # Trophy emoji (HUD score)
    'ðŸ†': '&#x1F3C6;',
    
    # Temple/Sanctuary emoji
    'ðŸ›ï¸': '&#x1F3DB;&#xFE0F;',
    
    # Shield emoji (multiple places)
    'ðŸ›¡ï¸': '&#x1F6E1;&#xFE0F;',
    'ðŸ›&iexcl;ï¸': '&#x1F6E1;&#xFE0F;',
    
    # Stopwatch/timer emoji
    'â±ï¸': '&#x23F1;&#xFE0F;',
    
    # Star emoji
    'â­': '&#x2B50;',
    
    # Fix CAPITÁN (Spanish accented character)
    'CAPITÃN': 'CAPIT&Aacute;N',
}

# Apply all replacements
for old, new in replacements.items():
    if old in content:
        content = content.replace(old, new)
        print(f"Fixed: '{old}' -> '{new}'")
    else:
        print(f"Not found: '{old}'")

# Write the fixed content back
with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("\n All text corruption has been fixed!")
