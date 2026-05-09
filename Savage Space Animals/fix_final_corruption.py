
import os

file_path = r"c:\Users\HP\Desktop\Ocean and Wild Studios\Savage Space Animals\index.html"

# Define the replacements map
replacements = {
    "ðŸ †": "&#x1F3C6;",
    "ðŸ ›ï¸ ": "&#x1F3DB;&#xFE0F;",
    "â­ ": "&#x2B50;",
    "CAPITÃ N": "CAPIT&Aacute;N",
    "ðŸ›&iexcl;ï¸ ": "&#x1F6E1;&#xFE0F;",
    "â ±ï¸ ": "&#x23F1;&#xFE0F;",
    "ðŸ›¡ï¸ ": "&#x1F6E1;&#xFE0F;", # Alternative shield
    "ðŸ›¡": "&#x1F6E1;&#xFE0F;",    # Alternative shield
    "Ã¡": "&aacute;",
    "Ã©": "&eacute;",
    "Ã­": "&iacute;",
    "Ã³": "&oacute;",
    "Ãº": "&uacute;",
    "Ã±": "&ntilde;",
    "Ã‘": "&Ntilde;",
    "Â¿": "&iquest;",
    "Â¡": "&iexcl;"
}

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Apply replacements
for bad, good in replacements.items():
    content = content.replace(bad, good)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed text corruption.")
