with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = [
    ('\u00f0\u0178\u2020', '&#x1F3C6;'),
    ('\u00f0\u0178\u203a\u00ef\u00b8', '&#x1F3DB;&#xFE0F;'),
    ('\u00f0\u0178\u203a&iexcl;\u00ef\u00b8', '&#x1F6E1;&#xFE0F;'),
    ('\u00e2\u00b1\u00ef\u00b8', '&#x23F1;&#xFE0F;'),
    ('\u00e2\u00ad', '&#x2B50;'),
    ('CAPIT\u00c3N', 'CAPIT&Aacute;N'),
]

fixed = 0
for old, new in fixes:
    if old in content:
        count = content.count(old)
        content = content.replace(old, new)
        fixed += count
        print(f'Fixed {count}x: {repr(old)}')

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print(f'Total: {fixed}')
