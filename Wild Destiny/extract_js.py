
import re

try:
    with open('index.html', 'r', encoding='utf-8') as f:
        content = f.read()

    # Find all script tags
    scripts = re.split(r'<script.*?>', content)
    
    combined_js = ""
    # Skip the first items which is before the first script tag
    for i in range(1, len(scripts)):
        script_content = scripts[i].split('</script>')[0]
        # We need to preserve line numbers to some extent to map back errors
        # But since we are concatenating, it's hard.
        # Better approach: Replace non-script content with newlines so line numbers match exactly.
        
    # Re-read to do the line-preserving extraction
    lines = content.splitlines()
    js_lines = []
    in_script = False
    
    for line in lines:
        if '<script' in line:
            in_script = True
            # Keep the line but comment out the html part if mixed, 
            # or just assume script starts on next line if it's a simple tag.
            # Simplified: just output the line as is if it's code, or blank if HTML.
            # Actually, standard HTML has <script> then code.
            js_lines.append('// ' + line) # Comment out the script tag line
        elif '</script>' in line:
            in_script = False
            js_lines.append('// ' + line)
        else:
            if in_script:
                js_lines.append(line)
            else:
                js_lines.append('') # Empty line to preserve line count
                
    with open('temp_check.js', 'w', encoding='utf-8') as f:
        f.write('\n'.join(js_lines))
        
    print("Extracted JS to temp_check.js preserving line numbers.")

except Exception as e:
    print(e)
