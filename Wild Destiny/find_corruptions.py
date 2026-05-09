
try:
    with open('index.html', 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    import re
    corrupted_words = {}
    
    for i, line in enumerate(lines):
        if '\ufffd' in line:
            # Find words containing the corruption character
            # We look for sequences of letters handling the corruption char as a letter
            words = re.findall(r'\b\w*\ufffd\w*\b', line)
            for w in words:
                corrupted_words[w] = corrupted_words.get(w, 0) + 1
            
            # Also capture partials if regex fails (e.g. inside strings)
            # Just rough split by space
            for w in line.split():
                if '\ufffd' in w:
                    clean_w = w.strip('",\'();:<>')
                    corrupted_words[clean_w] = corrupted_words.get(clean_w, 0) + 1

    print(f"Found {len(corrupted_words)} unique corrupted tokens.")
    sorted_words = sorted(corrupted_words.items(), key=lambda x: x[1], reverse=True)
    for w, count in sorted_words:
        try:
            print(f"{count}: {w.replace('\ufffd', '?')}")
        except:
            pass

except Exception as e:
    print(e)
