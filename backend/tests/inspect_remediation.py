import re
from pathlib import Path

content = Path('sample-projects/vulnerable-python/backend/database.py').read_text(encoding='utf-8')
unsafe_sql_pattern = r'query\s*=\s*f["\']SELECT\s+id,\s*username,\s*email,\s*role\s+FROM\s+users\s+WHERE\s+username\s*=\s*[\'"]\{search_term\}[\'"]\s+OR\s+email\s*=\s*[\'"]\{search_term\}[\'"]["\']\s*\n\s*try:\s*\n\s*cursor\.execute\(query\)'

print("Raw has \\r\\n:", "\r\n" in content)
print("Direct search:", bool(re.search(unsafe_sql_pattern, content)))
print("Unix newlines search:", bool(re.search(unsafe_sql_pattern, content.replace("\r\n", "\n"))))

# Let's inspect the lines around line 20-30
lines = content.splitlines()
for i, line in enumerate(lines[18:30], 19):
    print(f"{i}: {repr(line)}")
