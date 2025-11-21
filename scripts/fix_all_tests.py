#!/usr/bin/env python3
"""
Systematically fix ALL test files to handle APIResponse format.

The API returns: {"success": true, "data": {...}, "error": null}
But tests expect data directly.

This script fixes ALL test files to:
1. Get response with response.json()
2. Extract data = resp["data"]
3. Use data for assertions
"""

import re
from pathlib import Path

def fix_test_file(filepath):
    """Fix a single test file to handle APIResponse format."""
    with open(filepath, 'r') as f:
        content = f.read()

    original_content = content

    # Pattern 1: data = response.json() followed by assertions on data
    # Need to add extraction of nested data object

    # Find all instances of: data = response.json()
    # and add: data = data["data"] if "data" in data else data

    lines = content.split('\n')
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        # Check if this line assigns response.json()
        if re.search(r'(\w+)\s*=\s*(?:await\s+)?response\.json\(\)', line):
            var_name = re.search(r'(\w+)\s*=\s*(?:await\s+)?response\.json\(\)', line).group(1)

            # Check if next lines don't already extract data
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if 'success' not in next_line and '["data"]' not in next_line:
                    # Add data extraction
                    indent = len(line) - len(line.lstrip())
                    new_lines.append(' ' * indent + f'if "data" in {var_name} and isinstance({var_name}, dict):')
                    new_lines.append(' ' * (indent + 4) + f'{var_name} = {var_name}["data"]')

        i += 1

    content = '\n'.join(new_lines)

    # Only write if changed
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

if __name__ == '__main__':
    test_dir = Path('/mnt/d/activity/auth-service/tests')
    test_files = list(test_dir.glob('test_*.py'))

    print(f"Found {len(test_files)} test files")

    fixed = 0
    for test_file in test_files:
        if fix_test_file(test_file):
            print(f"✅ Fixed: {test_file.name}")
            fixed += 1
        else:
            print(f"⏭️  Skipped: {test_file.name} (no changes needed)")

    print(f"\n✅ Fixed {fixed}/{len(test_files)} test files")
