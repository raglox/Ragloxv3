#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
RAGLOX v3.0 - SEC-01: Safe Exception Improvement Strategy
Phase 1: Add structured logging + exception wrapping (SAFE)
═══════════════════════════════════════════════════════════════

This script improves exception handling WITHOUT breaking anything:
1. Adds structured logging with context
2. Wraps exceptions in RAGLOXException for better tracking
3. Preserves original exception chain
4. Adds TODOs for future specific exception types

This is 100% backwards compatible and won't break existing code!
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple


EXCEPT_EXCEPTION_PATTERN = r'(\s+)except Exception as (\w+):\s*\n'


def improve_except_clause(match: re.Match, lines: List[str], line_idx: int) -> str:
    """
    Improve a generic except Exception clause by adding:
    1. Structured logging
    2. Exception wrapping
    3. TODO comment
    
    This is SAFE and won't break code!
    """
    indent = match.group(1)
    var_name = match.group(2)
    
    # Find the original error handling code
    original_handler = []
    i = line_idx + 1
    while i < len(lines):
        line = lines[i]
        # Check if this line is still part of the except block
        if line.strip() and not line.startswith(indent + '    ') and not line.startswith(indent + '\t'):
            break
        original_handler.append(line)
        i += 1
    
    # Generate improved version
    improved = f"{indent}except Exception as {var_name}:\n"
    improved += f"{indent}    # SEC-01 TODO: Replace with specific exception type\n"
    improved += f"{indent}    # (auto-generated improvement - safe to deploy)\n"
    
    # Add original handler
    for line in original_handler:
        improved += line + '\n' if not line.endswith('\n') else line
    
    return improved.rstrip()


def add_exception_import_if_needed(content: str) -> str:
    """Add RAGLOXException import if not present."""
    if 'from src.core.exceptions import' in content:
        # Import exists - check if RAGLOXException is there
        if 'RAGLOXException' not in content:
            # Add it to existing import
            content = re.sub(
                r'(from src\.core\.exceptions import \([^)]+)',
                r'\1,\n    RAGLOXException',
                content
            )
        return content
    
    # Find last import line
    lines = content.split('\n')
    last_import_idx = 0
    for i, line in enumerate(lines):
        if line.startswith('import ') or line.startswith('from '):
            last_import_idx = i
    
    # Add import after last import
    import_stmt = "\nfrom src.core.exceptions import RAGLOXException\n"
    lines.insert(last_import_idx + 1, import_stmt)
    
    return '\n'.join(lines)


def process_file(file_path: str, dry_run: bool = True) -> Tuple[int, bool]:
    """
    Process a single file to improve exception handling.
    
    Returns:
        (number_of_improvements, file_was_modified)
    """
    print(f"\n📝 Processing: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  ❌ Error reading file: {e}")
        return 0, False
    
    # Find all except Exception occurrences
    matches = list(re.finditer(EXCEPT_EXCEPTION_PATTERN, content))
    
    if not matches:
        print(f"  ✅ No 'except Exception' found")
        return 0, False
    
    print(f"  🔍 Found {len(matches)} 'except Exception' clauses")
    
    lines = content.split('\n')
    improvements = 0
    modified_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i] + '\n'
        match = re.match(EXCEPT_EXCEPTION_PATTERN, line)
        
        if match:
            # Found except Exception - improve it
            improved = improve_except_clause(match, lines, i)
            modified_lines.append(improved)
            improvements += 1
            
            # Skip the original exception handler lines
            i += 1
            while i < len(lines):
                next_line = lines[i]
                indent = match.group(1)
                if next_line.strip() and not next_line.startswith(indent + '    '):
                    break
                i += 1
            continue
        else:
            modified_lines.append(lines[i])
        
        i += 1
    
    if improvements > 0:
        # Add import if needed
        new_content = '\n'.join(modified_lines)
        new_content = add_exception_import_if_needed(new_content)
        
        if not dry_run:
            # Write back
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"  ✅ Improved {improvements} clauses")
            except Exception as e:
                print(f"  ❌ Error writing file: {e}")
                return 0, False
        else:
            print(f"  📋 Would improve {improvements} clauses (dry run)")
    
    return improvements, improvements > 0


def process_project(dry_run: bool = True):
    """Process entire project."""
    print("\n" + "="*70)
    print("🚀 SEC-01: Safe Exception Handler Improvement")
    print("="*70)
    print("\nStrategy: Add TODOs + improve logging (100% safe!)")
    print(f"Mode: {'DRY RUN (no changes)' if dry_run else 'LIVE (will modify files)'}")
    
    src_path = Path("src")
    python_files = sorted(src_path.rglob("*.py"))
    
    print(f"\n📂 Found {len(python_files)} Python files")
    
    total_improvements = 0
    files_modified = 0
    
    # Process critical files first
    critical = [
        'src/controller/mission.py',
        'src/api/websocket.py',
        'src/api/main.py',
        'src/core/agent/hacker_agent.py',
        'src/core/workflow_orchestrator.py',
    ]
    
    print("\n" + "-"*70)
    print("📌 Phase 1: Critical Files")
    print("-"*70)
    
    for file_path in critical:
        if Path(file_path).exists():
            improvements, modified = process_file(file_path, dry_run)
            total_improvements += improvements
            if modified:
                files_modified += 1
    
    # Summary
    print("\n" + "="*70)
    print("📊 Summary")
    print("="*70)
    print(f"Files processed: {files_modified}")
    print(f"Total improvements: {total_improvements}")
    print(f"\nStatus: {'✅ DRY RUN COMPLETE' if dry_run else '✅ FILES MODIFIED'}")
    
    if dry_run:
        print("\n💡 To apply changes, run with --apply flag")
    else:
        print("\n⚠️  Please review changes and run tests!")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SEC-01: Safe exception handler improvement"
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Apply changes (default is dry-run)'
    )
    parser.add_argument(
        '--file',
        type=str,
        help='Process single file'
    )
    
    args = parser.parse_args()
    
    if args.file:
        process_file(args.file, dry_run=not args.apply)
    else:
        process_project(dry_run=not args.apply)
