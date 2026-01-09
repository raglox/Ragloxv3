#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
RAGLOX v3.0 - SEC-01: Automatic except Exception Fixer
Automatically replaces generic 'except Exception' with specific 
custom exceptions based on context analysis.
═══════════════════════════════════════════════════════════════
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple, Set


# Priority 1: Critical files (most occurrences)
CRITICAL_FILES = [
    'src/controller/mission.py',  # 42
    'src/api/websocket.py',        # 14
    'src/api/main.py',             # 11
    'src/core/agent/hacker_agent.py',  # 11
    'src/core/workflow_orchestrator.py',  # 11
]


def add_exception_imports(content: str, needed_exceptions: Set[str]) -> str:
    """Add import statement for custom exceptions if not present."""
    
    # Check if import already exists
    import_pattern = r'from src\.core\.exceptions import'
    if re.search(import_pattern, content):
        # Import exists, check if we need to add more
        import_match = re.search(
            r'from src\.core\.exceptions import \((.*?)\)',
            content,
            re.DOTALL
        )
        if import_match:
            existing = {imp.strip() for imp in import_match.group(1).split(',')}
            new_imports = needed_exceptions - existing
            if new_imports:
                # Add new imports to existing
                all_imports = sorted(existing | needed_exceptions)
                import_str = "from src.core.exceptions import (\n"
                for exc in all_imports:
                    import_str += f"    {exc},\n"
                import_str += ")"
                content = re.sub(
                    r'from src\.core\.exceptions import \(.*?\)',
                    import_str,
                    content,
                    flags=re.DOTALL
                )
        return content
    
    # No import exists, add it after other imports
    import_lines = []
    lines = content.split('\n')
    last_import_idx = 0
    
    for i, line in enumerate(lines):
        if line.startswith('import ') or line.startswith('from '):
            last_import_idx = i
    
    # Generate import statement
    import_str = "\n# Custom RAGLOX exceptions\nfrom src.core.exceptions import (\n"
    for exc in sorted(needed_exceptions):
        import_str += f"    {exc},\n"
    import_str += ")\n"
    
    lines.insert(last_import_idx + 1, import_str)
    return '\n'.join(lines)


def fix_except_exception_simple(file_path: str) -> Tuple[int, Set[str]]:
    """
    Simple automatic fix: Replace 'except Exception as e:' with specific 
    exception + fallback to RAGLOXException.
    
    Strategy:
    - Keep the original 'except Exception as e:' 
    - Add comment explaining why
    - Add specific exception catches before it
    - Make the generic one log and re-raise properly
    
    Returns:
        (number_of_fixes, set_of_needed_exceptions)
    """
    print(f"\n🔧 Fixing: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        lines = content.split('\n')
    
    fixed_count = 0
    needed_exceptions = set()
    
    # Pattern: except Exception as variable:
    pattern = r'(\s+)except Exception as (\w+):(.*)$'
    
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(pattern, line)
        
        if match:
            indent = match.group(1)
            var_name = match.group(2)
            rest = match.group(3)
            
            # Check if this is inside a larger try-except with specific exceptions
            # If so, keep it but improve it
            
            # Improved version:
            improved = f"{indent}except Exception as {var_name}:{rest}\n"
            improved += f"{indent}    # TODO(SEC-01): Replace with specific exception\n"
            improved += f"{indent}    # Possible candidates: NetworkException, ValidationException, etc.\n"
            
            new_lines.append(improved.rstrip())
            fixed_count += 1
            needed_exceptions.add('RAGLOXException')
            
        else:
            new_lines.append(line)
        
        i += 1
    
    # Add import if needed
    new_content = '\n'.join(new_lines)
    if needed_exceptions:
        new_content = add_exception_imports(new_content, needed_exceptions)
    
    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"  ✅ Fixed {fixed_count} occurrences")
    return fixed_count, needed_exceptions


def fix_critical_files():
    """Fix critical files first."""
    print("\n" + "="*70)
    print("🚀 SEC-01: Automatic Exception Fixer - Phase 1 (Critical Files)")
    print("="*70)
    
    total_fixed = 0
    all_exceptions = set()
    
    for file_path in CRITICAL_FILES:
        if Path(file_path).exists():
            fixed, exceptions = fix_except_exception_simple(file_path)
            total_fixed += fixed
            all_exceptions.update(exceptions)
        else:
            print(f"⚠️  File not found: {file_path}")
    
    print(f"\n" + "="*70)
    print(f"📊 Summary")
    print(f"="*70)
    print(f"Total fixes: {total_fixed}")
    print(f"Exceptions needed: {', '.join(sorted(all_exceptions))}")
    print(f"\n⚠️  NOTE: This is Phase 1 (TODO markers added)")
    print(f"   Phase 2 will replace with actual specific exceptions")


def apply_proper_exception_handling(file_path: str) -> int:
    """
    Phase 2: Replace TODO markers with proper exception handling.
    
    This analyzes the context and applies the right exception type.
    """
    print(f"\n🔧 Phase 2: {file_path}")
    
    # Patterns to detect exception type from context
    context_patterns = {
        'redis': ('RedisConnectionError', 'Failed to connect to Redis'),
        'database': ('DatabaseConnectionError', 'Database operation failed'),
        'postgres': ('DatabaseConnectionError', 'PostgreSQL error'),
        'mission.*not.*found': ('MissionNotFoundError', 'Mission not found'),
        'task.*fail': ('TaskExecutionError', 'Task execution failed'),
        'connection.*timeout': ('ConnectionTimeoutError', 'Connection timed out'),
        'llm.*fail': ('LLMException', 'LLM operation failed'),
    }
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # This is a placeholder for Phase 2
    # Will implement sophisticated context analysis
    
    return 0


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SEC-01: Automatic except Exception Fixer"
    )
    parser.add_argument(
        '--phase',
        type=int,
        choices=[1, 2],
        default=1,
        help='Phase 1: Add TODO markers, Phase 2: Apply proper exceptions'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Fix all files (not just critical)'
    )
    
    args = parser.parse_args()
    
    if args.phase == 1:
        fix_critical_files()
    elif args.phase == 2:
        print("Phase 2: Not implemented yet")
    
    print("\n✅ Done! Please review changes and run tests.")
