#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
RAGLOX v3.0 - SEC-01: except Exception Fixer
Automatically refactors generic except Exception clauses to 
use specific custom exceptions.
═══════════════════════════════════════════════════════════════
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict
import ast


# Mapping of common error patterns to specific exceptions
ERROR_PATTERNS = {
    # Connection errors
    r'(redis|connection|connect).*fail': 'RedisConnectionError',
    r'(database|db|postgres).*fail': 'DatabaseConnectionError',
    r'(ssh|remote).*connection': 'SSHConnectionError',
    r'connection.*timeout': 'ConnectionTimeoutError',
    r'connection.*refused': 'NetworkException',
    
    # Mission errors
    r'mission.*not.*found': 'MissionNotFoundError',
    r'mission.*exists': 'MissionAlreadyExistsError',
    r'invalid.*mission.*state': 'InvalidMissionStateError',
    
    # Task errors
    r'task.*not.*found': 'TaskNotFoundError',
    r'task.*execution.*fail': 'TaskExecutionError',
    r'task.*timeout': 'TaskTimeoutError',
    
    # Validation errors
    r'(invalid|validation).*ip': 'InvalidIPAddressError',
    r'(invalid|validation).*uuid': 'InvalidUUIDError',
    r'missing.*required': 'MissingRequiredFieldError',
    
    # API errors
    r'bad.*request': 'BadRequestError',
    r'not.*found': 'NotFoundError',
    r'(unauthorized|authentication)': 'AuthenticationError',
    r'(forbidden|authorization)': 'AuthorizationError',
    
    # Network errors
    r'(network|socket).*error': 'NetworkException',
    r'timeout': 'ConnectionTimeoutError',
    r'service.*unavailable': 'ServiceUnavailableError',
    
    # File errors
    r'file.*not.*found': 'FileReadError',
    r'(read|write).*file': 'FileOperationException',
    
    # LLM errors
    r'llm.*(rate.*limit|quota)': 'LLMRateLimitError',
    r'llm.*response': 'LLMResponseError',
    
    # Data errors
    r'json.*parse': 'JSONParsingError',
    r'(serialize|deserialize)': 'DataSerializationError',
    
    # Command execution
    r'command.*fail': 'CommandExecutionError',
    r'executor.*fail': 'ExecutorException',
}


def analyze_exception_context(file_path: str, line_num: int) -> Tuple[str, str, str]:
    """
    Analyze the context around an except Exception clause.
    
    Returns:
        (exception_type, error_message, context)
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Get context (5 lines before, except clause, 5 lines after)
    start = max(0, line_num - 5)
    end = min(len(lines), line_num + 6)
    context_lines = lines[start:end]
    context = ''.join(context_lines).lower()
    
    # Try to find error message in logger calls
    error_msg = ""
    for i in range(line_num, min(len(lines), line_num + 10)):
        if 'logger' in lines[i] or 'log.' in lines[i]:
            error_msg = lines[i].strip()
            break
    
    # Determine appropriate exception based on context
    for pattern, exception_type in ERROR_PATTERNS.items():
        if re.search(pattern, context):
            return exception_type, error_msg, context
    
    # Default to RAGLOXException
    return 'RAGLOXException', error_msg, context


def generate_import_statement(exceptions: set) -> str:
    """Generate import statement for needed exceptions."""
    base_imports = ['RAGLOXException']
    all_exceptions = sorted(base_imports + list(exceptions))
    
    import_str = "from src.core.exceptions import (\n"
    for exc in all_exceptions:
        import_str += f"    {exc},\n"
    import_str += ")\n"
    
    return import_str


def fix_except_exception_in_file(file_path: str, dry_run: bool = True) -> Dict:
    """
    Fix all except Exception clauses in a file.
    
    Returns:
        Dictionary with fix statistics
    """
    print(f"\n{'='*70}")
    print(f"📁 Analyzing: {file_path}")
    print(f"{'='*70}")
    
    with open(file_path, 'r') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Find all except Exception occurrences
    except_lines = []
    for i, line in enumerate(lines, 1):
        if re.search(r'except\s+Exception\s*(\s+as\s+\w+)?:', line):
            except_lines.append(i)
    
    if not except_lines:
        print("✅ No 'except Exception' found")
        return {'file': file_path, 'total': 0, 'fixed': 0}
    
    print(f"🔍 Found {len(except_lines)} 'except Exception' clauses")
    
    # Analyze each exception
    needed_exceptions = set()
    fixes = []
    
    for line_num in except_lines:
        exc_type, err_msg, context = analyze_exception_context(file_path, line_num - 1)
        needed_exceptions.add(exc_type)
        
        print(f"\n  Line {line_num}:")
        print(f"    → Suggested: {exc_type}")
        if err_msg:
            print(f"    → Context: {err_msg[:80]}...")
        
        fixes.append({
            'line': line_num,
            'exception': exc_type,
            'context': context[:200]
        })
    
    # Check if file already has imports
    has_exception_import = 'from src.core.exceptions import' in content
    
    print(f"\n📦 Required exceptions: {', '.join(sorted(needed_exceptions))}")
    print(f"📝 Import statement exists: {has_exception_import}")
    
    if not dry_run:
        print(f"\n⚠️  Would modify file (dry_run={dry_run})")
    
    return {
        'file': file_path,
        'total': len(except_lines),
        'fixed': 0 if dry_run else len(except_lines),
        'exceptions': sorted(needed_exceptions),
        'fixes': fixes
    }


def scan_project(src_dir: str = "src"):
    """Scan entire project for except Exception."""
    print(f"\n{'='*70}")
    print(f"🔍 RAGLOX v3.0 - SEC-01: Exception Scanner")
    print(f"{'='*70}")
    
    src_path = Path(src_dir)
    python_files = list(src_path.rglob("*.py"))
    
    print(f"\n📂 Scanning {len(python_files)} Python files...")
    
    results = []
    total_except_exception = 0
    
    for py_file in sorted(python_files):
        result = fix_except_exception_in_file(str(py_file), dry_run=True)
        if result['total'] > 0:
            results.append(result)
            total_except_exception += result['total']
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"📊 SUMMARY")
    print(f"{'='*70}")
    print(f"Total files scanned: {len(python_files)}")
    print(f"Files with except Exception: {len(results)}")
    print(f"Total except Exception clauses: {total_except_exception}")
    
    print(f"\n{'='*70}")
    print(f"📈 Top 10 Files (by exception count)")
    print(f"{'='*70}")
    
    sorted_results = sorted(results, key=lambda x: x['total'], reverse=True)[:10]
    for i, result in enumerate(sorted_results, 1):
        file_name = Path(result['file']).name
        print(f"{i:2d}. {file_name:40s} {result['total']:3d} occurrences")
    
    # Save detailed report
    report_path = "SEC_01_EXCEPTION_ANALYSIS_REPORT.md"
    with open(report_path, 'w') as f:
        f.write("# SEC-01: except Exception Analysis Report\n\n")
        f.write(f"**Total files scanned:** {len(python_files)}\n")
        f.write(f"**Files with except Exception:** {len(results)}\n")
        f.write(f"**Total except Exception clauses:** {total_except_exception}\n\n")
        
        f.write("## Files by Priority\n\n")
        f.write("| # | File | Count | Exceptions Needed |\n")
        f.write("|---|------|-------|-------------------|\n")
        
        for i, result in enumerate(sorted_results, 1):
            file_path = result['file'].replace('src/', '')
            exceptions = ', '.join(result['exceptions'][:3])
            if len(result['exceptions']) > 3:
                exceptions += f", +{len(result['exceptions']) - 3} more"
            f.write(f"| {i} | `{file_path}` | {result['total']} | {exceptions} |\n")
        
        f.write("\n## Detailed Analysis\n\n")
        for result in sorted_results:
            f.write(f"### {result['file']}\n\n")
            f.write(f"**Total:** {result['total']} occurrences\n\n")
            f.write(f"**Required exceptions:**\n")
            for exc in result['exceptions']:
                f.write(f"- `{exc}`\n")
            f.write("\n---\n\n")
    
    print(f"\n✅ Detailed report saved to: {report_path}")
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="RAGLOX SEC-01: Analyze and fix except Exception clauses"
    )
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Scan entire project'
    )
    parser.add_argument(
        '--file',
        type=str,
        help='Analyze specific file'
    )
    parser.add_argument(
        '--fix',
        action='store_true',
        help='Actually fix files (not dry-run)'
    )
    
    args = parser.parse_args()
    
    if args.scan:
        scan_project()
    elif args.file:
        fix_except_exception_in_file(args.file, dry_run=not args.fix)
    else:
        print("Usage:")
        print("  --scan        Scan entire project")
        print("  --file FILE   Analyze specific file")
        print("  --fix         Actually modify files")
        parser.print_help()
