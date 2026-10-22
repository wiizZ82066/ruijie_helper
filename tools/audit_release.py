"""Offline source-release gate. Reports locations/categories, never matched values.

Checks tracked files (including forcibly added ignored files) and publishable
untracked files. Local diagnostics/builds remain on disk but are excluded by Git.
This is a guard against common mistakes, not a proof that arbitrary text contains
no secrets. History and packaged dependency audits are separate checks.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_DIRS = {'analysis', 'build', 'release', 'dist', 'exe', 'node_modules', '.venv', 'venv'}
FORBIDDEN_NAMES = {'suconfig.dat', 'userinfo.dat', 'supplicantresult.ini', 'credentials.dpapi',
                   'settings.json', 'config.json', 'nuitka-crash-report.xml'}
FORBIDDEN_SUFFIXES = {'.dpapi', '.pcap', '.pcapng', '.etl', '.exe', '.msi', '.pyd', '.dll'}
SOURCE_SUFFIXES = {'.py', '.ps1', '.bat', '.cjs', '.js', '.ts', '.tsx', '.json', '.md', '.txt', '.yml', '.yaml', '.iss', '.nsi', '.nsh', '.html'}
SECRET_RULES = {
    'private_key': re.compile(r'(?m)^-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    'github_token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b'),
    'aws_access_key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'slack_token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
    'credential_url': re.compile(r'https?://[^\s/:@]+:[^\s/@]+@'),
    'personal_windows_directory': re.compile(r'(?i)\b[A-Z]:[\\/]+Users[\\/]+(?!Public\b|Default\b)[^\s\\/"\']+'),
}
ABSOLUTE_WINDOWS_PATH = re.compile(r'(?i)(?<![A-Za-z])[A-Z]:[\\/]')


def git(*arguments):
    result = subprocess.run(['git', '-C', str(ROOT), *arguments], capture_output=True, check=True)
    return result.stdout


def candidates():
    paths = set()
    for arguments in [('ls-files', '-z'), ('ls-files', '--others', '--exclude-standard', '-z')]:
        paths.update(os.fsdecode(p).replace('\\', '/') for p in git(*arguments).split(b'\0') if p)
    return sorted(paths)


def local_markers():
    # Machine values are discovered at scan time, never embedded in this tool
    # or serialized in its report. Do not open any credential/profile files.
    paths = {str(ROOT), str(Path.home())}
    values = set()
    for path in paths:
        for variant in (path, path.replace('\\', '/'), path.replace('\\', '\\\\')):
            if len(variant) > 8:
                values.add(variant.casefold())
    if os.name == 'nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces') as key:
                for index in range(winreg.QueryInfoKey(key)[0]):
                    name = winreg.EnumKey(key, index).strip('{}')
                    if re.fullmatch(r'[0-9a-fA-F-]{36}', name):
                        values.add(name.casefold())
        except OSError:
            pass
    return values


def audit():
    findings = []
    checked = 0
    markers = local_markers()

    def record(path, rule, line=None):
        # User profile directory names must not leak even if force-added.
        safe = re.sub(r'(?i)(^|/)users/[^/]+', r'\1users/<account>', path)
        item = {'path': safe, 'category': rule}
        if line is not None:
            item['line'] = line
        if item not in findings:
            findings.append(item)

    for relative in candidates():
        path = ROOT / relative
        parts = {p.casefold() for p in Path(relative).parts}
        name = path.name.casefold()
        if (parts & FORBIDDEN_DIRS or name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES
                or (name.startswith('.env') and name != '.env.example')):
            record(relative, 'runtime_or_build_artifact')
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            record(relative, 'external_symlink')
            continue
        if not path.is_file():
            continue
        checked += 1
        if path.suffix.lower() not in SOURCE_SUFFIXES and path.name != '.gitignore':
            continue
        try:
            text = path.read_text(encoding='utf-8-sig')
        except UnicodeError:
            record(relative, 'unreviewed_text_encoding')
            continue
        for rule, pattern in SECRET_RULES.items():
            for match in pattern.finditer(text):
                record(relative, rule, text.count('\n', 0, match.start()) + 1)
        for number, line in enumerate(text.splitlines(), 1):
            if any(marker in line.casefold() for marker in markers):
                record(relative, 'local_machine_marker', number)
        # Literal drive paths in production code/fixtures are often accidental
        # defaults. Windows device/registry paths and environment expansion are
        # allowed; values must be discovered at runtime.
        if path.suffix.lower() == '.py':
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str) and ABSOLUTE_WINDOWS_PATH.search(node.value):
                        record(relative, 'absolute_windows_path_literal', node.lineno)
            except SyntaxError:
                record(relative, 'python_syntax')
        elif path.suffix.lower() in {'.ps1', '.bat', '.cjs', '.js', '.ts', '.tsx', '.nsi', '.nsh'}:
            for number, line in enumerate(text.splitlines(), 1):
                if ABSOLUTE_WINDOWS_PATH.search(line):
                    record(relative, 'absolute_windows_path_literal', number)
    return {'scope': 'tracked and publishable untracked working-tree files', 'checked_files': checked,
            'finding_count': len(findings), 'findings': findings,
            'limitations': ['Pattern and host-marker scan; not a guarantee for arbitrary unknown secrets.',
                            'Does not rewrite or audit Git history; audit history separately.',
                            'Executable/archive inspection is a separate release check.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='Optional local JSON report path (use build/).')
    args = parser.parse_args()
    result = audit()
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + '\n', encoding='utf-8')
    print(rendered)
    return 1 if result['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
