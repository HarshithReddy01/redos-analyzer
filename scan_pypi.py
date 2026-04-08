import argparse
import ast
import csv
import io
import os
import sys
import tarfile
import zipfile
import tempfile
import textwrap
import requests
from collections import Counter, OrderedDict
from pathlib import Path
from dataclasses import dataclass, field, fields
sys.path.insert(0, str(Path(__file__).parent))
from redos_analyzer import analyze, classify_exploitability
PACKAGES = ['requests', 'flask', 'django', 'fastapi', 'sqlalchemy', 'pydantic', 'pytest', 'numpy', 'pandas', 'pillow', 'scrapy', 'celery', 'boto3', 'httpx', 'aiohttp', 'click', 'rich', 'typer', 'black', 'mypy']
SEVERITY = {'NESTED_QUANTIFIER': 'HIGH', 'NULLABLE_BRANCH_IN_QUANTIFIER': 'HIGH', 'OVERLAPPING_ALTERNATION': 'MEDIUM', 'LIKELY_TYPO': 'MEDIUM', 'PARSE_ERROR': 'LOW'}
RE_FUNCTIONS = {'compile', 'search', 'match', 'fullmatch', 'findall', 'finditer', 'sub', 'subn', 'split'}
OUTPUT_CSV = Path(__file__).parent / 'redos_report.csv'
OUTPUT_SUMMARY = Path(__file__).parent / 'scan_summary.txt'
CACHE_DIR = Path(__file__).parent / '_pkg_cache'
CACHE_DIR.mkdir(exist_ok=True)
SKIP_PATHS = {'/tests/', '/test/', '/vendored/', '/vendor/', '/docs/', '/examples/', 'setup.py', 'conftest.py', '/build/'}
# Runtime-first reporting: we still parse everything, but default output focuses on likely production paths.

def _path_segments(path: str) -> list[str]:
    return path.replace('\\', '/').split('/')

def _classify_context_type(path: str) -> str:
    segs = _path_segments(path)
    seg_lower = [s.lower() for s in segs]
    if any(s in ('tests', 'test', 'unittests') for s in seg_lower):
        return 'test'
    if any(s in ('vendor', 'vendored') or s.startswith('vendor') for s in seg_lower):
        return 'vendored'
    if any(s in ('docs', 'doc', 'examples', 'example') for s in seg_lower):
        return 'tooling'
    return 'runtime'

def _should_skip(path: str) -> bool:
    filename = path.replace('\\', '/').rsplit('/', 1)[-1]
    if filename in ('setup.py', 'conftest.py'):
        return True
    return _classify_context_type(path) != 'runtime'

@dataclass
class Finding:
    package: str
    file: str
    line: int
    pattern: str
    warning_class: str
    severity: str
    exploitability: str
    exploit_score: int
    exploit_reasons: str
    context_type: str
    occurrences: int
    detail: str

def _pypi_sdist_url(package: str) -> tuple[str, str]:
    resp = requests.get(f'https://pypi.org/pypi/{package}/json', timeout=15)
    resp.raise_for_status()
    data = resp.json()
    version = data['info']['version']
    urls = data['urls']
    for ext in ('.tar.gz', '.zip'):
        for entry in urls:
            if entry['packagetype'] == 'sdist' and entry['filename'].endswith(ext):
                return (entry['url'], entry['filename'])
    for entry in urls:
        if entry['filename'].endswith('.whl'):
            return (entry['url'], entry['filename'])
    raise ValueError(f'No downloadable dist found for {package} {version}')

def _download_cached(package: str) -> Path:
    existing = list(CACHE_DIR.glob(f'{package}-*'))
    if existing:
        return existing[0]
    url, filename = _pypi_sdist_url(package)
    dest = CACHE_DIR / filename
    print(f'    Downloading {filename} ...', end=' ', flush=True)
    resp = requests.get(url, timeout=60, stream=True)
    resp.raise_for_status()
    with open(dest, 'wb') as f:
        for chunk in resp.iter_content(65536):
            f.write(chunk)
    print('done')
    return dest

def _iter_py_files(archive: Path):
    name = archive.name

    def _read_member(name_in_archive: str, read_fn) -> tuple[str, str] | None:
        if not name_in_archive.endswith('.py'):
            return None
        try:
            raw = read_fn()
            text = raw.decode('utf-8', errors='replace')
            return (name_in_archive, text)
        except Exception:
            return None
    if name.endswith('.tar.gz'):
        with tarfile.open(archive, 'r:gz') as tf:
            for member in tf.getmembers():
                result = _read_member(member.name, lambda m=member: tf.extractfile(m).read())
                if result:
                    yield result
    elif name.endswith(('.zip', '.whl')):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                result = _read_member(info.filename, lambda i=info: zf.read(i.filename))
                if result:
                    yield result

def _extract_re_calls(source: str, filepath: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_re_call = isinstance(func, ast.Attribute) and func.attr in RE_FUNCTIONS and isinstance(func.value, ast.Name) and (func.value.id == 're')
        is_bare_call = isinstance(func, ast.Name) and func.id in RE_FUNCTIONS
        if not (is_re_call or is_bare_call):
            continue
        if not node.args:
            continue
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            results.append((node.lineno, first_arg.value))
            continue
        joined = _try_join_strings(first_arg)
        if joined is not None:
            results.append((node.lineno, joined))
    return results

def _try_join_strings(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _try_join_strings(node.left)
        right = _try_join_strings(node.right)
        if left is not None and right is not None:
            return left + right
    return None

def _context_around_line(source: str, lineno: int, radius: int=8) -> str:
    lines = source.splitlines()
    if not lines:
        return ''
    idx = max(lineno - 1, 0)
    start = max(idx - radius, 0)
    end = min(idx + radius + 1, len(lines))
    return '\n'.join(lines[start:end])

def scan_package(package: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        archive = _download_cached(package)
    except Exception as exc:
        print(f'    ERROR downloading {package}: {exc}')
        return findings
    py_files = list(_iter_py_files(archive))
    patterns_checked = 0
    files_scanned = 0
    files_skipped = 0
    for rel_path, source in py_files:
        ctx_type = _classify_context_type(rel_path)
        should_count = not _should_skip(rel_path)
        if should_count:
            files_scanned += 1
        else:
            files_skipped += 1
        calls = _extract_re_calls(source, rel_path)
        for lineno, pattern in calls:
            if should_count:
                patterns_checked += 1
            try:
                warnings_list = analyze(pattern)
            except Exception:
                continue
            context = _context_around_line(source, lineno)
            # Exploitability uses local source context + path classification for fast triage.
            _exp = classify_exploitability(context, rel_path)
            for w in warnings_list:
                findings.append(Finding(package=package, file=rel_path, line=lineno, pattern=pattern, warning_class=w.kind, severity=SEVERITY.get(w.kind, 'UNKNOWN'), exploitability=_exp['exploitability'], exploit_score=_exp['score'], exploit_reasons='; '.join(_exp['reasons']), context_type=ctx_type, occurrences=1, detail=w.message[:200]))
    print(f'    {files_scanned} files ({files_skipped} skipped), {patterns_checked} patterns, {len(findings)} warning(s)')
    return findings

def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: dict = OrderedDict()
    for f in findings:
        # Collapse repeated warnings at the same site to keep CSV/summary readable.
        key = (f.package, f.file, f.line, f.warning_class)
        if key in seen:
            seen[key].occurrences += 1
        else:
            seen[key] = f
    return list(seen.values())

def write_csv(all_findings: list[Finding]) -> None:
    col_names = [f.name for f in fields(Finding)]
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=col_names)
        writer.writeheader()
        for f in all_findings:
            writer.writerow({fn: getattr(f, fn) for fn in col_names})
    print(f'\n  CSV written  -> {OUTPUT_CSV}  ({len(all_findings)} rows)')

def write_summary(all_findings: list[Finding], per_package: dict[str, list[Finding]], show_all: bool=False, out_path: Path=OUTPUT_SUMMARY) -> None:
    view = all_findings if show_all else [f for f in all_findings if f.context_type == 'runtime']
    view_label = 'all' if show_all else 'runtime only'
    ctx_counts = Counter(f.context_type for f in all_findings)
    lines = []
    lines.append('=' * 72)
    lines.append('  ReDoS Scan -- Summary Report')
    lines.append('=' * 72)
    lines.append(f'  Packages scanned : {len(per_package)}')
    lines.append(f'  Total warnings   : {len(all_findings)}  (showing: {view_label})')
    lines.append(f'  Displayed        : {len(view)}')
    lines.append('')
    lines.append('  By context_type:')
    for ct in ('runtime', 'test', 'vendored', 'tooling'):
        marker = '  <-- displayed' if ct == 'runtime' and (not show_all) or show_all else ''
        lines.append(f'    {ct:<12}: {ctx_counts.get(ct, 0):>4}{marker}')
    lines.append('')
    high = sum(1 for f in view if f.severity == 'HIGH')
    med = sum(1 for f in view if f.severity == 'MEDIUM')
    likely = sum(1 for f in view if f.exploitability == 'LIKELY')
    lines.append(f'  HIGH severity     : {high}')
    lines.append(f'  MEDIUM severity   : {med}')
    lines.append(f'  LIKELY exploitable: {likely}')
    lines.append('')
    lines.append(f'  {'Package':<16}  {'Total':>6}  {'Runtime':>8}  {'HIGH':>6}  {'MEDIUM':>8}')
    lines.append(f'  {'-' * 16}  {'-' * 6}  {'-' * 8}  {'-' * 6}  {'-' * 8}')
    for pkg in PACKAGES:
        fds_all = per_package.get(pkg, [])
        fds = fds_all if show_all else [f for f in fds_all if f.context_type == 'runtime']
        h = sum(1 for f in fds if f.severity == 'HIGH')
        m = sum(1 for f in fds if f.severity == 'MEDIUM')
        rt = sum(1 for f in fds_all if f.context_type == 'runtime')
        marker = '  <-- HIGH RISK' if h > 0 else ''
        lines.append(f'  {pkg:<16}  {len(fds_all):>6}  {rt:>8}  {h:>6}  {m:>8}{marker}')
    lines.append('')
    lines.append('=' * 72)
    lines.append(f'  TOP FINDINGS (HIGH severity, {view_label})')
    lines.append('=' * 72)
    high_findings = [f for f in view if f.severity == 'HIGH']
    for f in high_findings[:30]:
        lines.append(f'\n  [{f.package}]  {f.file}  line {f.line}')
        lines.append(f'  Class       : {f.warning_class}')
        lines.append(f'  context     : {f.context_type}')
        lines.append(f'  Exploit     : {f.exploitability}')
        lines.append(f'  Pattern     : {f.pattern!r}')
        lines.append(f'  Detail      : {textwrap.fill(f.detail, 68, subsequent_indent='              ')}')
    if not high_findings:
        lines.append('\n  No HIGH severity findings.')
    lines.append('')
    if not show_all:
        lines.append(f'  Run with --all to include test/vendored/tooling findings.')
    lines.append('')
    report = '\n'.join(lines)
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(report)
    print(report)
    print(f'\n  Summary written -> {out_path}')

def main() -> None:
    parser = argparse.ArgumentParser(description='ReDoS Scanner -- 20 PyPI Packages')
    parser.add_argument('--all', action='store_true', help='Include test/vendored/tooling findings in summary')
    parser.add_argument('--out-summary', default=str(OUTPUT_SUMMARY), metavar='PATH', help=f'Path for summary file (default: {OUTPUT_SUMMARY.name})')
    args = parser.parse_args()
    out_summary = Path(args.out_summary)
    print('=' * 72)
    print('  ReDoS Scanner -- 20 Popular PyPI Packages')
    print('=' * 72)
    print('  Output will be written to:')
    print(f'    {OUTPUT_CSV}')
    print(f'    {out_summary}')
    print('=' * 72)
    all_findings: list[Finding] = []
    per_package: dict[str, list[Finding]] = {}
    try:
        for pkg in PACKAGES:
            print(f'\n  [{pkg}]')
            findings = scan_package(pkg)
            per_package[pkg] = findings
            all_findings.extend(findings)
        all_findings = deduplicate(all_findings)
        write_csv(all_findings)
    finally:
        write_summary(all_findings, per_package, show_all=args.all, out_path=out_summary)
    print('\n  Output files:')
    for path in [OUTPUT_CSV, out_summary]:
        if path.exists():
            size = path.stat().st_size
            print(f'    {path.name}: {size:,} bytes  OK')
        else:
            print(f'    {path.name}: MISSING -- expected output not found')
            raise FileNotFoundError(f'Expected output not found: {path}')
if __name__ == '__main__':
    main()
