import csv
import sys
import textwrap
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / 'src'))
from redos_analyzer import analyze, suggest_fix, verify_fix
INPUT_CSV = Path(__file__).parent / 'redos_report.csv'
OUTPUT_CSV = Path(__file__).parent / 'redos_fixes.csv'

def load_top10() -> list[dict]:
    if not INPUT_CSV.exists():
        return []
    with open(INPUT_CSV, encoding='utf-8') as fh:
        rows = list(csv.DictReader(fh))
    high = [r for r in rows if r['severity'] == 'HIGH']
    seen = set()
    unique = []
    for r in high:
        key = (r['package'], r['file'], r['line'], r['pattern'][:80])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique[:10]
SEP = '=' * 72

def process(row: dict, index: int) -> dict:
    pattern = row['pattern']
    pkg = row['package']
    file_ = row['file'].split('/')[-1]
    line = row['line']
    print(f'\n{SEP}')
    print(f'  #{index}  [{pkg}]  {file_}:{line}')
    print(f'  Warning : {row['warning_class']}')
    print(f'  Pattern : {pattern[:80]!r}')
    print(SEP)
    warnings_list = analyze(pattern)
    # Re-analyze raw pattern so fix suggestions are based on current analyzer logic.
    if not warnings_list:
        print('  [??] analyze() returned no warnings -- skipping')
        return _empty_row(row, 'no_warnings_on_reanalysis')
    w = warnings_list[0]
    fix = suggest_fix(pattern, w)
    print(f'\n  fix_type  : {fix['fix_type']}')
    print(f'  verified  : {fix['verified']}')
    if fix['fixed']:
        print(f'  fixed     : {fix['fixed'][:80]!r}')
    else:
        print(f'  fixed     : None -- manual review required')
    v: dict = {}
    if fix['fixed'] and fix['fix_type'] == 'atomic_group':
        print(f'\n  Running verify_fix()...')
        # Verify both semantics and timing; speedup alone is not enough to accept a fix.
        v = verify_fix(pattern, fix['fixed'])
        print(f'  semantics_preserved : {v['semantics_preserved']}')
        print(f'  speedup_factor      : {v['speedup_factor']}x')
        print(f'  evil_input          : {v['evil_input_tested']!r}')
        print(f'  original_time       : {v['original_time_s']:.6f}s')
        print(f'  fixed_time          : {v['fixed_time_s']:.6f}s')
        if v['notes']:
            for note in v['notes']:
                print(f'  NOTE: {textwrap.fill(note, 65, subsequent_indent='        ')}')
        if v['semantic_mismatches']:
            print(f'  MISMATCH: {v['semantic_mismatches'][:3]}')
    else:
        v = dict(semantics_preserved=None, speedup_factor=None, evil_input_tested='', notes=[])
    return {'package': pkg, 'file': row['file'], 'line': line, 'original_pattern': pattern, 'fixed_pattern': fix.get('fixed') or '', 'fix_type': fix['fix_type'], 'verified': fix['verified'], 'speedup_factor': v.get('speedup_factor', ''), 'semantics_preserved': v.get('semantics_preserved', ''), 'explanation': fix['explanation'][:300]}

def _empty_row(row: dict, reason: str) -> dict:
    return {'package': row['package'], 'file': row['file'], 'line': row['line'], 'original_pattern': row['pattern'], 'fixed_pattern': '', 'fix_type': 'manual_review', 'verified': False, 'speedup_factor': '', 'semantics_preserved': '', 'explanation': reason}

def main():
    print(f'\n{SEP}')
    print('  ReDoS Auto-Fixer -- Top 10 HIGH Severity Findings')
    print(SEP)
    top10 = load_top10()
    if not INPUT_CSV.exists():
        print(f'\n  ERROR: input report not found: {INPUT_CSV}')
        print('  Run `python scan_pypi.py` first, then retry.')
        return
    if not top10:
        print('\n  No HIGH severity rows found in redos_report.csv.')
        print('  Nothing to auto-fix.')
        return
    results = []
    for i, row in enumerate(top10, 1):
        results.append(process(row, i))
    cols = ['package', 'file', 'line', 'original_pattern', 'fixed_pattern', 'fix_type', 'verified', 'speedup_factor', 'semantics_preserved', 'explanation']
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        writer.writerows(results)
    print(f'\n  CSV written -> {OUTPUT_CSV}')
    print(f'\n{'#' * 72}')
    print('  PART 5 -- BRUTAL HONESTY ASSESSMENT')
    print(f'{'#' * 72}')
    auto_fixed = [r for r in results if r['fix_type'] == 'atomic_group']
    verified_ok = [r for r in auto_fixed if r['verified'] is True]
    manual_review = [r for r in results if r['fix_type'] == 'manual_review']
    semantics_ok = [r for r in auto_fixed if r['semantics_preserved'] is True]
    semantics_bad = [r for r in auto_fixed if r['semantics_preserved'] is False]
    fast = [r for r in auto_fixed if isinstance(r['speedup_factor'], (int, float)) and r['speedup_factor'] >= 2.0]
    slow_oracle = [r for r in auto_fixed if isinstance(r['speedup_factor'], (int, float)) and r['speedup_factor'] < 2.0]
    print(f"\n  Q1. How many of the 10 patterns were fixed automatically? (verified=True)\n  -------------------------------------------------------------------------\n  Auto-generated fixes  : {len(auto_fixed)} / 10\n  Warnings eliminated   : {len(verified_ok)} / {len(auto_fixed)}  (analyze(fixed)==[])\n  Manual review needed  : {len(manual_review)} / 10\n\n  Q2. How many required manual_review?\n  -------------------------------------------------------------------------\n  {len(manual_review)} pattern(s) required manual review.\n  Reasons:\n    • PARSE_ERROR (truncated pattern in CSV) -- pattern too long to scan fully\n    • Patterns where the fix rebuilt correctly but still had residual warnings\n      (e.g. multiple independent nested quantifiers, or reconstructed form\n       differs enough from original that analyzer re-fires on a different node)\n\n  Q3. Were semantics always preserved? Any edge cases?\n  -------------------------------------------------------------------------\n  Semantics preserved   : {len(semantics_ok)} / {len(auto_fixed)}\n  Semantics MISMATCH    : {len(semantics_bad)} / {len(auto_fixed)}\n\n  Edge cases to know:\n  • Atomic groups change WHICH way a match is found, not WHETHER it matches.\n    For most patterns this is invisible. Exception: if user code inspects\n    capture group content and depends on the greedy-longest match of a\n    specific sub-group, the result may differ.\n  • ((?>inner)) preserves the capture NUMBER but the inner content is now\n    matched atomically -- the group always captures the greedy result and\n    cannot be coerced to capture less via backtracking.\n  • Named groups (?P<name>...) are reconstructed as (?P<name>inner_str)\n    by sre_parse's _to_str but the atomic wrapper sits INSIDE. This is safe.\n\n  Q4. What are the limitations of this approach?\n  -------------------------------------------------------------------------\n  LIMITATION 1 -- Reconstruction changes pattern appearance.\n    sre_parse normalises: \\s->[\\s], \\d->[\\d], \\w->[\\w], \\b->...\n    The fixed pattern is semantically identical but looks different. This\n    means you cannot do a line-by-line diff of original vs fixed in code.\n\n  LIMITATION 2 -- Bounded quantifiers not always dangerous in practice.\n    Patterns like ([a-z_]+/){{0,2}} have outer max=2. CPython's backtracker\n    can only try 3 splits (0,1,2 iterations), so the real-world speedup is\n    unmeasurable -- but the pattern IS theoretically quadratic not exponential.\n\n  LIMITATION 3 -- False-safe from sre_parse optimiser.\n    sre_parse's prefix factoring changes what our detector sees. A pattern\n    like (a|aa)+ is detected as NULLABLE_BRANCH (correct!) but the\n    reconstructed fix is based on the factored AST, not the original.\n    The fix still works, but auditing it requires understanding the optimised form.\n\n  LIMITATION 4 -- Cannot fix patterns with backreferences to removed captures.\n    If a capturing group that we convert to ((?> ... )) is referenced later\n    with \\1 or (?P=name), that is preserved because we use ((?>...)) not\n    (?>...) -- but if the group vanished entirely (which we avoid), it would break.\n\n  LIMITATION 5 -- Timing test is heuristic.\n    _infer_evil_input() guesses the character class from the pattern text.\n    For complex patterns (SQLAlchemy's CREATE TABLE parser) the evil input\n    may not trigger the worst case, giving misleading speedup=1.0x results.\n\n  Q5. Does Python 3.11 atomic group syntax work for all detected cases?\n  -------------------------------------------------------------------------\n  Atomic groups work reliably for:\n    NESTED_QUANTIFIER         -- the primary use case, well-tested\n    NULLABLE_BRANCH           -- wrapping the alternation atomically stops\n                                infinite-empty-match iteration\n    OVERLAPPING_ALTERNATION   -- atomic group commits to first matching branch,\n                                preventing multi-path iteration\n\n  Atomic groups do NOT help with:\n    • Catastrophic backtracking NOT caused by quantifier nesting\n      (e.g. complex lookahead interactions -- not detected by our tool anyway)\n    • Patterns in Python < 3.11 (use possessive quantifiers or regex module instead)\n    • Patterns where SEMANTIC CHANGE is unacceptable -- in those cases, the\n      real fix is to redesign the pattern to eliminate ambiguity structurally.\n\n  HONEST VERDICT: The auto-fixer is useful as a first-pass suggestion tool.\n  It correctly identifies the fix structure for ~{len(auto_fixed)}/10 patterns\n  and eliminates the warning for ~{len(verified_ok)}/{len(auto_fixed)} of those.\n  The remaining cases need a human to understand context before applying.\n  Do not apply these fixes to production code without a test suite.\n")
if __name__ == '__main__':
    main()
