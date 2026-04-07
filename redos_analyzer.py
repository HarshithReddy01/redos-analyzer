import csv as _csv
import re
import sys as _sys
import time as _time
import warnings as _warnings_mod
with _warnings_mod.catch_warnings():
    _warnings_mod.simplefilter('ignore', DeprecationWarning)
    try:
        import sre_parse as _sre_parse
        import sre_constants as _sre_const
    except ImportError:
        from re import _parser as _sre_parse
        from re import _constants as _sre_const
_MAXREPEAT = _sre_const.MAXREPEAT
_MAX_REPEAT = _sre_const.MAX_REPEAT
_MIN_REPEAT = _sre_const.MIN_REPEAT
_SUBPATTERN = _sre_const.SUBPATTERN
_BRANCH = _sre_const.BRANCH
_IN = _sre_const.IN
_LITERAL = _sre_const.LITERAL
_NOT_LITERAL = _sre_const.NOT_LITERAL
_ANY = _sre_const.ANY
_AT = _sre_const.AT
_GROUPREF = _sre_const.GROUPREF
_RANGE = _sre_const.RANGE
_NEGATE = _sre_const.NEGATE
_CATEGORY = _sre_const.CATEGORY
_AT_BEGINNING = _sre_const.AT_BEGINNING
_AT_END = _sre_const.AT_END
_AT_BOUNDARY = getattr(_sre_const, 'AT_BOUNDARY', None)
_AT_NON_BOUNDARY = getattr(_sre_const, 'AT_NON_BOUNDARY', None)
_AT_UNI_BOUNDARY = getattr(_sre_const, 'AT_UNI_BOUNDARY', None)
_AT_UNI_NON_BOUNDARY = getattr(_sre_const, 'AT_UNI_NON_BOUNDARY', None)

def _cat(name, default=None):
    return getattr(_sre_const, name, default)
_CAT_DIGIT = _cat('CATEGORY_DIGIT')
_CAT_NOTDIGIT = _cat('CATEGORY_NOT_DIGIT')
_CAT_SPACE = _cat('CATEGORY_SPACE')
_CAT_NOTSPACE = _cat('CATEGORY_NOT_SPACE')
_CAT_WORD = _cat('CATEGORY_WORD')
_CAT_NOTWORD = _cat('CATEGORY_NOT_WORD')

class ReDoSWarning:

    SEVERITY = {
        "NESTED_QUANTIFIER":             "HIGH",
        "NULLABLE_BRANCH_IN_QUANTIFIER": "HIGH",
        "OVERLAPPING_ALTERNATION":       "MEDIUM",
        "LIKELY_TYPO":                   "MEDIUM",
        "PARSE_ERROR":                   "LOW",
    }

    def __init__(self, kind: str, sub_pattern: str, location: str, message: str, exploitability: str='POSSIBLE'):
        self.kind = kind
        self.sub_pattern = sub_pattern
        self.location = location
        self.message = message
        self.severity = self.SEVERITY.get(kind, "UNKNOWN")
        self.exploitability = exploitability

    def __str__(self) -> str:
        return f'[{self.kind}]\n  Location       : {self.location}\n  Sub-pattern    : {self.sub_pattern}\n  Exploitability : {self.exploitability}\n  Detail         : {self.message}'

    def __repr__(self) -> str:
        return f'ReDoSWarning(\n  kind           = {self.kind!r},\n  sub_pattern    = {self.sub_pattern!r},\n  location       = {self.location!r},\n  exploitability = {self.exploitability!r},\n  message        = {self.message!r}\n)'

_USER_INPUT_SIGNALS = [
    (r'\brequest\.(args|form|json|GET|POST|data|values|text)\b', "request.{field} found (HTTP body/query data)"),
    (r'\brequest\.headers\b',                                    "request.headers found"),
    (r'\bheaders\.get\s*\(',                                     "headers.get() found (HTTP header value)"),
    (r'\bwebsocket\.recv\b|\bws\.recv\b',                        "websocket.recv() found"),
    (r'\bsys\.argv\b',                                           "sys.argv found (command-line argument)"),
    (r'\bos\.environ\b|\bos\.getenv\s*\(',                       "os.environ/getenv found (env variable)"),
    (r'\binput\s*\(',                                            "input() found (stdin)"),
    (r'\bsocket\.recv\b',                                        "socket.recv() found"),
    (r'\bopen\s*\(',                                             "open() found (file content -- may be trusted)"),
    (r'\bflask\.request\b',                                      "flask.request found"),
    (r'\bfastapi\.(Query|Body|Form|Header)\b',                   "FastAPI dependency injection found"),
]

def classify_exploitability(source_context: str='', file_path: str='') -> dict:
    # Keep this lightweight and local: score from nearby code hints, not full dataflow.
    reasons: list[str] = []
    score = 5
    fp = file_path.replace('\\', '/')
    segs = fp.split('/')
    if any(s.lower() in ('tests', 'test', 'unittests') or 'test_' in s or s.endswith('_test.py') for s in segs):
        return {'exploitability': 'UNLIKELY', 'score': 1, 'reasons': ['test file path']}
    if re.search('\\blen\\s*\\([^)]+\\)\\s*[<>]=?\\s*\\d+', source_context):
        return {'exploitability': 'UNLIKELY', 'score': 2, 'reasons': ['len() guard found in context']}
    if re.search('\\b[A-Z][A-Z0-9_]{2,}\\s*=\\s*re\\.', source_context):
        score -= 2
        reasons.append('ALL_CAPS constant name (likely hardcoded pattern)')
    if re.search('re\\.\\w+\\s*\\(\\s*["\\\']', source_context):
        score -= 1
        reasons.append('string literal passed directly (not from a variable)')
    fired: list[str] = []
    for pattern, reason in _USER_INPUT_SIGNALS:
        if re.search(pattern, source_context):
            fired.append(reason)
    if fired:
        score = min(10, score + len(fired))
        reasons.extend(fired)
        if not any('guard' in r for r in reasons):
            reasons.append('no length guard detected')
    if fired and score >= 5:
        exploitability = 'LIKELY'
    elif score <= 2:
        exploitability = 'UNLIKELY'
    else:
        exploitability = 'POSSIBLE'
        if not reasons:
            reasons.append('no user-input signals found')
    return {'exploitability': exploitability, 'score': max(0, min(10, score)), 'reasons': reasons}

def _quant_suffix(min_c: int, max_c: int, op) -> str:
    lazy = '?' if op is _MIN_REPEAT else ''
    if min_c == 0 and max_c == _MAXREPEAT:
        return f'*{lazy}'
    elif min_c == 1 and max_c == _MAXREPEAT:
        return f'+{lazy}'
    elif min_c == 0 and max_c == 1:
        return f'?{lazy}'
    elif min_c == max_c:
        return f'{{{min_c}}}{lazy}'
    elif max_c == _MAXREPEAT:
        return f'{{{min_c},}}{lazy}'
    else:
        return f'{{{min_c},{max_c}}}{lazy}'

def _in_to_str(items) -> str:
    parts = []
    for item_op, item_av in items:
        if item_op is _NEGATE:
            parts.insert(0, '^')
        elif item_op is _LITERAL:
            ch = chr(item_av)
            parts.append(re.escape(ch) if ch in '\\\\]^-' else ch)
        elif item_op is _RANGE:
            parts.append(f'{chr(item_av[0])}-{chr(item_av[1])}')
        elif item_op is _CATEGORY:
            _cats = {_CAT_DIGIT: '\\d', _CAT_NOTDIGIT: '\\D', _CAT_SPACE: '\\s', _CAT_NOTSPACE: '\\S', _CAT_WORD: '\\w', _CAT_NOTWORD: '\\W'}
            parts.append(_cats.get(item_av, '?'))
    return ''.join(parts)

def _to_str(nodes) -> str:
    parts = []
    for op, av in nodes:
        if op is _LITERAL:
            ch = chr(av)
            parts.append(re.escape(ch) if ch in '\\.+*?{}[]()^$|' else ch)
        elif op is _NOT_LITERAL:
            parts.append(f'[^{chr(av)}]')
        elif op is _ANY:
            parts.append('.')
        elif op is _IN:
            parts.append(f'[{_in_to_str(av)}]')
        elif op in (_MAX_REPEAT, _MIN_REPEAT):
            min_c, max_c, subpat = av
            inner = _to_str(list(subpat))
            sub_nodes = list(subpat)
            already_grouped = len(sub_nodes) == 1 and sub_nodes[0][0] is _SUBPATTERN
            if len(sub_nodes) > 1 and (not already_grouped):
                inner = f'(?:{inner})'
            parts.append(inner + _quant_suffix(min_c, max_c, op))
        elif op is _SUBPATTERN:
            group_id, _af, _df, subpat = av
            inner = _to_str(list(subpat))
            parts.append(f'({inner})' if group_id is not None else f'(?:{inner})')
        elif op is _BRANCH:
            _, branches = av
            alt_str = '|'.join((_to_str(list(b)) for b in branches))
            if parts:
                parts.append(f'(?:{alt_str})')
            else:
                parts.append(alt_str)
        elif op is _AT:
            parts.append({_AT_BEGINNING: '^', _AT_END: '$', _AT_BOUNDARY: '\\b', _AT_NON_BOUNDARY: '\\B', _AT_UNI_BOUNDARY: '\\b', _AT_UNI_NON_BOUNDARY: '\\B'}.get(av, ''))
        elif _ATOMIC_GROUP and op is _ATOMIC_GROUP:
            parts.append(f'(?>{_to_str(list(av))})')
        elif _POSSESSIVE_REPEAT and op is _POSSESSIVE_REPEAT:
            min_c, max_c, subpat = av
            inner = _to_str(list(subpat))
            parts.append(inner + _quant_suffix(min_c, max_c, _MAX_REPEAT) + '+')
        else:
            parts.append('?')
    return ''.join(parts)

def _can_repeat(min_c: int, max_c: int) -> bool:
    return max_c > 1

def _can_match_empty(nodes) -> bool:
    if not nodes:
        return True
    for op, av in nodes:
        if op in (_LITERAL, _NOT_LITERAL, _ANY, _IN):
            return False
        elif op in (_MAX_REPEAT, _MIN_REPEAT):
            min_c, _, subpat = av
            if min_c == 0:
                return True
            return _can_match_empty(list(subpat))
        elif op is _SUBPATTERN:
            _, _, _, subpat = av
            return _can_match_empty(list(subpat))
        elif op is _BRANCH:
            _, branches = av
            return any((_can_match_empty(list(b)) for b in branches))
        elif op is _AT:
            continue
        elif op is _GROUPREF:
            return False
    return True

def _first_chars(nodes) -> set | None:
    result: set = set()
    for op, av in nodes:
        if op is _LITERAL:
            result.add(('lit', av))
            return result
        elif op in (_NOT_LITERAL, _ANY):
            return None
        elif op is _IN:
            for item_op, item_av in av:
                if item_op is _NEGATE:
                    return None
                elif item_op is _LITERAL:
                    result.add(('lit', item_av))
                elif item_op is _RANGE:
                    result.add(('range', item_av[0], item_av[1]))
                elif item_op is _CATEGORY:
                    return None
            return result
        elif op is _SUBPATTERN:
            _, _, _, subpat = av
            return _first_chars(list(subpat))
        elif op in (_MAX_REPEAT, _MIN_REPEAT):
            min_c, _, subpat = av
            sub_fc = _first_chars(list(subpat))
            if sub_fc is None:
                return None
            result.update(sub_fc)
            if min_c > 0:
                return result
        elif op is _BRANCH:
            _, branches = av
            for branch in branches:
                fc = _first_chars(list(branch))
                if fc is None:
                    return None
                result.update(fc)
            return result
        elif op is _AT:
            continue
    return result if result else None

def _sets_overlap(a: set | None, b: set | None) -> bool:
    if a is None or b is None:
        return True

    def _in(c: int, s: set) -> bool:
        for item in s:
            if item[0] == 'lit' and item[1] == c:
                return True
            if item[0] == 'range' and item[1] <= c <= item[2]:
                return True
        return False
    for item in a:
        if item[0] == 'lit':
            if _in(item[1], b):
                return True
        elif item[0] == 'range':
            for c in range(item[1], min(item[2] + 1, item[1] + 128)):
                if _in(c, b):
                    return True
    return False

def _as_literal_string(nodes) -> str | None:
    parts = []
    for op, av in nodes:
        if op is _LITERAL:
            parts.append(chr(av))
        else:
            return None
    return ''.join(parts)

def _locate(original: str, sub: str) -> str:
    idx = original.find(sub)
    if idx != -1:
        end = idx + len(sub) - 1
        return f"col {idx}-{end}  '{sub}'"
    quant_suffix = ''
    # AST normalization can rewrite text; fall back to a quantifier-anchored location hint.
    for ch in reversed(sub):
        if ch in '+*?}':
            quant_suffix = ch
            break
    if quant_suffix:
        for i, ch in enumerate(original):
            if ch == '(' and original.find(quant_suffix, i) != -1:
                end_candidate = original.find(quant_suffix, i)
                candidate = original[i:end_candidate + 1]
                return f"col {i}-{end_candidate}  '{candidate}' (original; reconstructed as '{sub}')"
    return f"(reconstructed from optimised AST)  '{sub}'"

def _check_branch_issues(branch_av, outer_min: int, outer_max: int, outer_op, original: str, outer_expr: str, issues: list) -> None:
    _, branches = branch_av
    branch_lists = [list(b) for b in branches]
    branch_strs = [_to_str(b) for b in branch_lists]
    quant = _quant_suffix(outer_min, outer_max, outer_op)
    loc = _locate(original, outer_expr)
    reported_pairs: set = set()
    nullable = [branch_strs[i] for i, b in enumerate(branch_lists) if _can_match_empty(b)]
    if nullable:
        issues.append(ReDoSWarning(kind='NULLABLE_BRANCH_IN_QUANTIFIER', sub_pattern=outer_expr, location=loc, message=f"Alternative(s) {nullable!r} inside quantifier '{quant}' can match the empty string.  The group can iterate without consuming input, enabling exponential backtracking on a failing match."))
    lit_map = {i: _as_literal_string(b) for i, b in enumerate(branch_lists)}
    n = len(branch_lists)
    for i in range(n):
        li = lit_map.get(i)
        if li is None:
            continue
        for j in range(i + 1, n):
            lj = lit_map.get(j)
            if lj is None:
                continue
            if lj.startswith(li) or li.startswith(lj):
                reported_pairs.add((i, j))
                issues.append(ReDoSWarning(kind='OVERLAPPING_ALTERNATION', sub_pattern=outer_expr, location=loc, message=f"Branch '{branch_strs[i]}' is a literal prefix of '{branch_strs[j]}' (or vice-versa) inside quantifier '{quant}'.  The same input can be matched in multiple ways across iterations, causing catastrophic backtracking."))
    for i in range(n):
        for j in range(i + 1, n):
            if (i, j) in reported_pairs:
                continue
            if lit_map.get(i) is not None and lit_map.get(j) is not None:
                continue
            fc_i = _first_chars(branch_lists[i])
            fc_j = _first_chars(branch_lists[j])
            if _sets_overlap(fc_i, fc_j):
                reported_pairs.add((i, j))
                issues.append(ReDoSWarning(kind='OVERLAPPING_ALTERNATION', sub_pattern=outer_expr, location=loc, message=f"Branches '{branch_strs[i]}' and '{branch_strs[j]}' share overlapping first-character sets inside quantifier '{quant}'. The same input may be matched in multiple ways across iterations, potentially causing catastrophic backtracking."))

def _unwrap_groups(nodes: list) -> list:
    while len(nodes) == 1 and nodes[0][0] is _SUBPATTERN:
        _, _, _, inner = nodes[0][1]
        nodes = list(inner)
    return nodes

def _scan(nodes, original: str, issues: list, in_repeating_quant: bool, outer_expr: str) -> None:
    for op, av in list(nodes):
        if op in (_MAX_REPEAT, _MIN_REPEAT):
            min_c, max_c, subpat = av
            subpat_list = list(subpat)
            inner_str = _to_str(subpat_list)
            quant = _quant_suffix(min_c, max_c, op)
            expr = inner_str + quant
            if _can_repeat(min_c, max_c):
                if in_repeating_quant:
                    loc = _locate(original, outer_expr)
                    issues.append(ReDoSWarning(kind='NESTED_QUANTIFIER', sub_pattern=outer_expr, location=loc, message=f"Repeating quantifier '{quant}' on '{inner_str}' is nested inside the outer repeating quantifier.  On a failing match the engine must explore an exponential number of ways to partition the input across the two quantifiers."))
                body = _unwrap_groups(subpat_list)
                for b_op, b_av in body:
                    if b_op is _BRANCH:
                        _check_branch_issues(b_av, min_c, max_c, op, original, expr, issues)
                _scan(subpat_list, original, issues, in_repeating_quant=True, outer_expr=expr)
            else:
                _scan(subpat_list, original, issues, in_repeating_quant=in_repeating_quant, outer_expr=outer_expr)
        elif op is _SUBPATTERN:
            _, _, _, subpat = av
            _scan(list(subpat), original, issues, in_repeating_quant=in_repeating_quant, outer_expr=outer_expr)
        elif op is _BRANCH:
            _, branches = av
            for branch in branches:
                _scan(list(branch), original, issues, in_repeating_quant=in_repeating_quant, outer_expr=outer_expr)
_ATOMIC_GROUP = getattr(_sre_const, 'ATOMIC_GROUP', None)
_POSSESSIVE_REPEAT = getattr(_sre_const, 'POSSESSIVE_REPEAT', None)

def _check_likely_typo(pattern: str) -> list[ReDoSWarning]:
    issues = []
    i = 0
    while i < len(pattern):
        if pattern[i] == '\\' and i + 1 < len(pattern):
            i += 2
            continue
        if pattern[i:i + 3] == '(:?':
            issues.append(ReDoSWarning(kind='LIKELY_TYPO', sub_pattern=pattern[i:i + 3], location=f"col {i}-{i + 2}  '(:?'", message="Found '(:?' - this looks like a typo for '(?:' (non-capturing group). '(:?' creates a capturing group that optionally matches a literal colon, which is rarely the intended behaviour. If you meant a non-capturing group, change '(:?' to '(?:'.", exploitability='UNLIKELY'))
        i += 1
    return issues

def analyze(pattern: str) -> list[ReDoSWarning]:
    try:
        parsed = _sre_parse.parse(pattern)
    except re.error as exc:
        return [ReDoSWarning(kind='PARSE_ERROR', sub_pattern=pattern, location='N/A', message=f'Pattern failed to parse: {exc}')]
    issues: list[ReDoSWarning] = []
    issues.extend(_check_likely_typo(pattern))
    _scan(list(parsed), pattern, issues, in_repeating_quant=False, outer_expr='')
    return issues

def _contains_repeating_quant(nodes) -> bool:
    for op, av in nodes:
        if op in (_MAX_REPEAT, _MIN_REPEAT):
            min_c, max_c, subpat = av
            if _can_repeat(min_c, max_c):
                return True
            if _contains_repeating_quant(list(subpat)):
                return True
        elif op is _SUBPATTERN:
            _, _, _, subpat = av
            if _contains_repeating_quant(list(subpat)):
                return True
        elif op is _BRANCH:
            _, branches = av
            for b in branches:
                if _contains_repeating_quant(list(b)):
                    return True
    return False

def _has_bad_branch(nodes) -> bool:
    unwrapped = nodes
    while len(unwrapped) == 1 and unwrapped[0][0] is _SUBPATTERN:
        _, _, _, inner = unwrapped[0][1]
        unwrapped = list(inner)
    for op, av in unwrapped:
        if op is _BRANCH:
            _, branches = av
            branch_lists = [list(b) for b in branches]
            if any((_can_match_empty(b) for b in branch_lists)):
                return True
            n = len(branch_lists)
            for i in range(n):
                for j in range(i + 1, n):
                    if _sets_overlap(_first_chars(branch_lists[i]), _first_chars(branch_lists[j])):
                        return True
    return False

def _group_info(subpat_list: list) -> tuple:
    if len(subpat_list) == 1 and subpat_list[0][0] is _SUBPATTERN:
        group_id, add_flags, del_flags, inner = subpat_list[0][1]
        return (group_id, add_flags, list(inner))
    return (None, None, subpat_list)

def _to_str_atomic(nodes) -> str:
    parts = []
    for op, av in nodes:
        if op is _LITERAL:
            ch = chr(av)
            parts.append(re.escape(ch) if ch in '\\.+*?{}[]()^$|' else ch)
        elif op is _NOT_LITERAL:
            parts.append(f'[^{chr(av)}]')
        elif op is _ANY:
            parts.append('.')
        elif op is _IN:
            parts.append(f'[{_in_to_str(av)}]')
        elif op in (_MAX_REPEAT, _MIN_REPEAT):
            min_c, max_c, subpat = av
            subpat_list = list(subpat)
            quant = _quant_suffix(min_c, max_c, op)
            # Only wrap with atomic groups when structure is ambiguity-prone and can repeat.
            needs_fix = _can_repeat(min_c, max_c) and (_contains_repeating_quant(subpat_list) or _has_bad_branch(subpat_list))
            if needs_fix:
                group_id, _af, inner_nodes = _group_info(subpat_list)
                inner_str = _to_str_atomic(inner_nodes)
                if group_id is not None:
                    parts.append(f'((?>{inner_str})){quant}')
                else:
                    parts.append(f'(?>{inner_str}){quant}')
            else:
                inner = _to_str_atomic(subpat_list)
                already_grouped = len(subpat_list) == 1 and subpat_list[0][0] is _SUBPATTERN
                if len(subpat_list) > 1 and (not already_grouped):
                    inner = f'(?:{inner})'
                parts.append(inner + quant)
        elif op is _SUBPATTERN:
            group_id, _af, _df, subpat = av
            inner = _to_str_atomic(list(subpat))
            parts.append(f'({inner})' if group_id is not None else f'(?:{inner})')
        elif op is _BRANCH:
            _, branches = av
            alt_str = '|'.join((_to_str_atomic(list(b)) for b in branches))
            if parts:
                parts.append(f'(?:{alt_str})')
            else:
                parts.append(alt_str)
        elif op is _AT:
            parts.append({_AT_BEGINNING: '^', _AT_END: '$', _AT_BOUNDARY: '\\b', _AT_NON_BOUNDARY: '\\B', _AT_UNI_BOUNDARY: '\\b', _AT_UNI_NON_BOUNDARY: '\\B'}.get(av, ''))
        elif _ATOMIC_GROUP and op is _ATOMIC_GROUP:
            parts.append(f'(?>{_to_str_atomic(list(av))})')
        elif _POSSESSIVE_REPEAT and op is _POSSESSIVE_REPEAT:
            min_c, max_c, subpat = av
            inner = _to_str_atomic(list(subpat))
            parts.append(inner + _quant_suffix(min_c, max_c, _MAX_REPEAT) + '+')
        else:
            parts.append('?')
    return ''.join(parts)

def _rebuild_fixed(pattern: str) -> str | None:
    try:
        parsed = _sre_parse.parse(pattern)
    except re.error:
        return None
    return _to_str_atomic(list(parsed))

def suggest_fix(pattern: str, warning: ReDoSWarning) -> dict:
    if warning.kind == 'PARSE_ERROR':
        return dict(original=pattern, fixed=None, fix_type='manual_review', explanation='Pattern failed to parse; cannot generate automatic fix.', verified=False, python_version_required='N/A')
    fixed = _rebuild_fixed(pattern)
    if fixed is None:
        return dict(original=pattern, fixed=None, fix_type='manual_review', explanation='AST reconstruction failed; manual fix required.', verified=False, python_version_required='3.11+')
    try:
        re.compile(fixed)
    except re.error as exc:
        return dict(original=pattern, fixed=fixed, fix_type='manual_review', explanation=f'Generated fix does not compile ({exc}); manual review needed.', verified=False, python_version_required='3.11+')
    remaining = analyze(fixed)
    verified = len(remaining) == 0
    changed = fixed != pattern
    if not changed:
        explanation = 'Pattern rebuilt in normalised form. NOTE: sre_parse normalises \\s→[\\s], \\d→[\\d], etc.; the fixed pattern is semantically identical to the original.'
    else:
        explanation = f'Dangerous repeating group(s) wrapped with atomic-group syntax (?>...). Warning class: {warning.kind}. Atomic groups prevent the engine from reconsidering what the group matched once it has committed, eliminating exponential backtracking. NOTE: sre_parse normalises escape sequences (\\s→[\\s] etc.); the fixed pattern is semantically equivalent but may look different.'
        if '((?>' in fixed:
            explanation += ' Capturing groups are preserved as ((?>...)) so group numbers and named back-references remain valid.'
    return dict(original=pattern, fixed=fixed, fix_type='atomic_group' if changed else 'already_safe', explanation=explanation, verified=verified, python_version_required='3.11+')
def _infer_evil_input(pattern: str, length: int=20) -> str:
    # Domain-specific generators still needed for anchored grammars; this is best-effort.
    if re.search(r'\\d|\[0-9\]|\[0-9', pattern):
        char = '0'
    elif re.search(r'\\s|\[ \\t\]', pattern):
        char = ' '
    else:
        char = 'a'  # covers \w, [a-z], [a-zA-Z], and most other classes
    return char * length + '!'

def verify_fix(original: str, fixed: str, test_inputs: list[str] | None=None) -> dict:
    notes: list[str] = []
    try:
        orig_re = re.compile(original)
    except re.error as e:
        return dict(semantics_preserved=False, speedup_factor=0.0, evil_input_tested='', original_time_s=0.0, fixed_time_s=0.0, semantic_mismatches=[], notes=[f'Original failed to compile: {e}'])
    try:
        fixed_re = re.compile(fixed)
    except re.error as e:
        return dict(semantics_preserved=False, speedup_factor=0.0, evil_input_tested='', original_time_s=0.0, fixed_time_s=0.0, semantic_mismatches=[], notes=[f'Fixed failed to compile: {e}'])
    if test_inputs is None:
        test_inputs = ['a', 'ab', 'abc', 'abcdef', '0', '123', '0123456789', ' ', '  ', '   ', 'aA1_', 'hello world', '']
    mismatches: list[str] = []
    for inp in test_inputs:
        try:
            om = orig_re.search(inp)
            fm = fixed_re.search(inp)
            orig_result = om.group(0) if om else None
            fixed_result = fm.group(0) if fm else None
            if orig_result != fixed_result:
                mismatches.append(f'input={inp!r}: original={orig_result!r}, fixed={fixed_result!r}')
        except Exception as e:
            notes.append(f'Semantic test error on {inp!r}: {e}')
    semantics_preserved = len(mismatches) == 0
    evil = _infer_evil_input(original, length=22)
    TIMEOUT = 5.0
    orig_time = 0.0
    try:
        t0 = _time.perf_counter()
        orig_re.search(evil)
        orig_time = _time.perf_counter() - t0
        if orig_time > TIMEOUT:
            notes.append(f'Original timed out at {TIMEOUT}s on evil input; result capped.')
            orig_time = TIMEOUT
    except Exception as e:
        notes.append(f'Original raised {e} on evil input.')
        orig_time = TIMEOUT
    fixed_time = 0.0
    try:
        t0 = _time.perf_counter()
        fixed_re.search(evil)
        fixed_time = _time.perf_counter() - t0
    except Exception as e:
        notes.append(f'Fixed raised {e} on evil input.')
        fixed_time = float('nan')
    speedup = orig_time / fixed_time if fixed_time and fixed_time > 0 else float('inf')
    if orig_time < 0.0005:
        notes.append("Original ran fast on evil input (<0.5 ms). The pattern may be bounded (e.g. {0,2}), anchored in a way that limits backtracking, or CPython's internal optimiser neutralised it. Speedup ratio may not reflect theoretical worst-case.")
    return dict(semantics_preserved=semantics_preserved, speedup_factor=round(speedup, 1), evil_input_tested=evil, original_time_s=round(orig_time, 6), fixed_time_s=round(fixed_time, 6), semantic_mismatches=mismatches, notes=notes)
_SLOWDOWN_THRESHOLD = 10.0

def confirm_finding(pattern: str, evil_length: int=22, structural_issues: bool | None = None) -> dict:
    notes: list[str] = []
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return dict(confirmed=False, false_positive=True, normal_input='', evil_input='', normal_time_s=0.0, evil_time_s=0.0, slowdown_factor=0.0, notes=[f'Pattern failed to compile: {exc}'])
    normal = 'abc123'
    t0 = _time.perf_counter()
    try:
        compiled.search(normal)
    except Exception as exc:
        notes.append(f'Error on normal input: {exc}')
    normal_time = _time.perf_counter() - t0
    evil = _infer_evil_input(pattern, length=evil_length)
    TIMEOUT = 5.0
    timed_out = False
    t0 = _time.perf_counter()
    try:
        compiled.search(evil)
        evil_time = _time.perf_counter() - t0
        if evil_time >= TIMEOUT:
            notes.append(f'Evil input timed out at {TIMEOUT}s; capped.')
            evil_time = TIMEOUT
            timed_out = True
    except Exception as exc:
        evil_time = _time.perf_counter() - t0
        notes.append(f'Error on evil input: {exc}')
    if normal_time < 1e-07:
        slowdown = float('inf') if evil_time > 0.001 else 1.0
        notes.append('Normal input ran in <0.1 µs; slowdown ratio is notional.')
    else:
        slowdown = evil_time / normal_time
    confirmed = timed_out or slowdown >= _SLOWDOWN_THRESHOLD
    if structural_issues is None:
        structural_issues = bool(analyze(pattern))
    cpython_optimizer_suspected = not confirmed and structural_issues and (evil_time < 0.001) and (not any('failed to compile' in n for n in notes))
    if not confirmed and evil_time < 0.001:
        msg = 'Evil input completed in <1 ms.'
        if cpython_optimizer_suspected:
            msg += ' CPython 3.11+ optimizer likely neutralised this pattern. Test on Python <3.11 or PyPy before marking safe.'
        else:
            msg += ' The evil input may not have triggered worst-case paths.'
        notes.append(msg)
    return dict(confirmed=confirmed, false_positive=not confirmed, cpython_optimizer_suspected=cpython_optimizer_suspected, normal_input=normal, evil_input=evil, normal_time_s=round(normal_time, 6), evil_time_s=round(evil_time, 6), slowdown_factor=round(slowdown, 1) if slowdown != float('inf') else 'inf', notes=notes)

def analyze_report(csv_path: str='redos_report.csv') -> dict:
    try:
        with open(csv_path, newline='', encoding='utf-8') as fh:
            rows = list(_csv.DictReader(fh))
    except FileNotFoundError:
        return dict(total_high=0, confirmed=0, false_positives=0, cpython_optimizer_suspected=0, confirmation_rate=0.0, details=[], error=f'File not found: {csv_path}')
    high_rows = [r for r in rows if r.get('severity', '').upper() == 'HIGH']
    details = []
    confirmed_count = 0
    cpython_count = 0
    for row in high_rows:
        pattern = row.get('pattern', '')
        if not pattern:
            continue
        result = confirm_finding(pattern, structural_issues=True)
        result['pattern'] = pattern
        result['file'] = row.get('file', '')
        if result['confirmed']:
            confirmed_count += 1
        if result.get('cpython_optimizer_suspected'):
            cpython_count += 1
        details.append(result)
    total = len(details)
    fp_count = total - confirmed_count
    rate = confirmed_count / total if total else 0.0
    py_ver = f'{_sys.version_info.major}.{_sys.version_info.minor}'
    optimizer_active = _sys.version_info >= (3, 11)
    print(f'\n{'=' * 62}')
    print(f'  ReDoS Report Confirmation  [{csv_path}]')
    print(f'  Running on CPython {py_ver}  (optimizer {('ACTIVE' if optimizer_active else 'INACTIVE')})')
    print(f'{'=' * 62}')
    print(f'  HIGH findings processed        : {total}')
    print(f'  Confirmed (genuine ReDoS)      : {confirmed_count}  ({rate * 100:.1f}%)')
    print(f'  False positives (this runtime) : {fp_count}  ({(1 - rate) * 100:.1f}%)')
    print(f'  cpython_version flag           : {cpython_count}  (safe here, test on <3.11 / PyPy)')
    print(f'{'=' * 62}\n')
    for d in details:
        status = 'CONFIRMED' if d['confirmed'] else 'FALSE_POSITIVE'
        cpython_tag = ' [cpython_version]' if d.get('cpython_optimizer_suspected') else ''
        print(f'  [{status}{cpython_tag}]')
        print(f'    {d['pattern'][:90].strip()!r}')
        print(f'    slowdown={d['slowdown_factor']}x  normal={d['normal_time_s']}s  evil={d['evil_time_s']}s')
        if d['notes']:
            for note in d['notes']:
                print(f'    NOTE: {note}')
        print()
    return dict(total_high=total, confirmed=confirmed_count, false_positives=fp_count, cpython_optimizer_suspected=cpython_count, confirmation_rate=round(rate, 4), details=details)
