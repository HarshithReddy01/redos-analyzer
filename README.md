# redos-analyzer

redos-analyzer is a static analysis tool that detects and automatically fixes Regular Expression Denial of Service vulnerabilities in Python codebases. Unlike online checkers that test patterns by running them against adversarial inputs, this tool works by walking Python's own internal `sre_parse` abstract syntax tree, the same representation CPython uses when it compiles a regex, so it sees exactly what the engine sees, including optimizations, without executing anything. When a dangerous pattern is found, the tool generates a corrected version using atomic groups, verifies that the fix preserves the original matching semantics, and reports whether the fix is safe to apply. The tool was validated against the top 20 most-downloaded PyPI packages and confirmed detections against real maintainer-acknowledged issues.


## What is ReDoS

Most regular expression engines, including Python's `re` module, use a backtracking strategy to find matches. When a pattern is written in a way that allows the same input to be matched in multiple overlapping ways, the engine is forced to explore an exponential number of possible combinations before it can confirm a non-match. The time taken grows not linearly but exponentially with input length — a pattern that takes one millisecond on ten characters may take minutes on thirty. An attacker who can supply input to a web server that applies such a pattern can cause a complete service stall with a single crafted request. This is not theoretical. In July 2019, Cloudflare suffered a global outage lasting 27 minutes because a single poorly written regex in their WAF rule set triggered catastrophic backtracking under normal traffic conditions, taking their entire edge network offline.

```
Input length 10  ->  ~0.001s
Input length 20  ->  ~0.884s    (884x slower)
Input length 30  ->  ~hours
Input length 40  ->  longer than the age of the universe
```

The doubling of input length roughly squares the time, which is the hallmark of exponential complexity. The pattern does not need to be obviously malicious — most ReDoS vulnerabilities are introduced accidentally by developers who have no idea the pattern they wrote is dangerous.


## What Makes This Different

Three things separate this tool from existing options. First, it does not just detect, it generates a corrected pattern using atomic group syntax and runs a semantic equivalence check before presenting the fix, so you are not left to figure out the repair yourself. Second, it analyzes the `sre_parse` AST rather than the raw pattern string, which means it sees patterns the way Python actually compiles them, including prefix factoring and other internal normalizations that change what the backtracker encounters at runtime. Online checkers and tools that operate on raw regex text can miss vulnerabilities that are only visible at the AST level, or flag patterns that are actually safe after internal optimization. Third, the exploitability classifier reads the surrounding source code context to distinguish patterns that match user-supplied input from patterns applied to trusted internal strings, so findings are graded by real-world risk rather than raw structural danger.


## Installation

Clone the repository and install the single runtime dependency. PyPI publication is coming soon, at which point a standard `pip install redos-analyzer` will be available.

```bash
git clone https://github.com/HarshithReddy01/redos-analyzer.git
cd redos-analyzer
pip install -r requirements.txt
```


## Quick Start

The core API is `analyze()`, which takes a pattern string and returns a list of warnings, and `suggest_fix()`, which takes a pattern and a warning and returns a corrected pattern along with a verification result.

```python
from redos_analyzer import analyze, suggest_fix

warnings = analyze(r'(a+)+')
print(warnings[0])
# [NESTED_QUANTIFIER]
#   Location       : col 0-5  '(a+)+'
#   Sub-pattern    : (a+)+
#   Exploitability : POSSIBLE
#   Detail         : Repeating quantifier '+' on 'a+' is nested inside the
#                    outer repeating quantifier. On a failing match the engine
#                    must explore an exponential number of ways to partition
#                    the input across the two quantifiers.

fix = suggest_fix(r'(a+)+', warnings[0])
print(fix['fixed'])            # (?>a+)+
print(fix['verified'])         # True
print(fix['semantics_preserved'])  # confirmed by verify_fix()
```

The `verified` field means `analyze()` returned no warnings on the fixed pattern. The `semantics_preserved` check runs both patterns against a suite of test inputs and confirms the match results are identical.


## Warning Classes

| Class | Severity | What it means | Example |
|---|---|---|---|
| `NESTED_QUANTIFIER` | HIGH | A repeating quantifier wraps a body that itself contains a repeating quantifier, creating an exponential number of ways to partition input | `(a+)+` |
| `NULLABLE_BRANCH_IN_QUANTIFIER` | HIGH | A quantifier's alternation contains a branch that can match the empty string, allowing infinite zero-progress iterations | `(a\|a?)+` |
| `OVERLAPPING_ALTERNATION` | MEDIUM | Two branches inside a repeating quantifier share overlapping first characters or one literal is a prefix of another | `(a\|aa)+` |
| `LIKELY_TYPO` | MEDIUM | The sequence `(:?` appears in the pattern, which is almost certainly a typo for the non-capturing group marker `(?:` | `(:?foo\|bar)+` |


## Scanning a Package

`scan_pypi.py` downloads the source distribution of each package in its target list, extracts every `.py` file, parses each file's AST to find `re.compile`, `re.search`, `re.match` and related calls, extracts statically determinable pattern strings, and runs the full analysis pipeline on each one. Findings are classified by context type — runtime, test, vendored, or tooling — so the summary focuses on production code by default. Results are written to `redos_report.csv` and `scan_summary.txt`.

```bash
python scan_pypi.py           # runtime findings only
python scan_pypi.py --all     # include test and vendored code
```

```
  Package            Total   Runtime    HIGH    MEDIUM
  ----------------  ------  --------  ------  --------
  sqlalchemy             8         8       4         4  <-- HIGH RISK
  numpy                 41        12      11         0  <-- HIGH RISK
  aiohttp                8         8       5         3  <-- HIGH RISK
  pytest                10        10       1         9  <-- HIGH RISK
```


## Real World Findings

Scanning the top 20 PyPI packages produced 90 raw warnings, which reduced to 23 confirmed runtime findings after filtering out vendored dependencies and test infrastructure. The results confirmed that ReDoS vulnerabilities are not obscure edge cases — they appear in actively maintained, widely deployed libraries.

In aiohttp, the WebSocket extension header parser (`_WS_EXT_RE` in `helpers.py`) was confirmed as a genuine ReDoS vulnerability using domain-specific adversarial inputs. The pattern is reached through `headers.get()` in the WebSocket handshake handler, meaning it processes attacker-controlled input on every connection. The aiohttp maintainers had independently identified and fixed _COOKIE_PATTERN in pull request 11900 following a prior security audit, confirming our tool detected the same issue. In pytest, the token pattern in `expression.py` contained `(:?\\w|:|...)` — a genuine typo of `(?:...)` that creates a capturing group with an optional colon rather than a non-capturing group. This is a correctness bug independent of ReDoS risk, and the `LIKELY_TYPO` detector found it automatically. Across the full scan, 9 out of 10 HIGH-severity patterns were fixed automatically using atomic groups, and all 9 verified fixes preserved match semantics exactly across the full semantic test suite. The fact that maintainers had independently identified and fixed the aiohttp finding confirms that the detector is finding real issues rather than false positives.


## How the Fixer Works

An atomic group, written `(?>...)` in Python 3.11 and newer, acts like a one-way door in the regex engine. Once the engine enters the group and finds a match, it commits to that match and is not permitted to go back and try a shorter one, even if the rest of the pattern fails. This eliminates the exponential search because the engine can no longer explore multiple ways to partition input across a repeated group, it takes the first partition and moves on. The fix is applied by rebuilding the pattern from its `sre_parse` AST using a modified reconstruction function that wraps each dangerous repeating quantifier body in an atomic group. Capturing groups are preserved as `((?>...))` rather than `(?>...)` so that group numbers and named back-references remain valid.

```
BEFORE   (a+)+          dangerous — engine explores all ways to split 'aaa...!'
AFTER    (?>a+)+         safe — engine commits to greedy match, no backtracking
```


## Limitations

Because the fixer rebuilds patterns from the `sre_parse` AST rather than editing the original string, the output pattern is semantically equivalent but may look different. Specifically, `sre_parse` normalizes shorthand character classes: `\s` becomes `[\s]`, `\d` becomes `[\d]`, and so on. The fixed pattern cannot be dropped in as a line-level replacement in source code without review — it should be understood as a specification of what the safe pattern means rather than a ready-to-paste string.

The tool flags all repeating quantifiers whose structure is ambiguous, including bounded ones like `{0,2}`. In practice, a quantifier with a small fixed maximum creates at most a polynomial blowup rather than an exponential one, and CPython's internal optimizer often eliminates the risk entirely on Python 3.11 and newer. The `cpython_optimizer_suspected` flag in the timing output identifies these cases. Findings should be reviewed in context rather than treated as uniformly critical.

The adversarial input generator used in timing verification is heuristic. It picks a repeating character based on the character classes in the pattern and appends a non-matching character to force the engine to exhaust all possibilities. For patterns anchored to specific prefixes, such as SQLAlchemy's `create table ...` parser — the heuristic input will not trigger the worst-case path, and the reported speedup ratio will be misleadingly low. Domain-specific evil inputs, as demonstrated in the aiohttp analysis, are needed to confirm timing in those cases.

Atomic group syntax requires Python 3.11 or newer. On earlier versions, the generated fix patterns will raise a `re.error` if compiled. The detection half of the tool — `analyze()` and the scanner, works on Python 3.8 and newer and requires no modifications. If you need fixes on older Python, the `regex` third-party module supports atomic groups back to Python 2 using the same `(?>...)` syntax.

Exploitability classification uses heuristics based on the source code context around the regex call site: the presence of `request.args`, `headers.get()`, `sys.argv`, and similar signals raises the score, while ALL-CAPS constant names and length guards lower it. This is not dataflow analysis. A pattern that receives its input from a variable defined twenty lines above the call will not be classified correctly unless the surrounding window happens to include a recognizable signal. Cross-file call chains — such as the aiohttp case where the pattern is defined in `helpers.py` but reached via `web_ws.py` — are not tracked at all.


## Requirements

Automatic fix generation requires Python 3.11 or newer because atomic group syntax (`(?>...)`) was added to the `re` module in that release. Detection, classification, and the PyPI scanner work on Python 3.8 and newer. The only third-party dependency is `requests`, used to download package source distributions during scanning. All analysis is performed using Python's standard library.


## Citation

If you use this tool in research, please cite it using the Zenodo DOI [placeholder — DOI will be assigned on first release]. This tool was developed as independent research into static ReDoS detection and automated remediation for the Python ecosystem.


## License

MIT
