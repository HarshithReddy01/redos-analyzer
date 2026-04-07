import sys

from redos_analyzer import analyze, suggest_fix


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="redos-scan",
        description="Detect and fix ReDoS vulnerabilities in regex patterns.",
    )
    parser.add_argument("pattern", help="Regex pattern to analyze")
    parser.add_argument("--fix", action="store_true", help="Suggest an automatic fix")
    args = parser.parse_args()

    warnings = analyze(args.pattern)
    if not warnings:
        print(f"[OK] No ReDoS issues found in: {args.pattern!r}")
        sys.exit(0)

    for w in warnings:
        print(w)
        print()

    if args.fix:
        fix = suggest_fix(args.pattern, warnings[0])
        print(f"Fixed pattern : {fix['fixed']!r}")
        print(f"Verified      : {fix['verified']}")
        print(f"Fix type      : {fix['fix_type']}")

    sys.exit(1)


if __name__ == "__main__":
    main()
