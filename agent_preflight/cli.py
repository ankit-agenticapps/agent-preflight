import argparse
import json
import os
import sys

from . import __version__
from .scanner import SEV_ORDER, START_EVENTS, scan_repo

COLORS = {"high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[2m"}
LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW "}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def counts(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}


def verdict(c, n):
    if c["high"] or c["medium"]:
        parts = []
        if c["high"]:
            parts.append("%d high" % c["high"])
        if c["medium"]:
            parts.append("%d medium" % c["medium"])
        if c["low"]:
            parts.append("%d low" % c["low"])
        if c["high"]:
            return "✗ %s — don't let an agent open this repo until you've read these" % ", ".join(parts), "high"
        return "⚠ %s — review these before letting an agent open this repo" % ", ".join(parts), "medium"
    extra = " (%d low note%s)" % (c["low"], "" if c["low"] == 1 else "s") if c["low"] else ""
    return "✓ no issues found in %d agent file%s%s" % (n, "" if n == 1 else "s", extra), "ok"


def render(path, n, findings, color):
    def paint(s, code):
        return code + s + RESET if color else s
    out = []
    out.append(paint("agent-preflight", BOLD) + "  " + path + "  " + paint("· %d agent file%s found" % (n, "" if n == 1 else "s"), DIM))
    out.append("")
    for f in findings:
        code = COLORS[f["severity"]]
        loc = "%s:%d" % (f["file"], f["line"])
        out.append("%s  %s  %s  %s" % (paint(LABEL[f["severity"]], code), paint(f["rule"], BOLD), loc, f["title"]))
        out.append("      " + paint(f["snippet"], DIM if f["severity"] == "low" else ""))
        if f.get("detail"):
            out.append("      " + paint(f["detail"], DIM))
        out.append("      " + paint("why: " + f["why"], DIM))
        out.append("")
    text, level = verdict(counts(findings), n)
    vcode = {"high": COLORS["high"], "medium": COLORS["medium"], "ok": "\033[1;32m"}[level]
    out.append(paint(text, vcode))
    return "\n".join(out)


def table(rows, color):
    w = max([len("repo")] + [len(r["repo"]) for r in rows])
    lines = ["", "%s  %5s  %4s  %3s  %3s  %5s" % ("repo".ljust(w), "files", "HIGH", "MED", "LOW", "hooks")]
    lines.append("-" * len(lines[1]))
    for r in rows:
        hi = "%4d" % r["high"]
        if color and r["high"]:
            hi = COLORS["high"] + hi + RESET
        lines.append("%s  %5d  %s  %3d  %3d  %5d" % (r["repo"].ljust(w), r["files_scanned"], hi, r["medium"], r["low"], r["hooks"]))
    n = len(rows)
    with_hooks = sum(1 for r in rows if r["hooks"])
    at_start = sum(1 for r in rows if r["hooks_start"])
    lines.append("")
    lines.append("%d of %d repo%s %s agent hooks that run commands on your machine (%d at session start)"
                 % (with_hooks, n, "" if n == 1 else "s", "ships" if with_hooks == 1 else "ship", at_start))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agent-preflight",
                                 description="Scan a repo's AI agent instruction/config files before letting an agent open it. Read-only.")
    ap.add_argument("paths", nargs="*", help="repo path(s) to scan (default: .)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--all-repos", metavar="DIR", help="scan every immediate subdirectory of DIR as its own repo")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                    help="hide (and ignore for the exit code) findings below this severity")
    ap.add_argument("--version", action="version", version="agent-preflight " + __version__)
    args = ap.parse_args(argv)

    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except Exception:
            pass

    targets = list(args.paths)
    if args.all_repos:
        d = args.all_repos
        if not os.path.isdir(d):
            print("agent-preflight: not a directory: %s" % d, file=sys.stderr)
            return 3
        targets += sorted(os.path.join(d, x) for x in os.listdir(d)
                          if os.path.isdir(os.path.join(d, x)) and not x.startswith("."))
    elif not targets:
        targets = ["."]

    color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    floor = SEV_ORDER[args.min_severity]
    results, worst = [], 0
    for t in targets:
        if not os.path.isdir(t):
            print("agent-preflight: not a directory: %s" % t, file=sys.stderr)
            worst = max(worst, 3)
            continue
        n, fs = scan_repo(t)
        hook_fs = [f for f in fs if f["rule"] == "PF001"]
        hooks = len(hook_fs)
        hooks_start = sum(1 for f in hook_fs if f.get("event") in START_EVENTS)
        fs = [f for f in fs if SEV_ORDER[f["severity"]] >= floor]
        c = counts(fs)
        results.append({"path": os.path.abspath(t), "repo": os.path.basename(os.path.abspath(t)), "files_scanned": n,
                        "findings": fs, "hooks": hooks, "hooks_start": hooks_start, **c})
        worst = max(worst, 2 if c["high"] else 1 if c["medium"] else 0)

    if args.json:
        allf = [dict(f, repo=r["path"]) for r in results for f in r["findings"]]
        tot = {s: sum(r[s] for r in results) for s in ("high", "medium", "low")}
        print(json.dumps({
            "findings": allf,
            "summary": dict(tot, repos=len(results), files_scanned=sum(r["files_scanned"] for r in results), exit_code=worst),
            "repos": [{k: r[k] for k in ("path", "files_scanned", "high", "medium", "low", "hooks", "hooks_start")} for r in results],
        }, indent=2, ensure_ascii=False))
        return worst

    for i, r in enumerate(results):
        if i:
            print("\n" + "=" * 60 + "\n")
        print(render(r["path"], r["files_scanned"], r["findings"], color))
    if len(results) > 1 or args.all_repos:
        print(table(results, color))
    return worst
