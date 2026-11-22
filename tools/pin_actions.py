#!/usr/bin/env python3
"""Pin every GitHub Action in .github/workflows to a full commit SHA.

Tags like actions/checkout@v5 can be moved by whoever controls the action's repo; that's how the
2025 tj-actions compromise spread. A 40-character commit SHA can't be moved.

  python tools/pin_actions.py            # resolve with your authenticated `gh`, rewrite in place
  python tools/pin_actions.py --check    # exit 1 if anything is unpinned (CI runs this as a test)

Rewrites   uses: actions/checkout@v5
into       uses: actions/checkout@<sha> # v5
Dependabot (.github/dependabot.yml) then proposes updates as reviewed PRs, keeping the comment.
"""
import glob, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USES = re.compile(r"^(\s*-?\s*uses:\s*)([\w.-]+/[\w./-]+)@([^\s#]+)(\s*#.*)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def workflows():
    return sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.y*ml")))


def unpinned():
    bad = []
    for path in workflows():
        with open(path) as fh:
            for n, line in enumerate(fh, 1):
                m = USES.match(line.rstrip("\n"))
                if m and not m.group(2).startswith("./") and not SHA.match(m.group(3)):
                    bad.append(f"{os.path.relpath(path, ROOT)}:{n}: {m.group(2)}@{m.group(3)}")
    return bad


def resolve(action, ref):
    owner_repo = "/".join(action.split("/")[:2])
    out = subprocess.run(["gh", "api", f"repos/{owner_repo}/commits/{ref}", "--jq", ".sha"],
                         capture_output=True, text=True)
    sha = out.stdout.strip()
    if out.returncode != 0 or not SHA.match(sha):
        raise SystemExit(f"could not resolve {action}@{ref}: {out.stderr.strip() or sha}")
    return sha


def pin():
    for path in workflows():
        with open(path) as fh:
            lines = fh.read().split("\n")
        changed = False
        for i, line in enumerate(lines):
            m = USES.match(line)
            if m and not SHA.match(m.group(3)):
                sha = resolve(m.group(2), m.group(3))
                lines[i] = f"{m.group(1)}{m.group(2)}@{sha} # {m.group(3)}"
                print(f"{os.path.relpath(path, ROOT)}: {m.group(2)}@{m.group(3)} -> {sha}")
                changed = True
        if changed:
            with open(path, "w", newline="\n") as fh:
                fh.write("\n".join(lines))


if __name__ == "__main__":
    if "--check" in sys.argv:
        bad = unpinned()
        print("\n".join(bad) if bad else "all actions pinned")
        sys.exit(1 if bad else 0)
    pin()
    bad = unpinned()
    sys.exit(1 if bad else 0)
