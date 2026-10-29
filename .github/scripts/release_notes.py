#!/usr/bin/env python3
"""Writes release notes (Markdown) from the commits between the previous tag and TAG.

    release_notes.py <tag> [<previous-tag>]

Each non-merge commit becomes a "### subject" with its "- " bullets from the commit body; a commit without bullets becomes a plain
bullet. A "Full Changelog" link closes the notes (the app's update sheet leaves that line out).
"""
import re
import subprocess
import sys

tag = sys.argv[1]
repo = "YashDayani/ArchiveX"


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


prev = sys.argv[2] if len(sys.argv) > 2 else ""
if not prev:
    try:
        prev = git("describe", "--tags", "--abbrev=0", f"{tag}^").strip()
    except subprocess.CalledProcessError:
        prev = ""

rng = f"{prev}..{tag}" if prev else tag
sep, end = "\x1e", "\x1f"
log = git("log", rng, "--no-merges", f"--pretty=format:%s{sep}%b{end}")

out = ["## What's new", ""]
for chunk in log.split(end):
    chunk = chunk.strip("\n")
    if not chunk.strip():
        continue
    subject, _, body = chunk.partition(sep)
    subject = subject.strip()
    if not subject:
        continue
    bullets = []
    for line in body.splitlines():
        if re.match(r"^\s*[-*] ", line) and not line.startswith("  "):
            bullets.append(re.sub(r"^\s*[-*] ", "", line).strip())
        elif line.startswith("  ") and bullets and line.strip():
            bullets[-1] += " " + line.strip()        # a wrapped bullet continues on the next line
    bullets = [b for b in bullets if not b.lower().startswith("co-authored-by")]
    if bullets:
        out.append(f"### {subject}")
        out.extend(f"- {b}" for b in bullets)
        out.append("")
    else:
        out.append(f"- {subject}")

if out[-1] != "":
    out.append("")
if prev:
    out.append(f"**Full Changelog**: https://github.com/{repo}/compare/{prev}...{tag}")
print("\n".join(out))
