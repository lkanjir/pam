#!/usr/bin/env python3
"""Verify that the repository's shared skills match the reviewed lock file."""

import hashlib
import json
from pathlib import Path
import sys


def main():
    root = Path(__file__).resolve().parent.parent
    lock = json.loads((root / "agent-skills.lock.json").read_text(encoding="utf-8"))
    skills_root = root / ".agents" / "skills"
    expected = set()
    errors = []

    for skill in lock["skills"]:
        for relative, digest in skill["files"].items():
            target = skills_root / skill["name"] / relative
            expected.add(target)
            if not target.is_file() or target.is_symlink():
                errors.append(f"Missing or unsupported skill file: {target.relative_to(root)}")
            elif hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                errors.append(f"Changed skill file: {target.relative_to(root)}")

    actual = {path for path in skills_root.rglob("*") if path.is_file() or path.is_symlink()}
    for target in sorted(actual - expected):
        errors.append(f"Unlisted skill file: {target.relative_to(root)}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"Verified {len(lock['skills'])} shared skills ({len(expected)} files).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
