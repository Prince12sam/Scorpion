#!/usr/bin/env python3
"""Deprecated script.

This repository is intended to be defensive by default and to avoid
shipping hardcoded demo targets or offensive tool invocations.
"""


def main() -> None:
    raise SystemExit(
        "Deprecated: this script previously used public demo targets and offensive tooling. "
        "Use the Scorpion CLI with an explicitly authorized target instead."
    )


if __name__ == "__main__":
    main()
