"""Pre-deploy guard for the TrainingPeaks MCP server.

Wraps `modal deploy main.py` with sanity checks so we don't ship code from a
dirty tree, the wrong branch, or a checkout that's behind origin/main.

Unlike the Garmin MCP, the TrainingPeaks cookie has no machine-readable
expiry (it's a session cookie that lasts weeks), so there's no token-freshness
check — rotate via the deployed `/refresh-cookie` endpoint instead.

Usage:
    uv run python deploy.py            # enforce all checks
    uv run python deploy.py --force    # bypass all checks (emergencies)
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def _run(*cmd: str, check: bool = True) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=check).stdout.strip()


def _check_clean() -> str | None:
    if subprocess.run(["git", "diff", "--quiet", "HEAD"]).returncode != 0:
        diff = subprocess.run(
            ["git", "diff", "--name-status", "HEAD"], capture_output=True, text=True
        ).stdout
        return f"working tree has uncommitted changes to tracked files:\n{diff}"
    return None


def _check_on_main() -> str | None:
    branch = _run("git", "rev-parse", "--abbrev-ref", "HEAD")
    if branch != "main":
        return f"not on 'main' (currently on '{branch}')"
    return None


def _check_up_to_date() -> str | None:
    try:
        subprocess.run(["git", "fetch", "origin", "main", "--quiet"], check=True)
    except subprocess.CalledProcessError:
        return "could not fetch origin/main (is the remote configured?)"
    behind = int(_run("git", "rev-list", "--count", "HEAD..origin/main"))
    if behind > 0:
        return f"HEAD is {behind} commit(s) behind origin/main"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="skip safety checks")
    args = parser.parse_args()

    if not args.force:
        for check in (_check_clean, _check_on_main, _check_up_to_date):
            err = check()
            if err:
                print(f"x {err}", file=sys.stderr)
                print("Re-run with --force to override.", file=sys.stderr)
                return 1

    sha = _run("git", "rev-parse", "--short", "HEAD")
    branch = _run("git", "rev-parse", "--abbrev-ref", "HEAD")
    print(f"-> Deploying {sha} from {branch}")
    return subprocess.call(["uv", "run", "modal", "deploy", "main.py"])


if __name__ == "__main__":
    sys.exit(main())
