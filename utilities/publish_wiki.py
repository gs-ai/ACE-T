#!/usr/bin/env python3
"""Utility to publish the local wiki/ directory to the GitHub wiki repo.

This script synchronises the contents of the `wiki/` directory with the
GitHub-hosted wiki repository for ACE-T. It clones (or reuses) a working
copy of the wiki repo, copies files across, commits, and pushes.

It requires that you have push access to the GitHub wiki remote. Provide a
personal access token via the environment (see README for details) or rely
on an existing credential helper.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a subprocess command and return the completed process."""
    return subprocess.run(cmd, cwd=cwd, check=True)


def git_root() -> Path:
    """Locate the root of the current git repository."""
    return Path(
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True)
        .strip()
    )


def infer_wiki_remote(base_url: str) -> str:
    """Infer the wiki remote URL from a standard GitHub remote."""
    if base_url.endswith(".git"):
        base_url = base_url[:-4]
    return f"{base_url}.wiki.git"


def copy_tree(src: Path, dest: Path) -> None:
    """Copy the contents of src into dest, replacing existing files."""
    if not src.exists():
        raise FileNotFoundError(f"Wiki source directory {src} does not exist")

    # Remove anything currently tracked in the wiki repo that is missing locally.
    to_remove: list[Path] = []
    for existing in dest.glob("**/*"):
        if ".git" in existing.parts:
            continue
        if not (src / existing.relative_to(dest)).exists():
            to_remove.append(existing)

    for target in sorted(to_remove, key=lambda p: len(p.parts), reverse=True):
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
        elif target.exists():
            target.unlink()

    for item in src.rglob("*"):
        relative = item.relative_to(src)
        target = dest / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def publish(remote: str, wiki_url: str | None, branch: str) -> None:
    repo_root = git_root()
    wiki_src = repo_root / "wiki"
    if not wiki_src.exists():
        raise SystemExit("wiki/ directory not found. Nothing to publish.")

    if wiki_url is None:
        base_remote_url = subprocess.check_output(
            ["git", "remote", "get-url", remote], text=True
        ).strip()
        wiki_url = infer_wiki_remote(base_remote_url)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        run(["git", "clone", wiki_url, str(tmp_path)])
        try:
            run(["git", "checkout", branch], cwd=tmp_path)
        except subprocess.CalledProcessError:
            run(["git", "checkout", "-b", branch], cwd=tmp_path)
        copy_tree(wiki_src, tmp_path)

        run(["git", "add", "-A"], cwd=tmp_path)
        status = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=tmp_path, text=True
        ).strip()
        if not status:
            print("Wiki repository is already up to date. No push performed.")
            return

        message = os.environ.get("WIKI_COMMIT_MESSAGE", "Update ACE-T wiki")
        run(["git", "commit", "-m", message], cwd=tmp_path)
        run(["git", "push", "origin", branch], cwd=tmp_path)
        print("Wiki updated successfully.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote name to derive the wiki URL from (default: origin)",
    )
    parser.add_argument(
        "--wiki-url",
        help="Explicit wiki git URL. Overrides inference from --remote.",
    )
    parser.add_argument(
        "--branch",
        default="master",
        help="Wiki branch to push to (default: master)",
    )
    args = parser.parse_args(argv)

    try:
        publish(args.remote, args.wiki_url, args.branch)
    except subprocess.CalledProcessError as exc:
        print(f"Command failed: {' '.join(exc.cmd)}", file=sys.stderr)
        raise SystemExit(exc.returncode) from exc


if __name__ == "__main__":
    main()
