#!/usr/bin/env python3
"""Clean ACE-T generated/downloaded data recursively.

By default, this removes downloaded/generated artifacts across the repo, including:
- output/
- alerts_for_review/
- alerts/
- tmp_alerts/
- tmp_checkpoints/
- checkpoints/
- data/alerts/
- data/checkpoints/
- data/reddit_cache/
- evidence/
- logs/
- state/
- http_cache.json (root or under data/)
- __pycache__ directories (recursive)
- test.db (if present)

Use --dry-run to preview without deleting.
"""

import argparse
import os
import shutil
from pathlib import Path


def repo_root() -> Path:
    # scripts/ is one level below repo root
    return Path(__file__).resolve().parents[1]


DEFAULT_TARGETS = [
    # top-level directories
    "output",
    "alerts_for_review",
    "alerts",
    "tmp_alerts",
    "tmp_checkpoints",
    "checkpoints",
    "evidence",
    "logs",
    "state",
    # data subfolders produced during runs
    "data/alerts",
    "data/checkpoints",
    "data/reddit_cache",
    # common cache files
    "http_cache.json",
    "data/http_cache.json",
]


def _ensure_within_repo(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def remove_contents_of_dir(path: Path, dry_run: bool = False) -> int:
    """Remove all children of a directory but leave the directory itself.
    Returns count of removed entries.
    """
    if not path.exists() or not path.is_dir():
        return 0
    removed = 0
    for child in path.iterdir():
        try:
            if child.is_dir():
                if dry_run:
                    print(f"DRY-RUN rm -rf {child}")
                else:
                    shutil.rmtree(child)
                removed += 1
            else:
                if dry_run:
                    print(f"DRY-RUN rm {child}")
                else:
                    child.unlink(missing_ok=True)
                removed += 1
        except Exception as e:
            print(f"[!] Failed to remove {child}: {e}")
    return removed


def remove_path(path: Path, dry_run: bool = False) -> int:
    """Remove a file or directory entirely. Returns 1 if removed, 0 otherwise."""
    if not path.exists():
        return 0
    try:
        if path.is_dir():
            if dry_run:
                print(f"DRY-RUN rm -rf {path}")
            else:
                shutil.rmtree(path)
        else:
            if dry_run:
                print(f"DRY-RUN rm {path}")
            else:
                path.unlink(missing_ok=True)
        return 1
    except Exception as e:
        print(f"[!] Failed to remove {path}: {e}")
        return 0


def remove_pycache(root: Path, dry_run: bool = False) -> int:
    """Recursively remove __pycache__ directories under root."""
    removed = 0
    for dirpath, dirnames, _ in os.walk(root):
        # Make a copy of dirnames to avoid modifying while iterating
        for d in list(dirnames):
            if d == "__pycache__":
                target = Path(dirpath) / d
                if dry_run:
                    print(f"DRY-RUN rm -rf {target}")
                else:
                    shutil.rmtree(target, ignore_errors=True)
                removed += 1
    return removed


def clean_workspace(targets: list[str], dry_run: bool = False) -> None:
    root = repo_root()
    total_removed = 0

    # Remove known generated directories/files
    for rel in targets:
        p = (root / rel).resolve()
        if not _ensure_within_repo(root, p):
            print(f"[!] Skipping outside-of-repo path: {p}")
            continue
        if not p.exists():
            print(f"[-] Missing (skip): {p}")
            continue

        # For directories, clear contents (keep dir). For files, delete file.
        if p.is_dir():
            print(f"[+] Clearing directory: {p}")
            total_removed += remove_contents_of_dir(p, dry_run=dry_run)
        else:
            print(f"[+] Removing file: {p}")
            total_removed += remove_path(p, dry_run=dry_run)

    # Remove test.db if present
    db_path = (root / "test.db").resolve()
    if db_path.exists():
        print(f"[+] Removing database: {db_path}")
        total_removed += remove_path(db_path, dry_run=dry_run)
    else:
        print(f"[-] Database not found (skip): {db_path}")

    # Recursively remove __pycache__
    print("[+] Removing __pycache__ directories ...")
    total_removed += remove_pycache(root, dry_run=dry_run)

    print(f"[✓] Clean complete. Entries scheduled{' (dry-run)' if dry_run else ''}: {total_removed}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Clean ACE-T generated/downloaded data recursively")
    p.add_argument("--dry-run", action="store_true", help="Preview what would be deleted without removing anything")
    p.add_argument(
        "--targets",
        default=",".join(DEFAULT_TARGETS),
        help="Comma-separated repo-relative paths to clean (directories are cleared, files removed)",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    clean_workspace(targets, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
