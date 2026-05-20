#!/usr/bin/env python3
"""
prepare_wordlist.py  —  Setup tool

Creates wordlist_small.txt (the 10,000 most common passwords from rockyou.txt).
Students use this file while building and testing their cracker in Phases 2-3.
For final experiments, they point their cracker at rockyou.txt directly.

Usage
-----
python prepare_wordlist.py                        # auto-locate rockyou.txt
python prepare_wordlist.py /path/to/rockyou.txt   # explicit path

Accepts both rockyou.txt and rockyou.txt.gz.
No external dependencies required.
"""

import gzip
import os
import sys


# =============================================================================
# CONFIGURATION
# =============================================================================

WORDLIST_SMALL_PATH = "wordlist_small.txt"
WORDLIST_SMALL_SIZE = 10_000

# Locations to search for rockyou.txt if no path is given on the command line.
# Add more paths here if your system stores it elsewhere.
SEARCH_PATHS = [
    "rockyou.txt",
    "rockyou.txt.gz",
    "wordlists/rockyou.txt",
    "wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
]

# These passwords must appear in any genuine rockyou.txt.
# Used as a sanity check that the file is complete and correctly read.
SANITY_PASSWORDS = ["password", "123456", "iloveyou", "sunshine", "dragon"]


# =============================================================================
# FUNCTIONS
# =============================================================================

def find_rockyou():
    """Return the path to rockyou.txt/.gz if found in a known location."""
    for path in SEARCH_PATHS:
        if os.path.exists(path):
            return path
    return None


def open_wordlist_file(path):
    """Open rockyou.txt or rockyou.txt.gz for binary reading."""
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def read_top_passwords(path, limit):
    """
    Read the first `limit` unique, non-empty passwords from rockyou.txt.

    rockyou.txt is sorted most-common first, so the first N unique lines
    are the N most common passwords.

    Tries UTF-8 decoding first, then falls back to Latin-1.
    Returns (list_of_passwords, number_of_lines_skipped_due_to_errors).
    """
    passwords = []
    seen = set()
    skipped = 0

    with open_wordlist_file(path) as f:
        for raw_line in f:
            try:
                word = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError:
                try:
                    word = raw_line.decode("latin-1").strip()
                except UnicodeDecodeError:
                    skipped += 1
                    continue

            # Skip empty lines and duplicates
            if not word or word in seen:
                continue

            seen.add(word)
            passwords.append(word)

            if len(passwords) >= limit:
                break

    return passwords, skipped


def write_wordlist_small(path, passwords):
    """
    Write passwords to wordlist_small.txt, one per line, no comments.

    No comments or headers: students read this file line by line in their
    cracker and should not need to handle any special characters.
    """
    with open(path, "w", encoding="utf-8") as f:
        for pw in passwords:
            f.write(pw + "\n")


def update_gitignore():
    """Add rockyou.txt and rockyou.txt.gz to .gitignore if not already there."""
    entries = ["rockyou.txt", "rockyou.txt.gz"]
    gitignore_path = ".gitignore"

    existing = ""
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r") as f:
            existing = f.read()

    to_add = [e for e in entries if e not in existing]
    if to_add:
        with open(gitignore_path, "a") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            for entry in to_add:
                f.write(entry + "\n")


def print_not_found_instructions():
    print("\nError: rockyou.txt not found.")
    print()
    print("How to get rockyou.txt:")
    print()
    print("  Option 1 — Kali Linux (already installed):")
    print("    gunzip /usr/share/wordlists/rockyou.txt.gz")
    print("    cp /usr/share/wordlists/rockyou.txt .")
    print()
    print("  Option 2 — macOS / Linux (download manually):")
    print("    Search for 'rockyou.txt SecLists' on GitHub.")
    print("    The file is ~133 MB. Place it in the project root directory.")
    print()
    print("  Option 3 — provide the path directly:")
    print("    python prepare_wordlist.py /path/to/rockyou.txt")
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    # ── 1. Locate rockyou.txt ─────────────────────────────────────────────
    if len(sys.argv) > 1:
        rockyou_path = sys.argv[1]
        if not os.path.exists(rockyou_path):
            print(f"\nError: file not found: {rockyou_path}")
            sys.exit(1)
    else:
        rockyou_path = find_rockyou()

    if rockyou_path is None:
        print_not_found_instructions()
        sys.exit(1)

    file_size_mb = os.path.getsize(rockyou_path) / (1024 * 1024)
    print(f"\nFound : {rockyou_path}  ({file_size_mb:.0f} MB)")

    # ── 2. Read the top N passwords ───────────────────────────────────────
    print(f"Reading top {WORDLIST_SMALL_SIZE:,} passwords...")
    passwords, skipped = read_top_passwords(rockyou_path, WORDLIST_SMALL_SIZE)

    if len(passwords) < WORDLIST_SMALL_SIZE:
        print(f"\nWarning: only found {len(passwords):,} passwords (expected {WORDLIST_SMALL_SIZE:,}).")
        print("The file may be incomplete.")

    # ── 3. Sanity check ───────────────────────────────────────────────────
    missing = [p for p in SANITY_PASSWORDS if p not in passwords]
    if missing:
        print(f"\nWarning: these expected passwords were not found in the top {WORDLIST_SMALL_SIZE:,}:")
        for p in missing:
            print(f"  '{p}'")
        print("The file may be incorrectly formatted, truncated, or not rockyou.txt.")

    # ── 4. Write wordlist_small.txt ───────────────────────────────────────
    write_wordlist_small(WORDLIST_SMALL_PATH, passwords)
    update_gitignore()

    # ── 5. Print summary ──────────────────────────────────────────────────
    print()
    print("=" * 52)
    print(f"  wordlist_small.txt created")
    print(f"  Passwords written : {len(passwords):,}")
    if skipped:
        print(f"  Lines skipped     : {skipped}  (encoding errors)")
    print()
    print("  First 5 entries (most common passwords):")
    for pw in passwords[:5]:
        print(f"    {pw}")
    print("  ...")
    print(f"  Entry {WORDLIST_SMALL_SIZE:,}:")
    print(f"    {passwords[-1]}")
    print()
    print("  rockyou.txt and rockyou.txt.gz added to .gitignore")
    print("=" * 52)
    print()
    print("Students use wordlist_small.txt for development (fast to iterate).")
    print("For final timed experiments, use rockyou.txt directly.")
    print()


if __name__ == "__main__":
    main()
