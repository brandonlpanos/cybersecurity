#!/usr/bin/env python3
"""
reference_solution.py  —  INSTRUCTOR USE ONLY

Complete working implementation of every function in cracker.py.
Do not distribute to students.

Also used as the basis for grade_component2.py (automated grading pipeline).
"""

import csv
import hashlib
import itertools
import os
import string
import time
import zipfile


# =============================================================================
# SHARED HELPERS  (identical to cracker.py)
# =============================================================================

def try_password(zip_path, password):
    """Try a single password. Returns True if correct, False otherwise."""
    try:
        with zipfile.ZipFile(zip_path) as zf:
            name = zf.namelist()[0]
            zf.read(name, pwd=password.encode())
        return True
    except Exception:
        return False


def save_result(phase, filename, password, time_seconds):
    """Save a cracked password to results/phaseN.csv."""
    os.makedirs("results", exist_ok=True)
    csv_path = f"results/phase{phase}.csv"
    write_header = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["filename", "password", "time_seconds"])
        writer.writerow([filename, password, round(time_seconds, 3)])
    print(f"  saved  {filename}  |  password: {password}  |  {time_seconds:.3f}s")


def load_hashes(filepath):
    """Read a hash challenge file. Returns list of (id, difficulty, hash)."""
    hashes = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(":")]
            if len(parts) == 3:
                hashes.append((parts[0], parts[1], parts[2]))
    return hashes


# =============================================================================
# PHASE 1 — Brute Force (digits only)
# =============================================================================

def brute_force_digits(zip_path, max_length=6):
    """Try every digit-only combination from length 1 up to max_length."""
    start = time.time()
    for length in range(1, max_length + 1):
        print(f"  Trying length {length}...", end="\r")
        for combo in itertools.product("0123456789", repeat=length):
            password = "".join(combo)
            if try_password(zip_path, password):
                elapsed = time.time() - start
                print()
                return password, elapsed
    return None, time.time() - start


# =============================================================================
# PHASE 2 — Extended Brute Force + Dictionary Attack
# =============================================================================

def brute_force(zip_path, charset, max_length):
    """Generalised brute force — works with any character set."""
    start = time.time()
    for length in range(1, max_length + 1):
        print(f"  Trying length {length} (charset size {len(charset)})...", end="\r")
        for combo in itertools.product(charset, repeat=length):
            password = "".join(combo)
            if try_password(zip_path, password):
                elapsed = time.time() - start
                print()
                return password, elapsed
    return None, time.time() - start


def dictionary_attack(zip_path, wordlist_path):
    """Try every word in wordlist_path as a password."""
    start = time.time()
    count = 0
    with open(wordlist_path, encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue
            count += 1
            if count % 10_000 == 0:
                print(f"  {count:,} words tried...", end="\r")
            if try_password(zip_path, password):
                elapsed = time.time() - start
                print()
                return password, elapsed
    return None, time.time() - start


# =============================================================================
# PHASE 3 — Hybrid Attacks + Hash Cracking
# =============================================================================

LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "+"}

SUFFIXES = ["!", "123", "1234", "123!", "2024", "2023", "2022", "2021", "2020", "#1"]


def _apply_leet(word):
    """Apply all leet substitutions to word at once."""
    for char, sub in LEET_MAP.items():
        word = word.replace(char, sub)
    return word


def apply_rules(word):
    """
    Apply all hybrid attack transformations to a single word.
    Returns a list of candidate passwords (no duplicates).
    """
    variants = set()

    for base in [word, word.capitalize()]:
        leet_base = _apply_leet(base)
        for b in [base, leet_base]:
            variants.add(b)
            for suffix in SUFFIXES:
                variants.add(b + suffix)
            for i in range(100):
                variants.add(b + str(i))

    return list(variants)


def hybrid_attack(zip_path, wordlist_path):
    """
    For each word in the wordlist, generate all rule-based variants and
    try each one against the ZIP file.
    """
    start = time.time()
    count = 0
    with open(wordlist_path, encoding="utf-8") as f:
        for line in f:
            word = line.strip()
            if not word:
                continue
            count += 1
            if count % 1_000 == 0:
                print(f"  {count:,} words processed...", end="\r")
            for candidate in apply_rules(word):
                if try_password(zip_path, candidate):
                    elapsed = time.time() - start
                    print()
                    return candidate, elapsed
    return None, time.time() - start


def _hash(text, algorithm):
    """Compute MD5 or SHA-256 hash of text. Returns hex string."""
    if algorithm == "md5":
        return hashlib.md5(text.encode()).hexdigest()
    if algorithm == "sha256":
        return hashlib.sha256(text.encode()).hexdigest()
    raise ValueError(f"Unknown algorithm: {algorithm!r}. Use 'md5' or 'sha256'.")


def build_lookup_table(wordlist_path, algorithm="md5"):
    """
    Pre-compute hashes for every word in the wordlist.
    Returns a dict mapping hash_string → plaintext_password.
    """
    table = {}
    with open(wordlist_path, encoding="utf-8") as f:
        for line in f:
            word = line.strip()
            if word:
                table[_hash(word, algorithm)] = word
    return table


def crack_hash(hash_value, algorithm, wordlist_path):
    """
    Find the plaintext for a given hash.
    Step 1: direct lookup table (fast).
    Step 2: hybrid variants of each word (slower, covers rule-based passwords).
    """
    # Step 1: direct lookup
    table = build_lookup_table(wordlist_path, algorithm)
    if hash_value in table:
        return table[hash_value]

    # Step 2: hybrid lookup
    with open(wordlist_path, encoding="utf-8") as f:
        for line in f:
            word = line.strip()
            if not word:
                continue
            for candidate in apply_rules(word):
                if _hash(candidate, algorithm) == hash_value:
                    return candidate

    return None


# =============================================================================
# PHASE 4 — The Bigger Picture
# =============================================================================

def check_breach_list(password, wordlist_path):
    """
    Check whether a password appears verbatim in the breach wordlist.
    Uses a set for O(1) lookup.
    """
    with open(wordlist_path, encoding="utf-8") as f:
        breach_set = {line.strip() for line in f if line.strip()}
    return password in breach_set


# =============================================================================
# FULL PIPELINE — used by grade_component2.py
# =============================================================================

def run_pipeline(zip_path, wordlist_small, wordlist_full, max_brute_digits=6,
                 max_brute_lower=5, max_brute_full=4):
    """
    Run the complete attack pipeline against zip_path.
    Returns (password, step_name, elapsed_seconds) or (None, None, total_elapsed).

    Pipeline order (matches the published grading spec):
      1. Brute force — digits only, up to max_brute_digits characters
      2. Brute force — lowercase only, up to max_brute_lower characters
      3. Brute force — full charset, up to max_brute_full characters
      4. Dictionary attack — full rockyou.txt
      5. Hybrid attack — rockyou.txt with all transformations
      6. Hash lookup — pre-computed table from rockyou.txt
    """
    start_total = time.time()

    steps = [
        ("brute_digits",   lambda: brute_force_digits(zip_path, max_brute_digits)),
        ("brute_lower",    lambda: brute_force(zip_path, string.ascii_lowercase, max_brute_lower)),
        ("brute_full",     lambda: brute_force(zip_path,
                                               string.ascii_lowercase + string.ascii_uppercase +
                                               string.digits + string.punctuation,
                                               max_brute_full)),
        ("dictionary",     lambda: dictionary_attack(zip_path, wordlist_full)),
        ("hybrid",         lambda: hybrid_attack(zip_path, wordlist_full)),
    ]

    for step_name, attack_fn in steps:
        print(f"\n[{step_name}]")
        password, elapsed = attack_fn()
        if password:
            return password, step_name, time.time() - start_total

    return None, None, time.time() - start_total


# =============================================================================
# MAIN — runs the full pipeline for self-testing and grading use
# =============================================================================

def main():
    print("Reference solution self-test\n")

    # ── Verify apply_rules covers all Phase 3/4 passwords ────────────────────
    targets = [
        ("sunshine",  "Sunshine"),
        ("password",  "password99"),
        ("dragon",    "dr@g0n"),
        ("dragon",    "dragon2024"),
        ("sunshine",  "Sunshine123!"),
        ("dragon",    "Dr@g0n99"),
        ("monkey",    "M0nk3y2024"),
        ("welcome",   "W3lc0m3!"),
    ]
    print("apply_rules coverage:")
    all_ok = True
    for base, target in targets:
        found = target in apply_rules(base)
        mark = "OK  " if found else "FAIL"
        if not found:
            all_ok = False
        print(f"  {mark}  apply_rules({base!r}) ⊇ {target!r}")
    print(f"  {'All OK' if all_ok else 'FAILURES ABOVE'}\n")

    # ── Verify hash cracking with known pairs ─────────────────────────────────
    print("Hash cracking (wordlist_small.txt required):")
    if os.path.exists("wordlist_small.txt"):
        known = [
            ("5f4dcc3b5aa765d61d8327deb882cf99",  "md5",    "password"),
            ("2ac9cb7dc02b3c0083eb70898e549b63",  "md5",    "Password1"),
            ("8621ffdbc5698829397d97767ac13db3",  "md5",    "dragon"),
        ]
        for h, alg, expected in known:
            result = crack_hash(h, alg, "wordlist_small.txt")
            ok = result == expected
            print(f"  {'OK  ' if ok else 'FAIL'}  crack_hash({h[:12]}...) = {result!r}")
    else:
        print("  Skipped — wordlist_small.txt not found. Run prepare_wordlist.py first.")

    # ── Verify try_password ───────────────────────────────────────────────────
    print("\ntry_password:")
    assert try_password("test_data/test.zip", "hello") is True
    assert try_password("test_data/test.zip", "wrong") is False
    print("  OK")


if __name__ == "__main__":
    main()
