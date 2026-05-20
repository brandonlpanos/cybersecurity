#!/usr/bin/env python3
"""
grade_component2.py  —  Instructor tool

Automated grading pipeline for Component 2: Defend Your Password.

Each student submits one password before the examination deadline. This script
creates a ZIP locked with that password and runs the standard attack pipeline
against it. The grade is determined by how long the pipeline takes to crack it.

Usage
-----
Single student:
    python grade_component2.py --student alice_meier --password "MyPassword"

Batch mode (reads from a CSV file):
    python grade_component2.py --batch submissions.csv

Options:
    --wordlist PATH      path to rockyou.txt  (default: rockyou.txt)
    --output DIR         output directory      (default: grades/)
    --timeout HOURS      stop after N hours    (default: 8)
    --resume             skip already-graded students in batch mode

submissions.csv format:
    student_id,password
    alice_meier,MyPassword123
    bob_mueller,dragon

Grade brackets:
    Disqualified (in wordlist / rule violation) → 1
    Cracked in under 5 minutes                 → 2
    Cracked in 5–30 minutes                    → 3
    Cracked in 30 minutes – 2 hours            → 4
    Cracked in 2–8 hours                       → 5
    Not cracked within 8 hours                 → 6
"""

import argparse
import csv
import itertools
import json
import os
import string
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime


# =============================================================================
# CONFIGURATION
# =============================================================================

MAX_PASSWORD_LENGTH = 16
DEFAULT_TIMEOUT_HOURS = 8
DEFAULT_WORDLIST = "rockyou.txt"
DEFAULT_OUTPUT_DIR = "grades"

# Attack pipeline limits
BRUTE_DIGITS_MAX_LEN  = 6   # digits only, up to 6 characters
BRUTE_LOWER_MAX_LEN   = 5   # lowercase only, up to 5 characters
BRUTE_FULL_MAX_LEN    = 4   # full charset, up to 4 characters

# Leet substitution table and suffixes (must match cracker.py exactly)
LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "+"}
SUFFIXES = ["!", "123", "1234", "123!", "2024", "2023", "2022", "2021", "2020", "#1"]

# Grade brackets: (seconds_threshold, grade, label)
GRADE_BRACKETS = [
    (5 * 60,       2, "cracked in under 5 minutes"),
    (30 * 60,      3, "cracked in 5–30 minutes"),
    (2 * 3600,     4, "cracked in 30 minutes – 2 hours"),
    (8 * 3600,     5, "cracked in 2–8 hours"),
    (float("inf"), 6, "not cracked within 8 hours"),
]


# =============================================================================
# CORE HELPERS
# =============================================================================

def _try(zip_path, password):
    """
    Try a single password against a ZIP file.
    Uses zf.read() (in-memory) instead of extractall() — no disk I/O per attempt.
    """
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.read(zf.namelist()[0], pwd=password.encode())
        return True
    except Exception:
        return False


def _leet(word):
    """Apply all leet substitutions from LEET_MAP simultaneously."""
    for char, sub in LEET_MAP.items():
        word = word.replace(char, sub)
    return word


def _variants(word):
    """Generate all hybrid rule variants of a word. Matches cracker.py apply_rules()."""
    vs = set()
    for base in [word, word.capitalize()]:
        leet_base = _leet(base)
        for b in [base, leet_base]:
            vs.add(b)
            for suffix in SUFFIXES:
                vs.add(b + suffix)
            for i in range(100):
                vs.add(b + str(i))
    return vs


def _fmt_time(seconds):
    """Format seconds as a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    return f"{h}h {m}m"


def _assign_grade(total_seconds, cracked):
    """Return (grade, label) based on total elapsed time."""
    if not cracked:
        return 6, "not cracked within timeout"
    for threshold, grade, label in GRADE_BRACKETS:
        if total_seconds <= threshold:
            return grade, label
    return 6, "not cracked within 8 hours"


# =============================================================================
# ZIP CREATION
# =============================================================================

def _create_grading_zip(student_id, password, zips_dir):
    """
    Create a password-protected ZIP for a student's submitted password.
    Returns the path to the created ZIP file.

    Note: the password appears briefly in the command-line arguments to 'zip',
    which may be visible in process listings during creation. This is acceptable
    for an instructor tool running on a secure machine.
    """
    os.makedirs(zips_dir, exist_ok=True)
    zip_path = os.path.join(zips_dir, f"{student_id}_defend.zip")

    if os.path.exists(zip_path):
        os.remove(zip_path)

    content = (
        f"Component 2: Defend Your Password\n"
        f"Student:  {student_id}\n"
        f"Created:  {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"This file was generated for automated grading. Do not distribute.\n"
    )

    with tempfile.TemporaryDirectory() as tmp:
        flag_path = os.path.join(tmp, "defend.txt")
        with open(flag_path, "w") as f:
            f.write(content)
        result = subprocess.run(
            ["zip", "-j", "-P", password, zip_path, flag_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"zip failed: {result.stderr}")

    return zip_path


# =============================================================================
# DISQUALIFICATION CHECK
# =============================================================================

def _load_breach_set(wordlist_path):
    """
    Load the wordlist into a set for O(1) membership checks.
    Returns an empty set if the file is not found.
    Uses ~1 GB RAM for rockyou.txt — acceptable on an instructor machine.
    """
    if not os.path.exists(wordlist_path):
        return set()
    print(f"  Loading breach list from {wordlist_path}...")
    with open(wordlist_path, encoding="utf-8", errors="replace") as f:
        s = {line.strip() for line in f if line.strip()}
    print(f"  {len(s):,} entries loaded.")
    return s


def _looks_like_passphrase(password, breach_set, min_words=3):
    """
    Return True if the all-lowercase password can be segmented into
    min_words or more dictionary words.
    Uses dynamic programming — fast for practical password lengths.
    """
    words = {w for w in breach_set if len(w) >= 3}
    pw = password.lower()
    n = len(pw)
    max_word_len = 20

    # dp[i] = minimum word count to cover pw[:i], inf if impossible
    INF = float("inf")
    dp = [INF] * (n + 1)
    dp[0] = 0

    for i in range(1, n + 1):
        for j in range(max(0, i - max_word_len), i):
            if dp[j] < INF and pw[j:i] in words:
                dp[i] = min(dp[i], dp[j] + 1)

    return dp[n] >= min_words


def disqualification_check(password, breach_set):
    """
    Check whether a submitted password should be disqualified.
    Returns (disqualified: bool, reason: str or None).

    Rules:
      - Must be between 1 and 16 characters
      - Must not appear verbatim in rockyou.txt
      - Must not be a concatenation of 3 or more unmodified dictionary words
    """
    if not password:
        return True, "empty password"

    if len(password) > MAX_PASSWORD_LENGTH:
        return True, f"length {len(password)} exceeds maximum of {MAX_PASSWORD_LENGTH}"

    if breach_set and password in breach_set:
        return True, "password appears verbatim in rockyou.txt"

    # Passphrase check: only applies to all-lowercase alphabetic strings
    if password.isalpha() and password.islower() and len(password) >= 9:
        if breach_set and _looks_like_passphrase(password, breach_set):
            return True, "password is a concatenation of 3 or more unmodified dictionary words"

    return False, None


# =============================================================================
# PIPELINE STEP FUNCTIONS
# Each returns (password_or_None, elapsed_seconds, status, attempts)
# status is one of: "cracked" | "exhausted" | "timeout"
# =============================================================================

def _step_brute(zip_path, charset, max_length, deadline, label):
    start = time.time()
    attempts = 0
    for length in range(1, max_length + 1):
        if time.time() > deadline:
            return None, time.time() - start, "timeout", attempts
        print(f"    {label}: length {length}/{max_length} ...", end="\r")
        for combo in itertools.product(charset, repeat=length):
            if time.time() > deadline:
                return None, time.time() - start, "timeout", attempts
            attempts += 1
            pw = "".join(combo)
            if _try(zip_path, pw):
                print()
                return pw, time.time() - start, "cracked", attempts
    print()
    return None, time.time() - start, "exhausted", attempts


def _step_dictionary(zip_path, wordlist_path, deadline):
    start = time.time()
    attempts = 0
    with open(wordlist_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if time.time() > deadline:
                return None, time.time() - start, "timeout", attempts
            pw = line.strip()
            if not pw:
                continue
            attempts += 1
            if attempts % 50_000 == 0:
                print(f"    dictionary: {attempts:,} words ...", end="\r")
            if _try(zip_path, pw):
                print()
                return pw, time.time() - start, "cracked", attempts
    print()
    return None, time.time() - start, "exhausted", attempts


def _step_hybrid(zip_path, wordlist_path, deadline):
    start = time.time()
    words_processed = 0
    with open(wordlist_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if time.time() > deadline:
                return None, time.time() - start, "timeout", words_processed
            word = line.strip()
            if not word:
                continue
            words_processed += 1
            if words_processed % 5_000 == 0:
                print(f"    hybrid: {words_processed:,} words ...", end="\r")
            for candidate in _variants(word):
                if _try(zip_path, candidate):
                    print()
                    return candidate, time.time() - start, "cracked", words_processed
    print()
    return None, time.time() - start, "exhausted", words_processed


# =============================================================================
# SINGLE STUDENT GRADING
# =============================================================================

def grade_one_student(student_id, password, wordlist_path, breach_set,
                      output_dir, timeout_hours):
    """
    Run the full grading pipeline for one student.
    Returns the result dict and writes it to grades/<student_id>.json.
    """
    print(f"\n{'='*60}")
    print(f"  Student : {student_id}")
    print(f"  Password: {'*' * len(password)} ({len(password)} chars)")
    print(f"{'='*60}")

    result = {
        "student_id": student_id,
        "password_length": len(password),
        "disqualified": False,
        "disqualification_reason": None,
        "cracked": False,
        "cracked_by_step": None,
        "total_time_seconds": None,
        "total_time_human": None,
        "grade": None,
        "grade_label": None,
        "pipeline_steps": [],
        "graded_at": datetime.now().isoformat(),
    }

    # ── Step 0: Disqualification check ───────────────────────────────────────
    print("\n  [0] Disqualification check...")
    t0 = time.time()
    disq, reason = disqualification_check(password, breach_set)
    result["pipeline_steps"].append({
        "step": "disqualification_check",
        "result": "disqualified" if disq else "pass",
        "reason": reason,
        "time_seconds": round(time.time() - t0, 3),
        "attempts": None,
    })

    if disq:
        print(f"  DISQUALIFIED: {reason}")
        result["disqualified"] = True
        result["disqualification_reason"] = reason
        result["grade"] = 1
        result["grade_label"] = f"disqualified: {reason}"
        result["total_time_seconds"] = 0
        result["total_time_human"] = "0s"
        _write_result(result, output_dir)
        return result

    # ── Create grading ZIP ────────────────────────────────────────────────────
    zips_dir = os.path.join(output_dir, "zips")
    try:
        zip_path = _create_grading_zip(student_id, password, zips_dir)
        print(f"  ZIP created: {zip_path}")
    except Exception as e:
        print(f"  ERROR creating ZIP: {e}")
        result["grade"] = 1
        result["grade_label"] = f"grading error: {e}"
        _write_result(result, output_dir)
        return result

    # ── Run pipeline ──────────────────────────────────────────────────────────
    deadline = time.time() + timeout_hours * 3600
    pipeline_start = time.time()

    full_charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation

    steps = [
        ("brute_digits",
         lambda d: _step_brute(zip_path, "0123456789",     BRUTE_DIGITS_MAX_LEN, d, "brute_digits")),
        ("brute_lower",
         lambda d: _step_brute(zip_path, string.ascii_lowercase, BRUTE_LOWER_MAX_LEN, d, "brute_lower")),
        ("brute_full",
         lambda d: _step_brute(zip_path, full_charset,     BRUTE_FULL_MAX_LEN,  d, "brute_full")),
        ("dictionary",
         lambda d: _step_dictionary(zip_path, wordlist_path, d)),
        ("hybrid",
         lambda d: _step_hybrid(zip_path, wordlist_path, d)),
    ]

    for step_name, step_fn in steps:
        if time.time() >= deadline:
            print(f"\n  [{step_name}] skipped — timeout reached")
            result["pipeline_steps"].append({
                "step": step_name, "result": "skipped", "reason": "timeout",
                "time_seconds": 0, "attempts": None,
            })
            continue

        print(f"\n  [{step_name}]")
        pw_found, step_time, status, attempts = step_fn(deadline)

        result["pipeline_steps"].append({
            "step": step_name,
            "result": status,
            "time_seconds": round(step_time, 3),
            "attempts": attempts,
        })

        print(f"    result: {status}  |  time: {_fmt_time(step_time)}  |  attempts: {attempts:,}")

        if status == "cracked":
            result["cracked"] = True
            result["cracked_by_step"] = step_name
            break

    # ── Assign grade ──────────────────────────────────────────────────────────
    total_time = time.time() - pipeline_start
    result["total_time_seconds"] = round(total_time, 1)
    result["total_time_human"] = _fmt_time(total_time)
    result["grade"], result["grade_label"] = _assign_grade(total_time, result["cracked"])

    print(f"\n  {'─'*40}")
    print(f"  Total time : {result['total_time_human']}")
    print(f"  Cracked    : {result['cracked']}"
          + (f" (by {result['cracked_by_step']})" if result["cracked"] else ""))
    print(f"  Grade      : {result['grade']}  ({result['grade_label']})")
    print(f"  {'─'*40}")

    _write_result(result, output_dir)
    return result


# =============================================================================
# OUTPUT
# =============================================================================

def _write_result(result, output_dir):
    """Write a student's result to grades/<student_id>.json."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{result['student_id']}.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2)


def _write_summary(results, output_dir):
    """Append all results to grades/summary.csv."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "summary.csv")
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow([
                "student_id", "password_length", "disqualified",
                "disqualification_reason", "cracked", "cracked_by_step",
                "total_time_seconds", "total_time_human", "grade", "grade_label",
                "graded_at",
            ])
        for r in results:
            writer.writerow([
                r["student_id"],
                r["password_length"],
                r["disqualified"],
                r.get("disqualification_reason") or "",
                r["cracked"],
                r.get("cracked_by_step") or "",
                r.get("total_time_seconds") or "",
                r.get("total_time_human") or "",
                r["grade"],
                r["grade_label"],
                r["graded_at"],
            ])


# =============================================================================
# ENTRY POINTS
# =============================================================================

def run_single(args):
    breach_set = _load_breach_set(args.wordlist)
    result = grade_one_student(
        student_id=args.student,
        password=args.password,
        wordlist_path=args.wordlist,
        breach_set=breach_set,
        output_dir=args.output,
        timeout_hours=args.timeout,
    )
    _write_summary([result], args.output)


def run_batch(args):
    if not os.path.exists(args.batch):
        print(f"Error: submissions file not found: {args.batch}")
        sys.exit(1)

    with open(args.batch, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        submissions = [(row["student_id"].strip(), row["password"].strip())
                       for row in reader]

    if not submissions:
        print("No submissions found in CSV.")
        sys.exit(1)

    print(f"Loaded {len(submissions)} submission(s) from {args.batch}")

    # Load breach set once for all students
    breach_set = _load_breach_set(args.wordlist)

    results = []
    for i, (student_id, password) in enumerate(submissions, 1):
        # Skip already-graded students if --resume is set
        result_path = os.path.join(args.output, f"{student_id}.json")
        if args.resume and os.path.exists(result_path):
            print(f"\n[{i}/{len(submissions)}] {student_id} — already graded, skipping.")
            with open(result_path) as f:
                results.append(json.load(f))
            continue

        print(f"\n[{i}/{len(submissions)}]")
        result = grade_one_student(
            student_id=student_id,
            password=password,
            wordlist_path=args.wordlist,
            breach_set=breach_set,
            output_dir=args.output,
            timeout_hours=args.timeout,
        )
        results.append(result)

    _write_summary(results, args.output)

    # Print final summary table
    print(f"\n{'='*60}")
    print(f"  GRADING COMPLETE — {len(results)} student(s)")
    print(f"{'='*60}")
    print(f"  {'Student':<25} {'Grade':>5}  {'Time':>12}  {'Cracked by'}")
    print(f"  {'-'*55}")
    for r in results:
        cracked_by = r.get("cracked_by_step") or ("disqualified" if r["disqualified"] else "—")
        time_str = r.get("total_time_human") or "—"
        print(f"  {r['student_id']:<25} {r['grade']:>5}  {time_str:>12}  {cracked_by}")
    print(f"\n  Full results: {args.output}/")
    print(f"  Summary CSV : {args.output}/summary.csv")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Grade Component 2: Defend Your Password",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--student", metavar="ID",
                      help="student identifier (use with --password)")
    mode.add_argument("--batch",   metavar="CSV",
                      help="path to submissions CSV (student_id, password)")

    parser.add_argument("--password",  metavar="PW",
                        help="submitted password (required with --student)")
    parser.add_argument("--wordlist",  metavar="PATH",
                        default=DEFAULT_WORDLIST,
                        help=f"path to rockyou.txt (default: {DEFAULT_WORDLIST})")
    parser.add_argument("--output",    metavar="DIR",
                        default=DEFAULT_OUTPUT_DIR,
                        help=f"output directory (default: {DEFAULT_OUTPUT_DIR}/)")
    parser.add_argument("--timeout",   metavar="HOURS",
                        type=float, default=DEFAULT_TIMEOUT_HOURS,
                        help=f"pipeline timeout in hours (default: {DEFAULT_TIMEOUT_HOURS})")
    parser.add_argument("--resume",    action="store_true",
                        help="skip already-graded students (batch mode only)")

    args = parser.parse_args()

    if args.student and not args.password:
        parser.error("--student requires --password")

    if args.wordlist != DEFAULT_WORDLIST and not os.path.exists(args.wordlist):
        parser.error(f"wordlist not found: {args.wordlist}")

    if not os.path.exists(args.wordlist):
        print(f"Warning: {args.wordlist} not found.")
        fallback = "wordlist_small.txt"
        if os.path.exists(fallback):
            print(f"  Falling back to {fallback} for disqualification check.")
            print(f"  For full grading accuracy, provide rockyou.txt with --wordlist.")
            args.wordlist = fallback
        else:
            print(f"  Disqualification check will be skipped (no wordlist available).")

    if args.student:
        run_single(args)
    else:
        run_batch(args)


if __name__ == "__main__":
    main()
