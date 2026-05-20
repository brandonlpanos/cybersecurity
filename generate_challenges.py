#!/usr/bin/env python3
"""
generate_challenges.py  —  Instructor tool

Generates all ZIP and hash challenge files for the FHNW Password Cracking module.
Run this script once before distributing materials to students.

No external dependencies required.
Requires the system 'zip' command (available by default on macOS and Linux).

Outputs
-------
zips/phase1/    digit-only brute-force targets          (3 files)
zips/phase2/    expanded brute-force + dictionary       (4 files)
zips/phase3/    hybrid attack targets                   (5 files)
zips/phase4/    final challenges, full pipeline needed  (3 files)
hashes/         MD5 and SHA-256 hash challenge files    (2 files)

manifest.json   KEEP PRIVATE — contains all answers
"""

import hashlib
import json
import os
import subprocess
import tempfile
from datetime import datetime


# =============================================================================
# CONFIGURATION
# All challenge passwords are defined here. Edit this section if you want to
# use different passwords in a future semester.
# =============================================================================

PHASE1_ZIPS = [
    {
        "filename": "level1.zip",
        "password": "2847",
        "content": """\
PHASE 1 — LEVEL 1
==================
You cracked this file using a digit-only brute-force attack.

Character set : digits only  (0-9)
Password length: 4 digits
Search space   : 10^4 = 10,000 combinations

A 4-digit PIN has exactly 10,000 possible values.
How long did your cracker take? Record that time in results/phase1.csv.
It is your baseline for the entire Phase 1 analysis.
""",
    },
    {
        "filename": "level2.zip",
        "password": "31926",
        "content": """\
PHASE 1 — LEVEL 2
==================
A 5-digit number. Your brute forcer worked through all 100,000 of them.

Character set : digits only  (0-9)
Password length: 5 digits
Search space   : 10^5 = 100,000 combinations

Ten times harder than Level 1 — by adding just one digit.
Is the crack time roughly 10x longer? It should be.
This is exponential growth. Plot it.
""",
    },
    {
        "filename": "level3.zip",
        "password": "749512",
        "content": """\
PHASE 1 — LEVEL 3
==================
A 6-digit number. One million possibilities, all tried in order.

Character set : digits only  (0-9)
Password length: 6 digits
Search space   : 10^6 = 1,000,000 combinations

Phone unlock codes are commonly 6 digits.
Bank PINs are 4. Why the difference?
How does crack time scale across Levels 1, 2, and 3?
Plot password length on the x-axis and time on the y-axis.
""",
    },
]

PHASE2_ZIPS = [
    # --- Brute-force targets: random lowercase, not in any wordlist ---
    {
        "filename": "brute_easy.zip",
        "password": "kbwp",
        "content": """\
PHASE 2 — BRUTE FORCE (Easy)
==============================
Four random lowercase letters. Not in any wordlist.

Character set : lowercase only  (a-z)
Password length: 4 characters
Search space   : 26^4 = 456,976 combinations

Your dictionary attack should have failed here.
Only brute force over the full lowercase alphabet works.
Truly random passwords are invisible to dictionary attacks,
no matter how large the wordlist.
""",
    },
    {
        "filename": "brute_medium.zip",
        "password": "xmqvt",
        "content": """\
PHASE 2 — BRUTE FORCE (Medium)
================================
Five random lowercase letters. Not in any wordlist.

Character set : lowercase only  (a-z)
Password length: 5 characters
Search space   : 26^5 = 11,881,376 combinations

One extra character — but 26 times harder than the 4-letter version.
Compare this search space with the 6-digit number from Phase 1.
They are similar in size. Is the crack time similar too? Why or why not?
""",
    },
    # --- Dictionary targets: real words from rockyou.txt ---
    {
        "filename": "dict_easy.zip",
        "password": "sunshine",
        "content": """\
PHASE 2 — DICTIONARY ATTACK (Easy)
=====================================
A common English word. Present in rockyou.txt.

Brute-force search space : 26^8 = 208,827,064,576 combinations
Dictionary search space  : your position in the wordlist

Your brute forcer would need days to reach 8 lowercase characters.
Your dictionary attack found this in seconds.
Human-chosen passwords cluster around a tiny fraction of the possible space.
Wordlists exploit that clustering directly.
""",
    },
    {
        "filename": "dict_medium.zip",
        "password": "dragon",
        "content": """\
PHASE 2 — DICTIONARY ATTACK (Medium)
======================================
Another common word. Also in rockyou.txt.

Look up where 'dragon' appears in rockyou.txt — count the line number.
The fact that it ranks so high tells you something important about
how people choose passwords when they think they are being creative.

How does dictionary crack time compare to brute-force crack time
for a password of the same length?
That comparison is the key finding of your Phase 2 results section.
""",
    },
]

PHASE3_ZIPS = [
    {
        "filename": "hybrid_capitalize.zip",
        "password": "Sunshine",
        "content": """\
PHASE 3 — HYBRID: Capitalise First Letter
==========================================
One transformation applied to a dictionary word.

Base word      : sunshine  (in rockyou.txt)
Transformation : capitalise the first letter
Result         : Sunshine

rockyou.txt is almost entirely lowercase entries.
A plain dictionary attack misses this.
But one rule — capitalise the first letter — extends your attack to cover
every word in the list simultaneously. How many extra candidates does that add?
""",
    },
    {
        "filename": "hybrid_append.zip",
        "password": "password99",
        "content": """\
PHASE 3 — HYBRID: Append Digits
=================================
One transformation: two digits appended.

Base word      : password  (in rockyou.txt)
Transformation : append digits 00 through 99
Result         : password99

When users are required to include a number in their password,
they almost always put it at the end, and it is almost always small.
Your hybrid attack tries all 100 suffixes per base word.
That adds 100x the candidates — a tiny cost compared to extending brute force.
""",
    },
    {
        "filename": "hybrid_leet.zip",
        "password": "dr@g0n",
        "content": """\
PHASE 3 — HYBRID: L33t Substitution
=====================================
All applicable substitutions applied to a dictionary word at once.

Base word       : dragon  (in rockyou.txt)
Transformations : a → @  AND  o → 0  (all applicable substitutions)
Result          : dr@g0n

Your hybrid attack applies every substitution in the leet table simultaneously.
Users believe these substitutions make passwords unguessable.
Attackers added these rules to their tools years ago.
Try applying the full table (a→@ e→3 i→1 o→0 s→$ t→+) to any base word —
the result is always predictable given the original word.
""",
    },
    {
        "filename": "hybrid_suffix.zip",
        "password": "dragon2024",
        "content": """\
PHASE 3 — HYBRID: Year Suffix
================================
One transformation: the current year appended.

Base word      : dragon  (in rockyou.txt)
Transformation : append year  (try 2020 through 2025)
Result         : dragon2024

Appending the current year is the most common pattern when users
are forced to rotate their password annually.
NIST SP 800-63B explicitly recommends against mandatory rotation.
Your crack time here is evidence for why.
""",
    },
    {
        "filename": "hybrid_combo.zip",
        "password": "Sunshine123!",
        "content": """\
PHASE 3 — HYBRID: Full Combination
=====================================
Three rules applied together.

Base word       : sunshine  (in rockyou.txt)
Transformations : capitalise first letter  +  append '123'  +  append '!'
Result          : Sunshine123!

This password satisfies every standard corporate complexity requirement:
  uppercase letter   ✓
  lowercase letters  ✓
  digits             ✓
  symbol             ✓
  12 characters      ✓

It fell to a hybrid attack in milliseconds.
This is the core lesson of Phase 3: complexity rules produce predictable patterns.
They do not produce unpredictable passwords.
""",
    },
]

PHASE4_ZIPS = [
    {
        "filename": "final1.zip",
        "password": "Dr@g0n99",
        "content": """\
PHASE 4 — FINAL CHALLENGE 1
==============================
Capitalise + full leet + two-digit suffix — three rules combined.

Your hybrid attack needed to:
  1. Take a base word from rockyou.txt
  2. Capitalise the first letter
  3. Apply the full leet table (all applicable substitutions at once)
  4. Append a two-digit number

Single-rule implementations will miss this.
Which base word did this come from? Reconstruct the logic in your report.
""",
    },
    {
        "filename": "final2.zip",
        "password": "M0nk3y2024",
        "content": """\
PHASE 4 — FINAL CHALLENGE 2
==============================
Capitalise + full leet + year suffix — three rules combined.

Your hybrid attack needed to:
  1. Take a base word from rockyou.txt
  2. Capitalise the first letter
  3. Apply the full leet table
  4. Append a year from the suffix list

If you are reading this, your apply_rules() correctly generates
combinations of multiple transformations simultaneously.
""",
    },
    {
        "filename": "final3.zip",
        "password": "Sh@d0w!",
        "content": """\
PHASE 4 — FINAL CHALLENGE 3
==============================
Capitalise + full leet (a→@ and o→0) + symbol suffix.

You have now cracked every challenge in the module.

Your results/phase*.csv files contain the raw data for your report.
Every recommendation in your password policy should cite a specific number
from those files — a crack time, a search space comparison, a rule hit rate.
Evidence first. Recommendations second.
""",
    },
]

HASH_CHALLENGES = [
    # Easy: verbatim rockyou.txt entries — dictionary attack finds these
    {"id": "h01", "password": "password",   "difficulty": "easy",   "note": "most common password ever recorded"},
    {"id": "h02", "password": "123456",     "difficulty": "easy",   "note": "most common digit sequence"},
    {"id": "h03", "password": "iloveyou",   "difficulty": "easy",   "note": "common phrase — top 10 in rockyou.txt"},
    {"id": "h04", "password": "sunshine",   "difficulty": "easy",   "note": "common single word"},
    # Medium: hybrid variations — hybrid attack required
    {"id": "h05", "password": "Password1",  "difficulty": "medium", "note": "capitalise + digit — the archetypal 'complex' password"},
    {"id": "h06", "password": "dragon99",   "difficulty": "medium", "note": "word + two digits"},
    {"id": "h07", "password": "m0nk3y",     "difficulty": "medium", "note": "full leet of 'monkey': o→0 and e→3"},
    # Hard: full leet + suffix, less common base words
    {"id": "h08", "password": "stargate7",  "difficulty": "hard",   "note": "less common base word + single digit"},
    {"id": "h09", "password": "Sup3rm@n!",  "difficulty": "hard",   "note": "capitalize + full leet (e→3, a→@) + symbol suffix of 'superman'"},
]


# =============================================================================
# FUNCTIONS
# =============================================================================

def check_zip_available():
    """Exit early with a helpful message if the system zip command is missing."""
    result = subprocess.run(["which", "zip"], capture_output=True)
    if result.returncode != 0:
        raise SystemExit(
            "\nError: the system 'zip' command was not found.\n"
            "On macOS and Linux it is installed by default.\n"
            "On Windows, install Git Bash or WSL and run this script there.\n"
        )


def create_zip(zip_path, password, content):
    """
    Create a password-protected ZIP file containing flag.txt.
    Uses ZipCrypto encryption (compatible with Python's built-in zipfile module).
    """
    # Remove any existing file so zip does not try to update it
    if os.path.exists(zip_path):
        os.remove(zip_path)

    with tempfile.TemporaryDirectory() as tmp:
        flag_path = os.path.join(tmp, "flag.txt")
        with open(flag_path, "w") as f:
            f.write(content)

        result = subprocess.run(
            ["zip", "-j", "-P", password, zip_path, flag_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"zip failed for {zip_path}:\n{result.stderr}")


def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def write_hash_file(path, algorithm, challenges):
    """Write a hash challenge file students will crack in Phase 3."""
    with open(path, "w") as f:
        f.write(f"# Password Hash Challenge — {algorithm.upper()}\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d')}\n")
        f.write("#\n")
        f.write("# Format: id : difficulty : hash\n")
        f.write("#\n")
        f.write("# Task: find the original plaintext password for each hash.\n")
        f.write("# Use your dictionary attack first, then your hybrid attack.\n")
        f.write("# Record each password you crack in results/phase3.csv.\n")
        f.write("#\n\n")
        for c in challenges:
            f.write(f"{c['id']} : {c['difficulty']:<6} : {c['hash']}\n")


def update_gitignore():
    """Add manifest.json to .gitignore if it is not already listed."""
    gitignore_path = ".gitignore"
    entry = "manifest.json"

    existing = ""
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r") as f:
            existing = f.read()

    if entry not in existing:
        with open(gitignore_path, "a") as f:
            # Ensure we start on a new line
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(entry + "\n")


# =============================================================================
# MAIN
# =============================================================================

def main():
    check_zip_available()

    phases = [
        ("zips/phase1", PHASE1_ZIPS),
        ("zips/phase2", PHASE2_ZIPS),
        ("zips/phase3", PHASE3_ZIPS),
        ("zips/phase4", PHASE4_ZIPS),
    ]

    manifest = {
        "generated": datetime.now().isoformat(),
        "note": "KEEP THIS FILE PRIVATE — it contains all challenge answers.",
        "zips": {},
        "hashes": {},
    }

    print("\nGenerating ZIP challenge files...")
    print("-" * 55)

    total_zips = 0
    for folder, specs in phases:
        os.makedirs(folder, exist_ok=True)
        for spec in specs:
            path = os.path.join(folder, spec["filename"])
            create_zip(path, spec["password"], spec["content"])
            manifest["zips"][spec["filename"]] = spec["password"]
            print(f"  {path:<42}  pw: {spec['password']}")
            total_zips += 1

    print(f"\nGenerating hash challenge files...")
    print("-" * 55)

    os.makedirs("hashes", exist_ok=True)

    md5_list    = [{**c, "hash": md5_hash(c["password"])}    for c in HASH_CHALLENGES]
    sha256_list = [{**c, "hash": sha256_hash(c["password"])} for c in HASH_CHALLENGES]

    for c in HASH_CHALLENGES:
        manifest["hashes"][c["id"]] = {
            "password":   c["password"],
            "difficulty": c["difficulty"],
            "md5":        md5_hash(c["password"]),
            "sha256":     sha256_hash(c["password"]),
        }

    write_hash_file("hashes/md5_hashes.txt",    "md5",    md5_list)
    write_hash_file("hashes/sha256_hashes.txt", "sha256", sha256_list)
    print(f"  hashes/md5_hashes.txt")
    print(f"  hashes/sha256_hashes.txt")

    # Write answer key and protect it
    with open("manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    update_gitignore()

    print()
    print("=" * 55)
    print(f"  {total_zips} ZIP files created across 4 phases")
    print(f"  {len(HASH_CHALLENGES)} hash challenges created (MD5 + SHA-256)")
    print(f"  manifest.json written and added to .gitignore")
    print()
    print("  DO NOT share manifest.json with students.")
    print("=" * 55)
    print()


if __name__ == "__main__":
    main()
