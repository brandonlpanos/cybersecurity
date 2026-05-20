#!/usr/bin/env python3
"""
cracker.py  —  FHNW Password Cracking Challenge

Your main project file. Work through the phases in order, filling in each
function stub as you reach it. Do not modify the PROVIDED sections.

Phase 1  (Weeks 1-3)  : brute_force_digits
Phase 2  (Weeks 4-6)  : brute_force, dictionary_attack
Phase 3  (Weeks 7-9)  : apply_rules, hybrid_attack, build_lookup_table, crack_hash
Phase 4  (Weeks 10-12): check_breach_list
"""

import csv
import hashlib
import itertools
import os
import string
import time
import zipfile


# =============================================================================
# PROVIDED — do not modify these functions
# =============================================================================

def try_password(zip_path, password):
    """
    Try a single password against an encrypted ZIP file.
    Returns True if the password is correct, False otherwise.
    """
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(path="/tmp/cracker_out", pwd=password.encode())
        return True
    except Exception:
        return False


def save_result(phase, filename, password, time_seconds):
    """
    Save a cracked password to results/phaseN.csv.
    Creates the results/ directory and the CSV file if they do not exist.
    """
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
    """
    Read a hash challenge file and return a list of (id, difficulty, hash) tuples.
    Skips comment lines (starting with #) and blank lines.
    """
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
    """
    Try every digit-only combination from length 1 up to max_length.

    Use itertools.product("0123456789", repeat=length) to generate all
    combinations of a given length. For each combination, join it into a
    string with "".join(combo) and call try_password().

    Stop as soon as a correct password is found and return it.
    Record the start time before the loop so you can measure elapsed time.

    Parameters
    ----------
    zip_path   : str  path to the ZIP file
    max_length : int  maximum password length to try (default 6)

    Returns
    -------
    tuple: (password, time_seconds)
        password     — the cracked password (str), or None if not found
        time_seconds — how long the search took (float)

    Tip: print something at the start of each length loop so it does not
    look frozen, e.g.:  print(f"  Trying length {length}...", end="\\r")
    """
    pass


# =============================================================================
# PHASE 2 — Extended Brute Force + Dictionary Attack
# =============================================================================

def brute_force(zip_path, charset, max_length):
    """
    Generalised brute force — works with any character set.

    Same structure as brute_force_digits(), but the character set is passed
    in as a parameter instead of being hardcoded.

    Use string.ascii_lowercase, string.ascii_uppercase, string.digits, and
    string.punctuation to build character sets. You can combine them with +:
        charset = string.ascii_lowercase + string.digits

    Parameters
    ----------
    zip_path   : str  path to the ZIP file
    charset    : str  characters to use, e.g. "abcdefghijklmnopqrstuvwxyz"
    max_length : int  maximum password length to try

    Returns
    -------
    tuple: (password, time_seconds)
    """
    pass


def dictionary_attack(zip_path, wordlist_path):
    """
    Try every word in the wordlist file as a password.

    Read the file LINE BY LINE — do not load the whole file into memory at
    once. Wordlist files can be very large (rockyou.txt is 133 MB).

    Open the file with open(wordlist_path, encoding="utf-8") and iterate
    over it directly. Strip each line with line.strip() before using it.
    Skip empty lines.

    Parameters
    ----------
    zip_path     : str  path to the ZIP file
    wordlist_path: str  path to a wordlist file (one password per line)

    Returns
    -------
    tuple: (password, time_seconds)
    """
    pass


# =============================================================================
# PHASE 3 — Hybrid Attacks + Hash Cracking
# =============================================================================

LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "+"}

SUFFIXES = ["!", "123", "1234", "123!", "2024", "2023", "2022", "2021", "2020", "#1"]


def apply_rules(word):
    """
    Apply all hybrid attack transformations to a single word.
    Return a list of candidate passwords derived from that word.

    Rules to implement — for EACH of (word, word.capitalize()):
      1. The base form as-is
      2. The base form with ALL leet substitutions applied at once
         Use LEET_MAP (defined above) and replace each character in sequence.
      3. Each of the above + every suffix from SUFFIXES
      4. Each of the above + every digit from 0 to 99

    Use a set() internally to avoid duplicates, then return list(variants).

    Parameters
    ----------
    word : str  a single dictionary word

    Returns
    -------
    list of str  all candidate passwords derived from word
    """
    pass


def hybrid_attack(zip_path, wordlist_path):
    """
    For each word in the wordlist, generate all rule-based variants using
    apply_rules() and try each one against the ZIP file.

    Read the wordlist line by line (same as dictionary_attack).
    For each word, call apply_rules(word) and try every candidate.

    Parameters
    ----------
    zip_path     : str  path to the ZIP file
    wordlist_path: str  path to a wordlist file

    Returns
    -------
    tuple: (password, time_seconds)
    """
    pass


def build_lookup_table(wordlist_path, algorithm="md5"):
    """
    Pre-compute hashes for every word in the wordlist.
    Store them as a dictionary: {hash_string: plaintext_password}.

    This is the core idea behind pre-computed hash tables. Once built,
    any hash in the table can be found in O(1) time — instantly.

    Use hashlib.md5(word.encode()).hexdigest() for MD5.
    Use hashlib.sha256(word.encode()).hexdigest() for SHA-256.

    Parameters
    ----------
    wordlist_path : str  path to wordlist
    algorithm     : str  "md5" or "sha256"

    Returns
    -------
    dict  {hash_string: password}
    """
    pass


def crack_hash(hash_value, algorithm, wordlist_path):
    """
    Find the plaintext password for a given hash.

    Strategy (in order):
      1. Build a lookup table from the wordlist — if the hash is in it, done.
      2. If not found, try all hybrid variants of each word using apply_rules().
         Hash each variant and compare to hash_value.

    Parameters
    ----------
    hash_value   : str  the hash to crack (hex string)
    algorithm    : str  "md5" or "sha256"
    wordlist_path: str  path to wordlist

    Returns
    -------
    str   the cracked plaintext password
    None  if not found
    """
    pass


# =============================================================================
# PHASE 4 — The Bigger Picture
# =============================================================================

def check_breach_list(password, wordlist_path):
    """
    Check whether a password appears verbatim in a breach wordlist.

    Load the entire wordlist into a Python set, then use the 'in' operator.

    Why a set and not a list?
    Checking membership in a list takes O(n) time — it scans every entry.
    Checking membership in a set takes O(1) time — instant, regardless of size.
    For a 10,000-word file this does not matter, but for rockyou.txt it does.

    Parameters
    ----------
    password     : str  the password to check
    wordlist_path: str  path to wordlist

    Returns
    -------
    True  if the password was found in the breach list
    False if it was not found
    """
    pass


# =============================================================================
# MAIN — edit this section to run experiments and record results
# =============================================================================

def main():

    # ── Self-test: run this first to confirm your environment works ───────────
    print("Self-test...")
    assert try_password("test_data/test.zip", "hello") is True,  \
        "FAIL: try_password returned False for the correct password 'hello'"
    assert try_password("test_data/test.zip", "wrong") is False, \
        "FAIL: try_password returned True for an incorrect password"
    print("  try_password: OK")
    print("  Environment ready.\n")

    # ── Phase 1 ───────────────────────────────────────────────────────────────
    # Uncomment these once you have implemented brute_force_digits().
    # Crack each file and save the result.

    # for filename in ["level1.zip", "level2.zip", "level3.zip"]:
    #     print(f"Cracking zips/phase1/{filename}...")
    #     password, elapsed = brute_force_digits(f"zips/phase1/{filename}")
    #     if password:
    #         save_result(1, filename, password, elapsed)
    #     else:
    #         print(f"  Not found in {elapsed:.1f}s")

    # ── Phase 2: Brute force ──────────────────────────────────────────────────
    # Uncomment once you have implemented brute_force().

    # password, elapsed = brute_force("zips/phase2/brute_easy.zip",
    #                                  charset=string.ascii_lowercase,
    #                                  max_length=5)
    # if password:
    #     save_result(2, "brute_easy.zip", password, elapsed)

    # password, elapsed = brute_force("zips/phase2/brute_medium.zip",
    #                                  charset=string.ascii_lowercase,
    #                                  max_length=5)
    # if password:
    #     save_result(2, "brute_medium.zip", password, elapsed)

    # ── Phase 2: Dictionary attack ────────────────────────────────────────────
    # Uncomment once you have implemented dictionary_attack().

    # for filename in ["dict_easy.zip", "dict_medium.zip"]:
    #     print(f"Cracking zips/phase2/{filename}...")
    #     password, elapsed = dictionary_attack(f"zips/phase2/{filename}",
    #                                            "wordlist_small.txt")
    #     if password:
    #         save_result(2, filename, password, elapsed)

    # ── Phase 3: Hybrid attack ────────────────────────────────────────────────
    # Uncomment once you have implemented hybrid_attack().

    # for filename in ["hybrid_capitalize.zip", "hybrid_append.zip",
    #                   "hybrid_leet.zip", "hybrid_suffix.zip", "hybrid_combo.zip"]:
    #     print(f"Cracking zips/phase3/{filename}...")
    #     password, elapsed = hybrid_attack(f"zips/phase3/{filename}",
    #                                        "wordlist_small.txt")
    #     if password:
    #         save_result(3, filename, password, elapsed)
    #     else:
    #         print(f"  Not found — try rockyou.txt instead of wordlist_small.txt")

    # ── Phase 3: Hash cracking ────────────────────────────────────────────────
    # Uncomment once you have implemented crack_hash().

    # print("Cracking MD5 hashes...")
    # for hash_id, difficulty, hash_value in load_hashes("hashes/md5_hashes.txt"):
    #     result = crack_hash(hash_value, "md5", "wordlist_small.txt")
    #     if result:
    #         print(f"  {hash_id} ({difficulty}): {result}")
    #         save_result(3, hash_id, result, 0)
    #     else:
    #         print(f"  {hash_id} ({difficulty}): not found — try rockyou.txt")

    # ── Phase 4: Final challenge ZIPs ─────────────────────────────────────────
    # Uncomment once your full pipeline is working.

    # for filename in ["final1.zip", "final2.zip", "final3.zip"]:
    #     print(f"Cracking zips/phase4/{filename}...")
    #     password, elapsed = hybrid_attack(f"zips/phase4/{filename}",
    #                                        "rockyou.txt")
    #     if password:
    #         save_result(4, filename, password, elapsed)

    # ── Phase 4: Breach list check ────────────────────────────────────────────
    # Uncomment once you have implemented check_breach_list().

    # test_passwords = ["sunshine", "xmqvt", "P@ssw0rd", "correct horse battery"]
    # for pw in test_passwords:
    #     found = check_breach_list(pw, "wordlist_small.txt")
    #     print(f"  '{pw}' in breach list: {found}")


if __name__ == "__main__":
    main()
