
*Alan Turing alongside the Enigma rotor assembly. Turing's work at Bletchley Park during World War II — deciphering messages encrypted by the German Enigma machine — is widely considered the founding act of modern cryptanalysis, and the direct ancestor of every attack you will implement in this challenge.*

---

# Password Cracking Challenge
### FHNW — Cybersecurity Module

---

## Why This Challenge?

Every year, hundreds of millions of passwords are exposed in data breaches. Analyses of these leaks consistently reveal the same uncomfortable truth: the vast majority of real-world passwords can be cracked within seconds using tools that any programmer can build in an afternoon.

But *knowing* a password is weak is easy to say. *Understanding why* requires becoming the attacker.

In this challenge you will write Python programs to crack encrypted files, run controlled experiments across multiple attack strategies, and translate your measured results into a real, evidence-based password policy. You will also confront the legal and ethical boundaries that every security professional must understand — because the same skills that let you protect systems can, in the wrong hands, be used to harm them.

---

## Learning Objectives

By the end of this challenge, you will be able to:

- Implement brute-force, dictionary, hybrid, and hash-lookup attacks in Python
- Explain how password length, character set, and structure affect crack time, backed by your own experimental data
- Describe how hashing algorithms (MD5, SHA-256, bcrypt) and salting differ in their security properties
- Explain why credential stuffing and social engineering can bypass even strong technical defenses
- Design a password policy grounded in your experimental results and current best practice (NIST SP 800-63B)
- Reflect on the ethical and legal boundaries of offensive security work

---

## Topics

**Attack techniques**
- Brute-force attacks and the combinatorics of password spaces
- Dictionary attacks using real-world wordlists (rockyou.txt)
- Rule-based and hybrid attacks: applying human patterns to dictionary words
- Hash-lookup attacks: pre-computed tables, their power, and their limits

**Cryptographic foundations**
- Password hashing: MD5, SHA-256, bcrypt
- Why MD5 and SHA-256 are dangerously fast for password storage
- Salting: why it defeats pre-computed lookup tables
- Why bcrypt is intentionally slow — and why that is exactly the point

**The broader threat landscape**
- Credential stuffing and the danger of password reuse
- Social engineering: the attacker's path of least resistance
- Defensive countermeasures: rate limiting, account lockout, multi-factor authentication (MFA)
- Password managers and why they change the game
- Modern password guidance: what NIST SP 800-63B actually recommends (and why it contradicts most "password rules" you have seen)

**Scientific and programming skills**
- Experimental design: controlling variables, measuring time fairly
- Recording data systematically in CSV files
- Visualizing results with matplotlib
- Writing a scientific report

**Python skills (built up progressively across the semester)**
- Strings, loops, and conditionals
- Functions and modular program structure
- File input/output: reading wordlists and writing results
- `itertools.product` for generating character combinations
- `hashlib` for computing MD5, SHA-256, and bcrypt hashes
- `zipfile` for working with encrypted ZIP archives
- `time` for measuring how long operations take
- `csv` for recording experimental data
- `matplotlib` for charts and graphs
- Dictionaries for fast hash lookups

---

## Materials Provided

You will receive the following at the start of the semester. Do not wait until they are needed — familiarise yourself with the structure early.

| File / Folder | Description |
|---|---|
| `cracker.py` | Skeleton file with function stubs — your main project file |
| `test_cases.txt` | Known password → hash pairs to verify your implementations are correct |
| `wordlist_small.txt` | 10,000 most common passwords — use this in early phases while you develop |
| `rockyou.txt` | The full rockyou dataset: 1.4 million real passwords from a data breach |
| `zips/phase1/` | ZIP files locked with digit-only passwords (4–6 digits) |
| `zips/phase2/` | ZIP files locked with lowercase passwords (4–6 characters) |
| `zips/phase3/` | ZIP files locked with dictionary words and common variations |
| `zips/phase4/` | ZIP files locked with stronger passwords — your final cracking challenge |
| `hashes/` | A set of MD5 and SHA-256 hashes to crack |
| `report_template.md` | Structure and prompts for your scientific report |

**A note on rockyou.txt:** This file is derived from a real credential breach. You receive it for the same reason security professionals use it: understanding how attackers think requires working with what attackers actually use. Using it outside this module is your legal and ethical responsibility.

---

## Phase Breakdown

---

### Phase 1 — Weeks 1–3: Foundations

**Goal:** Understand what brute force means mathematically, and build your first working cracker.

**Key concepts:**
- What is a *character set*? (digits `0–9`, lowercase `a–z`, uppercase `A–Z`, symbols)
- How many possible passwords exist for a given length and character set? The answer is: `(size of character set) ^ (password length)`. For a 4-digit PIN: 10⁴ = 10,000 possibilities. For a 6-digit PIN: 10⁶ = 1,000,000. Each extra character *multiplies* the search space.
- What does it mean to "crack" a ZIP file? You try every possible password until the file opens.
- Why is Python slower than dedicated tools like Hashcat? Python is an interpreted language with no GPU support. Your cracker will run at roughly 500–2,000 attempts per second — far slower than professional tools. This is a feature, not a bug: it makes the performance difference between attack strategies very visible in your data, and sets up the lesson about bcrypt in Phase 3.

**What you will build:**
- A function `brute_force_digits(zip_path, max_length)` that tries every digit combination from `0` up to `max_length` digits
- A `try_password(zip_path, password)` helper that returns `True` if a password opens the ZIP
- A results logger: each crack attempt saves the password found and time taken to `results/phase1.csv`

**Python skills introduced:** strings, `for` loops, `itertools.product`, `zipfile`, `time.time()`, writing CSV files, defining and calling functions

**Checkpoint:** Crack all ZIP files in `zips/phase1/`. Record your results in `results/phase1.csv` (columns: filename, password, time_seconds).

---

### Phase 2 — Weeks 4–6: Expanding the Arsenal

**Goal:** Extend brute force to other character sets, implement a dictionary attack, and run your first real experiments comparing strategies.

**Key concepts:**
- Adding one character to your alphabet multiplies the search space by the new alphabet size. Adding `a–z` to a 6-character password turns 1 million possibilities into 26⁶ ≈ 300 million. Your Python cracker will take hours — which is the point.
- A *dictionary attack* does not try every combination. It tries every word in a list of passwords that real people have actually used. If a password appears in `rockyou.txt`, it will be found almost instantly regardless of its apparent complexity.
- This creates a counterintuitive result that your experiments should reveal: a random 4-digit PIN (`7392`) is harder to crack by dictionary attack than `iloveyou`, even though the PIN "looks" weaker.

**What you will build:**
- Extend `brute_force` to accept any character set as a parameter (lowercase, uppercase, symbols, or any combination)
- A function `dictionary_attack(zip_path, wordlist_file)` that reads a wordlist line by line and tries each password
- An experiment runner: crack the same ZIP using brute force vs. dictionary attack, record both times
- Your first matplotlib chart: password length vs. brute-force crack time (bar chart or line graph)

**Python skills introduced:** function parameters with defaults, reading large files efficiently line-by-line (not loading the whole file at once), basic matplotlib (`plt.bar`, `plt.plot`, `plt.savefig`)

**Checkpoint:** Crack all ZIP files in `zips/phase2/`. Add results to `results/phase2.csv`. Save at least one visualization to `plots/`.

---

### Phase 3 — Weeks 7–9: Smart Attacks and Hashing

**Goal:** Implement attacks that exploit predictable human behaviour, then switch from ZIP cracking to hash cracking and understand what makes bcrypt fundamentally different from MD5.

**Key concepts:**

*Hybrid attacks:*
People do not choose random passwords. When told a password needs a number and a capital letter, they write `Password1`. When told it needs a symbol, they write `Password1!`. A hybrid attack takes dictionary words and applies these predictable transformations. The result is that `Password1!` — despite satisfying every common complexity rule — falls to a hybrid attack in milliseconds.

*Password hashing:*
Systems do not store your password. They store a *hash* — the result of a one-way function. When you log in, the system hashes what you typed and compares it to the stored hash. You cannot reverse a hash to recover the password, but you can hash candidate passwords and compare. This is exactly what your cracker does.

- **MD5 and SHA-256** are fast by design (built for file integrity, not passwords). A modern machine can compute billions of MD5 hashes per second. This speed is catastrophic for password storage.
- **bcrypt** is slow by design. It has a *cost factor* that makes each hash computation take a fixed amount of time (e.g., 100ms). Checking 1,000 passwords against bcrypt takes ~100 seconds. Checking the same 1,000 passwords against MD5 takes under a millisecond. This is not a bug — it is the entire security model.

*Hash lookup tables:*
Rather than hashing a candidate every time you need to check it, you can pre-compute hashes for your entire wordlist once and store them in a Python dictionary: `{hash: password}`. Then, given an unknown hash, you look it up in O(1) time — instant. This is the core idea behind rainbow tables. The defence against this is *salting*: before hashing, append a unique random string (the salt) to each password. Now `password` hashed with salt `x7k2` produces a completely different result from `password` hashed with salt `q9mw`. Pre-computed tables become useless because they would need to be recomputed for every possible salt.

**What you will build:**
- A `hybrid_attack(zip_path, wordlist_file, rules)` function that applies transformations to each dictionary word. Start with:
  - Capitalise the first letter: `password` → `Password`
  - Append digits 0–99: `password` → `password1`, `password99`
  - Common l33t substitutions: `a→@`, `e→3`, `o→0`, `i→1`, `s→$`
  - Common suffixes: `!`, `123`, `2024`, `#1`
- A hash cracker: given a list of MD5 or SHA-256 hashes, find the original passwords using dictionary + hybrid attacks
- A hash lookup table: pre-compute hashes for `wordlist_small.txt`, store in a dictionary, and measure lookup speed vs. hashing on the fly
- A bcrypt timing experiment: hash 100 candidate passwords against an MD5 target vs. a bcrypt target, and plot the time difference

**Python skills introduced:** string `.upper()`, `.replace()`, and format operations; `hashlib.md5()`, `hashlib.sha256()`, `bcrypt` library; Python dictionaries; understanding O(1) vs O(n) lookup

**Checkpoint:** Crack all hashes in `hashes/`. Crack ZIP files in `zips/phase3/`. Add results to `results/phase3.csv`. Produce a visualization comparing your attack strategies.

---

### Phase 4 — Weeks 10–12: The Bigger Picture

**Goal:** Understand the threats that your cracker cannot address, learn what defenders actually do, and use your experimental data to design a real password policy.

**Key concepts:**

*Credential stuffing:*
If a user's password for one site leaks, attackers automatically try that password on every other major site. This attack does not require cracking — just testing leaked username/password pairs directly. The defence is not a stronger password: it is *not reusing passwords*. Password managers make this feasible for normal users.

*Social engineering:*
The most efficient attack does not touch cryptography at all. An attacker who convinces a user to hand over their password — via phishing, impersonation, or pretexting — bypasses every technical defence. No password policy prevents this. Multi-factor authentication limits the damage: even a stolen password is not enough.

*Defensive countermeasures:*
- **Rate limiting and account lockout:** Online services limit login attempts. Your offline cracker tries thousands of passwords per second; an online attacker gets maybe 10 before the account locks. This is why offline hash cracking (from a stolen database) is so much more dangerous than online guessing.
- **Multi-factor authentication (MFA):** A second factor (TOTP app, hardware key) means a cracked password alone is not enough.
- **Password managers:** Enable every password to be unique and random. Defeat both dictionary attacks (random passwords are not in any wordlist) and credential stuffing (each site gets a different password).
- **Have I Been Pwned (HIBP):** A free service that checks whether a password appears in known breach data. Good services block passwords found in breach lists at registration.

*NIST SP 800-63B (2024 update) — what the evidence actually says:*
This is the US government's authoritative password guidance, based on research into how real users behave. Its key recommendations contradict most corporate password policies:
- **Length matters more than complexity.** A 16-character passphrase is stronger than an 8-character mix of upper/lower/digit/symbol.
- **Mandatory periodic rotation backfires.** Users forced to change passwords every 90 days choose weaker passwords and increment predictably (`Password1` → `Password2`). Only change passwords when compromise is suspected.
- **Complexity rules backfire.** Rules like "must contain uppercase, digit, and symbol" produce predictable patterns (`Password1!`). Your hybrid attack data will prove this directly.
- **Check against known breach lists.** Reject passwords that appear in rockyou.txt or HIBP data, regardless of their apparent complexity.
- **Allow all printable characters.** Do not restrict symbols.

*Drafting your password policy:*
Your policy must cite your experimental data. Do not write "long passwords are better" — write "our brute-force experiments showed that adding two characters to a digit-only password multiplied crack time by factor X, while switching to a dictionary word dropped crack time from Y minutes to Z seconds despite appearing more complex." Every recommendation needs evidence.

**Python skills introduced:** Python `set` for O(1) membership testing; loading and checking against a breach list; reading structured data

**Checkpoint:** Draft your password policy (1–2 pages) and ethical reflection (1 page). Both feed directly into the final report.

---

### Phase 5 — Weeks 13–15: Report and Defence

**Goal:** Finalize your scientific report, prepare your presentation, and complete the two graded cracking challenges.

**Report structure:**
1. **Introduction** — why password security matters; the Turing framing
2. **Methods** — describe each attack you implemented; how you measured time; how you ensured fair comparisons
3. **Experiments** — what questions you asked, what variables you controlled, what you measured
4. **Results** — your data with visualizations; what surprised you
5. **Password Policy** — your recommendation, justified by your results and NIST guidelines
6. **Ethical Reflection** — legal boundaries, what responsible disclosure means, the difference between a security professional and an attacker
7. **Conclusion**

**Checkpoint:** Submit the complete project repository, final report, and your "Defend Your Password" password **one week before the examination date**.

---

## Deliverables

| Deliverable | Deadline |
|---|---|
| GitLab repository with all source code | Last Friday of semester |
| `results/*.csv` — all experimental data | Last Friday of semester |
| Scientific report (5–10 pages) | Last Friday of semester |
| Cracked passwords as proof of work | Last Friday of semester |
| "Defend Your Password" submission | One week before examination |

---

## Examination and Grading

Your final grade has three components. Team size is **3–4 students**. All three components must be passed to pass the module.

---

### Component 1 — Group Presentation (40%)

Each team presents their work in a structured examination session.

**Format:**
- Team presentation of experiments and results: 20–30 minutes
- Questions to the whole team: 10 minutes
- Individual questions to each team member: up to 20 minutes per person

Every team member must be able to answer questions about the full project, not just their own part. If you implemented the dictionary attack, you are still expected to explain how the brute forcer works, and vice versa.

**Grading criteria:**

| Grade | Description |
|---|---|
| 6 | Every attack explained correctly and in depth. Experiments are well-designed with controlled variables. Visualizations are clear and tell a coherent story. Password policy follows logically from experimental data and cites NIST. Every team member handles cross-cutting questions confidently. |
| 5 | Minor gaps in explanation or in connecting experimental results to the policy. Visualizations present but could be clearer. |
| 4 | Attacks implemented and working, but explanations are surface-level. Policy exists but is not well-grounded in the team's own data. |
| 3 | Significant gaps in understanding. Experiments incomplete or poorly designed. Individuals cannot explain parts of the project they did not personally implement. |
| 2 | Major implementation failures. Work cannot be demonstrated or explained. |

---

### Component 2 — Defend Your Password (30%)

You submit one personally designed password before the examination deadline. The instructors will create a ZIP file locked with your password and run the standard attack pipeline against it on a fixed reference machine, unattended. Your grade is determined by how long it takes to crack.

This component tests whether you understood the attacks well enough to design a password that resists them.

**Rules:**
- Password must be between 1 and 16 characters
- No passphrase consisting of three or more unmodified common words (e.g., `correcthorsebattery` is disqualified; `c0rrectH0rse!` is fine)
- Your password must not appear verbatim in rockyou.txt — if it does, it is disqualified (you had the wordlist)
- Submit your password in plaintext via the secure submission form before the deadline; it is stored encrypted and only decrypted by the automated pipeline

**Why ZIP, not a hash?** Because cracking ZIP files is exactly what you built. There is no trick, no new technology — the same pipeline you wrote is the pipeline that runs against your password.

**The attack pipeline (stops as soon as the password is found):**

| Step | Attack |
|---|---|
| 1 | Brute force — digits only, lengths 1–6 |
| 2 | Brute force — lowercase only, lengths 1–5 |
| 3 | Brute force — full character set (lower + upper + digits + symbols), lengths 1–4 |
| 4 | Dictionary attack — full rockyou.txt |
| 5 | Hybrid attack — rockyou.txt words with: capitalise first letter, append digits 0–99, l33t substitutions, common suffixes (`!`, `123`, `2024`, `#1`) |
| 6 | Hash lookup — pre-computed table from rockyou.txt |

**Grading scale:**

| Time to crack | Grade |
|---|---|
| Disqualified (verbatim in rockyou.txt, or rule violation) | 1 |
| Cracked in under 5 minutes | 2 |
| Cracked in 5–30 minutes | 3 |
| Cracked in 30 minutes – 2 hours | 4 |
| Cracked in 2–8 hours | 5 |
| Not cracked within 8 hours | 6 |

*The pipeline runs on the reference machine overnight if necessary. The 8-hour window is wall-clock time.*

---

### Component 3 — Attack the Expert's ZIP (30%)

At the start of the examination session, you receive a unique encrypted ZIP file. Your task is to crack it using the tools you built during the semester. Your grade is determined by how quickly you find the password.

This component tests whether your implementation is correct, complete, and efficient enough to run the full pipeline under time pressure.

**Rules:**
- You may use any code, scripts, or wordlists you developed during the challenge
- No off-the-shelf cracking tools (no Hashcat, no John the Ripper) — your implementation only
- The ZIP uses ZipCrypto encryption, consistent with what the `zipfile` module supports
- The clock starts when you receive the file and stops when you submit the correct password

**Recommended pipeline order (same as what you built):**

| Step | Attack | Why first? |
|---|---|---|
| 1 | Dictionary attack — rockyou.txt | Fastest path if the password is a known word |
| 2 | Hybrid attack — rockyou.txt with transformations | Catches "Password1!" style passwords |
| 3 | Hash lookup — your pre-computed table | Instant if the password hashes to a known entry |
| 4 | Brute force — digits only, up to 6 characters | ~17 minutes worst case in Python |
| 5 | Brute force — lowercase only, up to 5 characters | Slow, but systematic |

*Note: the expert's passwords are chosen so that every password falls within the first three steps for a correctly implemented pipeline. Steps 4 and 5 are a fallback for partially working implementations.*

**Grading scale:**

| Time to crack | Grade |
|---|---|
| Not cracked within 4 hours | 2 |
| Cracked in 2–4 hours | 3 |
| Cracked in 30 minutes – 2 hours | 4 |
| Cracked in 5–30 minutes | 5 |
| Cracked in under 5 minutes | 6 |

---

## A Note on Fairness

Every student in Component 3 receives a different ZIP file. Passwords are selected before the semester from a fixed set of templates and assigned randomly at the start of the examination. No password requires an attack not covered in the module.

All Component 2 crack attempts run on the same reference machine, with the same software, in the same pipeline order. The full pipeline is published at the start of the semester — there are no surprises, only whether you understood and applied what you learned.

---

## Ethics and the Law

The techniques in this challenge are real. The code that cracks a test ZIP file is the same code that could attack real systems. Before you begin, you must understand the legal and professional boundaries.

**What is permitted in this challenge:**
- Cracking the ZIP files and hashes provided for this module
- Testing the pipeline against your own passwords and files
- Using rockyou.txt for the exercises described here

**What is illegal:**
- Using these techniques on any system, account, or file you do not own or have explicit written permission to test
- **Switzerland:** Unauthorized access to computer systems is an offence under **Art. 143bis of the Swiss Criminal Code**
- **EU/EEA:** National implementations of the Computer Misuse Directive apply
- **US:** The **Computer Fraud and Abuse Act (CFAA)** applies to anyone interacting with US-based systems

**Professional conduct:**
Security researchers operate under *responsible disclosure*: if you discover a real vulnerability, you report it privately to the affected organisation, give them time to fix it, and only publish details afterward. You do not exploit it, sell it, or announce it publicly without warning.

The ethical reflection in your final report is not a box to tick. It is an opportunity to show that you understand the difference between a security professional and an attacker — and that the difference is not primarily technical.
