# Password Security Analysis
## FHNW — Cybersecurity Module — Semester Report

| Field | Value |
|---|---|
| Group number | _TODO_ |
| Group members | _TODO_ |
| Submission date | _TODO_ |
| Word count (body only, excluding tables and references) | _TODO_ |

---

> **How to use this template**
> Replace every _TODO_ and every block marked `<!-- TODO … -->` with your own content.
> The word-count targets in each section heading are guides, not hard limits.
> **Every recommendation you make must cite a specific number from your results CSVs.**
> Evidence first. Recommendations second.

---

## Abstract (~150 words)

<!-- TODO
Summarise the whole report in one paragraph. Cover:
  - What you implemented (which attack types, in which language)
  - The most striking finding from each phase (one number each)
  - Your single most important password recommendation

Write this last — it is easiest once the rest of the report is complete.
-->

---

## 1. Introduction (~200 words)

<!-- TODO
Motivate the topic. Answer:
  - Why does weak password security cause real harm? (cite a real breach if you can)
  - What does this module set out to demonstrate?
  - What is the structure of the rest of this report?

Keep it concise. Do not define "brute force" or "dictionary attack" here —
save technical definitions for Section 2.
-->

---

## 2. Background (~300 words)

### 2.1 Password Hashing

<!-- TODO
Explain what a hash function does in one sentence, then answer:
  - Why are passwords stored as hashes rather than plaintext?
  - What is a pre-computed lookup table (simplified rainbow table) and how does
    your build_lookup_table() exploit it?
  - Why does bcrypt resist this attack when MD5 and SHA-256 do not?
    Hint: look up the "cost factor" parameter and what it controls.
-->

### 2.2 Salting

<!-- TODO
Explain what a salt is and why adding a random salt to each password
defeats pre-computed tables even for fast algorithms like MD5.
One short paragraph is enough.
-->

### 2.3 Attack Taxonomy

<!-- TODO
Define each attack type you implemented in one or two sentences each:
  - Brute force (digit-only)
  - Brute force (arbitrary character set)
  - Dictionary attack
  - Hybrid / rule-based attack
  - Hash lookup table (pre-computation)
-->

### 2.4 NIST SP 800-63B Guidelines

<!-- TODO
Summarise the NIST SP 800-63B recommendations that are directly relevant
to your results. Key points to cover:
  - Length matters more than complexity
  - Mandatory periodic rotation is counterproductive — why does your data support this?
  - Check submitted passwords against known breach lists
  - Do not impose composition rules (uppercase + digit + symbol requirements)

Cite the standard by name in your References section.
-->

---

## 3. Methodology (~250 words)

<!-- TODO
Describe how your cracker works at a level that would let another student
reproduce it. Cover:
  - Programming language and version (Python X.Y)
  - Which standard-library modules you used and why (itertools, hashlib, zipfile, …)
  - How you measured crack time (time.time() before and after each attack)
  - Hardware you ran it on (CPU model, RAM) — this affects your raw times
  - The wordlist you used (wordlist_small.txt: N words derived from rockyou.txt)
  - Which ZIP files were cracked in each phase

Do NOT paste your source code here. Reference specific function names
(e.g. "brute_force_digits()") but describe what they do in prose.
-->

**Test environment**

| Property | Value |
|---|---|
| CPU | _TODO_ |
| RAM | _TODO_ |
| OS | _TODO_ |
| Python version | _TODO_ |
| Wordlist size | _TODO_ words |

---

## 4. Results

> Paste your charts from the `plots/` directory into the relevant sub-sections.
> For each chart, write a figure caption and then a paragraph interpreting it.
> Do not just describe what the chart shows — explain what it *means*.

### 4.1 Phase 1 — Digit Brute Force

**Figure 1** — paste `plots/phase1_growth.png` here.

_Caption: TODO_

<!-- TODO
Insert your phase1.csv data in the table below, then interpret the chart.
Your interpretation must answer:
  - How did crack time change as password length increased from 4 to 6 digits?
  - Is the growth linear or exponential? How do you know from the numbers?
  - What does this imply for the security of 4-digit PINs vs 6-digit PINs?
-->

| Filename | Password length | Search space | Crack time (s) |
|---|---|---|---|
| level1.zip | 4 | 10,000 | _TODO_ |
| level2.zip | 5 | 100,000 | _TODO_ |
| level3.zip | 6 | 1,000,000 | _TODO_ |

---

### 4.2 Phase 2 — Brute Force vs Dictionary Attack

**Figure 2** — paste `plots/phase2_comparison.png` here.

_Caption: TODO_

<!-- TODO
Insert your phase2.csv data in the table, then interpret the chart.
Your interpretation must answer:
  - How long did brute force take on brute_easy.zip (4 lowercase chars)?
  - How long did the dictionary attack take on dict_easy.zip (8 chars, "sunshine")?
  - The dictionary target is longer — why did it crack faster?
  - What is the practical lesson for an attacker choosing between the two methods?
-->

| Filename | Password | Password length | Attack type | Crack time (s) |
|---|---|---|---|---|
| brute_easy.zip | kbwp | 4 | brute force | _TODO_ |
| brute_medium.zip | xmqvt | 5 | brute force | _TODO_ |
| dict_easy.zip | sunshine | 8 | dictionary | _TODO_ |
| dict_medium.zip | dragon | 6 | dictionary | _TODO_ |

---

### 4.3 Phase 3 — Hybrid Attacks and Hash Cracking

**Figure 3** — paste `plots/phase3_hybrid.png` here.

_Caption: TODO_

<!-- TODO
Insert your phase3.csv data. Your interpretation must answer:
  - Which hybrid rule was fastest? Which was slowest?
  - Sunshine123! satisfies every standard corporate complexity requirement
    (uppercase, lowercase, digit, symbol, 12 characters) yet you cracked it
    in under a second. What does this tell you about composition rules?
  - For the hash challenges: which hashes were cracked by the lookup table
    (direct dictionary match) and which required the hybrid step?
  - Why did MD5 crack faster than bcrypt would for the same password?
    (You may need to read the test_cases.txt bcrypt section to answer this.)
-->

**ZIP hybrid results**

| Filename | Password | Rule applied | Crack time (s) |
|---|---|---|---|
| hybrid_capitalize.zip | Sunshine | Capitalise first letter | _TODO_ |
| hybrid_append.zip | password99 | Append two-digit number | _TODO_ |
| hybrid_leet.zip | dr@g0n | Full leet substitution | _TODO_ |
| hybrid_suffix.zip | dragon2024 | Append year | _TODO_ |
| hybrid_combo.zip | Sunshine123! | Capitalise + append suffix | _TODO_ |

**Hash cracking results (MD5)**

| Hash ID | Difficulty | Cracked password | Method used |
|---|---|---|---|
| h01 | easy | _TODO_ | _TODO_ |
| h02 | easy | _TODO_ | _TODO_ |
| h03 | easy | _TODO_ | _TODO_ |
| h04 | easy | _TODO_ | _TODO_ |
| h05 | medium | _TODO_ | _TODO_ |
| h06 | medium | _TODO_ | _TODO_ |
| h07 | medium | _TODO_ | _TODO_ |
| h08 | hard | _TODO_ | _TODO_ |
| h09 | hard | _TODO_ | _TODO_ |

---

### 4.4 Phase 4 — Final Challenges

<!-- TODO
Insert your phase4.csv data. For each final ZIP, explain:
  - Which base word did the password derive from?
  - Which rules had to be combined to generate it?
  - How long did cracking take — and at which pipeline step did it succeed?

These three passwords required your full pipeline to work correctly.
If any of them failed, explain what went wrong and what you would fix.
-->

| Filename | Cracked password | Base word | Rules applied | Crack time (s) |
|---|---|---|---|---|
| final1.zip | _TODO_ | _TODO_ | _TODO_ | _TODO_ |
| final2.zip | _TODO_ | _TODO_ | _TODO_ | _TODO_ |
| final3.zip | _TODO_ | _TODO_ | _TODO_ | _TODO_ |

---

## 5. Discussion (~400 words)

<!-- TODO
Synthesise your results across all phases. This section earns marks for
connecting evidence to conclusions. Address all four points below.

5a. Search space vs crack time
    Your Phase 1 data shows the search space growing exponentially with length.
    Does crack time grow at the same rate? Is there any deviation and why?
    Use specific numbers: "Adding one digit increased the search space by 10×
    and crack time from X.Xs to Y.Ys (a Zx increase)."

5b. Why human-chosen passwords cluster
    Dictionary and hybrid attacks exploit the fact that humans choose passwords
    from a tiny fraction of the possible space. Use your Phase 2 and 3 crack
    times as quantitative evidence. How small is that fraction?

5c. The complexity rules trap
    Sunshine123! is 12 characters with uppercase, digits, and a symbol.
    You cracked it in under a second. Why do composition requirements fail
    to produce unpredictable passwords? Cite your Phase 3 hybrid_combo result.

5d. Credential stuffing and social engineering
    Brief paragraph (3-5 sentences) connecting your findings to two broader
    attack vectors: credential stuffing (reusing cracked passwords across sites)
    and social engineering (targeting password recovery questions or direct
    deception). These do not appear in your CSV files — this is your chance to
    reason beyond the data.
-->

---

## 6. Conclusions and Recommendations (~200 words)

<!-- TODO
State 4–6 concrete password policy recommendations.
EVERY recommendation must cite at least one number from your results.
Use this structure for each:

  **Recommendation N: [Short title]**
  Evidence: [specific result, e.g. "sunshine cracked in 0.03s by dictionary attack"]
  Recommendation: [what to do instead, e.g. "require minimum 16 characters"]
  Standard: [NIST SP 800-63B section X.Y] (if applicable)

Do not introduce new ideas here — only conclusions already supported by
Section 4 and discussed in Section 5.
-->

---

## 7. References

<!-- TODO
Use any consistent citation style (APA, IEEE, or Chicago — pick one and
apply it uniformly). Required entries:

  - NIST SP 800-63B (2017, updated 2019): Digital Identity Guidelines —
    Authentication and Lifecycle Management.
    https://pages.nist.gov/800-63-3/sp800-63b.html

  - rockyou.txt breach dataset (2009 RockYou data breach).
    Cite the original breach, not a secondary download source.

  - Python Software Foundation. Python 3 documentation — hashlib, zipfile,
    itertools. https://docs.python.org/3/

Add any additional sources you used for background (Section 2).
Wikipedia is acceptable as a starting point but not as a primary source —
follow its citations to the original material.
-->

---

*End of report template.*
