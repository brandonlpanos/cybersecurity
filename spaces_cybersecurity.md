# Cybersecurity – Password Cracking

How secure is your password really?

Every year, millions of passwords are exposed through data breaches. Analyses consistently show that a shockingly large proportion of them can be cracked within seconds. At the same time, passwords protect our emails, bank accounts, and personal data.

In this challenge, you'll find out what makes a password secure – by becoming the attacker yourself.

You'll receive encrypted ZIP files with passwords of varying complexity. Your task: write programs in Python that systematically crack these passwords. In doing so, you'll experimentally investigate:

- How long does it take to crack a password – depending on length and character set?
- Why are some attacks orders of magnitude faster than others?
- What does this mean for password recommendations in practice?

## Topics

- Brute-force attacks and password security
- Dictionary attacks
- Password hashing (MD5, SHA-256, bcrypt)
- Experimental work and data analysis
- Ethics in cybersecurity

## Equipment and Files

- Python framework with a wrapper function for testing passwords (provided)
- 10 encrypted ZIP files with increasing password complexity
- Wordlist (excerpt from rockyou.txt) for dictionary attacks
- Hashing file containing password hashes (MD5, SHA-256, bcrypt)
- Open-source tool (fcrackzip) for comparison with your own implementation

## Your Tasks

The following steps will guide you through the challenge:

**Getting Started (Weeks 1–4)**

- Get familiar with the provided Python framework
- Program a brute-force attack for simple passwords (digits only)
- Crack the first ZIP files and record timing measurements

**Extension and Experiments (Weeks 5–8)**

- Extend the brute-forcer to handle different character sets (letters, special characters)
- Run systematic experiments: how does crack time behave as password length and character set size increase?
- Compare your own implementation with the open-source tool
- Visualize results

**Cybersecurity Deep Dive (Weeks 9–12)**

- Implement a dictionary attack and compare it to brute force
- Hashing experiments: why do secure systems intentionally use slow hash functions?
- Formulate your own password policy – based on your measured data
- Ethical reflection: what is legal, what is not? What responsibility do security professionals bear?

**Report and Defense (Weeks 13–15)**

- Complete the scientific report
- Prepare the presentation

## Submission

### Submission Format

- Complete source code as a GitLab repository
- Scientific report (approx. 15–20 pages) clearly and traceably describing the approach, experiments, and results. The report includes:
  - Methodology and experimental setup
  - Results with visualizations (charts, tables)
  - Discussion and interpretation
  - Evidence-based password policy recommendation
  - Ethical reflection
- Cracked passwords as proof of work

### Submission Deadline

Last Friday of the semester.

## Support

Technical support takes place as indicated in the box at the top right.

- **Kickoff Workshop**: During the contact session in week 1.
- **Submission**: According to the degree program schedule.
- **Three checkpoints** (approx. weeks 4, 8, 12) as milestones with feedback. Students send the invitations.

## Challenge Examination

The challenge examination has three parts:

- Team presentation of the work (20–30 minutes)
- Questions from the examiners to the whole team (10 minutes)
- Questions from the examiners to individual team members (up to 20–25 minutes each). All team members must be able to answer questions about everything.

### Examination Date

The examination date is arranged bilaterally. This can take place at a checkpoint, for example.

## Use Immersive Tasks in This Project for Other Modules

You can reduce the workload for submissions in other modules by using artifacts and deliverables from this project to demonstrate your learning progress. To do this, you need to coordinate with the module leads of the other modules and define immersive tasks together with them.