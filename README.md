\# Password Strength Checker + Policy Analyzer



A small Python tool that evaluates a password against a configurable security policy and produces

a simple strength score with actionable recommendations.



\## Features

\- Checks policy rules (length, uppercase, lowercase, digits, symbols, whitespace)

\- Flags weak/common passwords (small built-in list)

\- Simple strength score (heuristic, not true entropy)

\- Outputs clear pass/fail results + recommendations



\## Install

```bash

python3 -m pip install --upgrade pip



python3 password\_checker.py



python3 password\_checker.py --min-length 14 --max-run 3

python3 password\_checker.py --min-length 10 --no-symbol



(You can pass --password but it is not recommended because it may appear in shell history.)



Example Output



See sample\_output.txt.



Limitations



Strength score is a heuristic (not a formal entropy calculation)



Common password list is intentionally small for this mini-project



Real systems should also check breached password databases and rate-limit attempts



Ethics / Safety



This tool does not crack passwords and does not attempt to recover secrets. It only evaluates the password

string you provide.



What I Learned



Why password length is often more important than complexity



How policy checks and user feedback improve security usability



How to build safety-focused security tooling (analysis, not exploitation)

