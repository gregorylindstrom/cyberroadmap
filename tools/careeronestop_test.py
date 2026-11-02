#!/usr/bin/env python3
"""
CareerOneStop API smoke test — CyberRoadmap
Replaces the earlier version that had credentials pasted inline (my fault,
not yours — this one does it right).

Credentials are read from environment variables and are NEVER stored in
this file, so it is safe to keep in the repo.

Usage:
  Option A — one-off shell env vars:
      export CAREERONESTOP_USER_ID="your-user-id"
      export CAREERONESTOP_API_TOKEN="your-token"
      python3 careeronestop_test.py

  Option B — .env file (recommended for local dev):
      1. cp .env.example .env
      2. Fill in your real values in .env  (.env is gitignored)
      3. pip install python-dotenv
      4. python3 careeronestop_test.py
"""

import os
import sys

import requests

# Load .env if python-dotenv is available (optional convenience)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

USER_ID = os.environ.get("CAREERONESTOP_USER_ID")
API_TOKEN = os.environ.get("CAREERONESTOP_API_TOKEN")

if not USER_ID or not API_TOKEN:
    sys.exit(
        "Missing credentials.\n"
        "Set CAREERONESTOP_USER_ID and CAREERONESTOP_API_TOKEN as environment\n"
        "variables, or create a .env file from .env.example.\n"
        "(See the docstring at the top of this file.)"
    )

url = (
    f"https://api.careeronestop.org/v1/jobsearch/{USER_ID}"
    f"/cybersecurity/TX/100/acquisitiondate/DESC/0/50/30"
)
headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json",
    "User-Agent": "CyberRoadmap/1.0",
}

r = requests.get(url, headers=headers, timeout=30)
print(f"Status: {r.status_code}")

if r.status_code == 200:
    data = r.json()
    jobs = data.get("Jobs", [])
    print(f"Jobs returned: {len(jobs)}")
    for j in jobs[:5]:
        print(f"  - {j.get('JobTitle', '?')} | {j.get('Company', '?')} | {j.get('AccquisitionDate', j.get('AcquisitionDate', '?'))}")
elif r.status_code in (401, 403):
    print("Auth failed — token is wrong, expired, or was rotated. "
          "Request a fresh token and update your env/.env (and the GitHub secret).")
else:
    print(r.text[:1500])

