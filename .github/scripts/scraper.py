#!/usr/bin/env python3
"""
CyberRoadmap Jobs Scraper
=========================
Pulls entry-level cyber/IT/infrastructure jobs from multiple public APIs,
merges them into a single normalized format, and writes the result to
public/data/jobs.json for the CyberRoadmap frontend to consume.

Sources:
    - USAJobs (federal)
    - Adzuna (nationwide aggregator)
    - The Muse (tech-focused, strong entry-level)
    - Remotive (remote-only)

Runs every 6 hours via GitHub Actions. Cost: $0.

Environment variables required (set in GitHub Secrets):
    - USAJOBS_API_KEY
    - USAJOBS_USER_EMAIL  (your email, required by USAJobs TOS)
    - ADZUNA_APP_ID
    - ADZUNA_APP_KEY

Optional:
    - THE_MUSE_API_KEY (works without it, lower rate limit)
"""

import json
import os
import re
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# --- Configuration ---------------------------------------------------------

# Categories we tag jobs with. Each category has a list of keyword patterns
# that, when matched in the title or description, tag the job with that category.
# A single job can belong to multiple categories (e.g., "Cloud Security Engineer"
# is both Cloud and Cyber).
CATEGORIES = {
    "Cyber": [
        r"\bcyber\b", r"\binfosec\b", r"\binformation\s+security\b",
        r"\bsecurity\s+(analyst|engineer|architect|consultant|specialist|administrator|operations)\b",
        r"\bSOC\b", r"\bpen\s*test", r"\bpenetration\b", r"\bethical\s+hack",
        r"\bvulnerability\b", r"\bthreat\b", r"\bincident\s+response\b",
        r"\bGRC\b", r"\bgovernance.{0,20}risk.{0,20}compliance\b",
        r"\bCISSP\b", r"\bCISM\b", r"\bOSCP\b", r"\bSecurity\+\b",
        r"\bred\s+team\b", r"\bblue\s+team\b", r"\bpurple\s+team\b",
        r"\bmalware\b", r"\bforensic", r"\bCMMC\b", r"\bNIST\s+800\b",
    ],
    "IT": [
        r"\bIT\s+(support|analyst|specialist|technician|admin)",
        r"\bhelp\s*desk\b", r"\bservice\s*desk\b", r"\bdesktop\s+support\b",
        r"\btechnical\s+support\b", r"\bsystems?\s+admin", r"\bsysadmin\b",
        r"\bnetwork\s+(admin|engineer|technician|analyst)\b",
        r"\bA\+\b", r"\bNetwork\+\b", r"\bCCNA\b",
    ],
    "Infrastructure": [
        r"\binfrastructure\b", r"\bdevops\b", r"\bSRE\b",
        r"\bsite\s+reliability\b", r"\bplatform\s+engineer\b",
        r"\bkubernetes\b", r"\bdocker\b", r"\bterraform\b", r"\bansible\b",
    ],
    "Cloud": [
        r"\bcloud\b", r"\bAWS\b", r"\bAzure\b",
        r"\bGCP\b", r"\bgoogle\s+cloud\b",
    ],
    "AI/ML": [
        r"\bAI\b(?!\s+ops)",  # "AI" but not "AI ops"
        r"\bartificial\s+intelligence\b", r"\bmachine\s+learning\b",
        r"\bML\s+(engineer|ops)\b", r"\bdata\s+scientist\b",
        r"\bLLM\b", r"\bneural\s+network\b", r"\bdeep\s+learning\b",
        r"\bMLOps\b", r"\bprompt\s+engineer",
    ],
    "Data": [
        r"\bdata\s+(analyst|engineer|scientist|architect)\b",
        r"\bETL\b", r"\bdatabase\s+admin", r"\bDBA\b", r"\bSQL\b",
        r"\bpower\s*BI\b", r"\btableau\b", r"\bsnowflake\b",
    ],
    "Software": [
        r"\bsoftware\s+(engineer|developer)\b", r"\bweb\s+developer\b",
        r"\bfull\s*stack\b", r"\bfront\s*end\b", r"\bback\s*end\b",
        r"\bpython\s+developer\b", r"\bjava\s+developer\b",
        r"\bapplication\s+developer\b",
    ],
}

# Entry-level indicators. A job is considered entry-level if ANY of these
# match in title/description, OR if none of the senior indicators match
# AND the years-of-experience requirement is low.
ENTRY_LEVEL_POSITIVE = [
    r"\bentry\s*level\b", r"\bjunior\b", r"\bassociate\b",
    r"\bintern(ship)?\b", r"\btrainee\b", r"\bgraduate\b",
    r"\bI\b(?!\w)", r"\bnew\s+grad", r"\bearly\s+career\b",
    r"\bapprentice\b", r"\bjr\.?\b", r"\btier\s+1\b",
    r"\blevel\s+[1I]\b", r"\b0[-\s]?2\s+years\b",
]

SENIOR_NEGATIVE = [
    r"\bsenior\b", r"\bsr\.?\b", r"\blead\b", r"\bprincipal\b",
    r"\bstaff\b", r"\barchitect\b", r"\bmanager\b", r"\bdirector\b",
    r"\b(5|6|7|8|9|10|15|20)\+?\s+years\b", r"\bexpert\b",
    r"\bhead\s+of\b", r"\bVP\b", r"\bchief\b",
]


# --- Utility functions -----------------------------------------------------

def log(msg: str) -> None:
    """Log with timestamp."""
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def fingerprint(title: str, company: str, location: str) -> str:
    """Create a stable deduplication key for a job."""
    normalized = f"{title.lower().strip()}|{company.lower().strip()}|{location.lower().strip()[:20]}"
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


def categorize(title: str, description: str = "") -> list[str]:
    """Apply our category regex patterns to tag a job."""
    text = f"{title} {description[:500]}".lower()
    matches = []
    for cat, patterns in CATEGORIES.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(cat)
                break
    return matches


def is_entry_level(title: str, description: str = "") -> bool:
    """
    Heuristic: entry-level if explicit entry indicator found,
    OR if no senior indicator AND description hints at low experience.
    """
    combined = f"{title} {description[:1000]}".lower()

    # Strong positive signal → entry-level
    for pattern in ENTRY_LEVEL_POSITIVE:
        if re.search(pattern, combined, re.IGNORECASE):
            return True

    # Strong negative signal → not entry-level
    for pattern in SENIOR_NEGATIVE:
        if re.search(pattern, combined, re.IGNORECASE):
            return False

    # Ambiguous — default to including (students can filter further)
    return True


def clean_description(text: str, max_len: int = 300) -> str:
    """Strip HTML and truncate to reasonable summary length."""
    if not text:
        return ""
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


def parse_location(loc: str) -> dict:
    """
    Parse a location string into structured components.
    Returns: {"display": str, "city": str, "state": str, "remote": bool}
    """
    if not loc:
        return {"display": "Location not specified", "city": "", "state": "", "remote": False}

    display = loc.strip()
    remote = bool(re.search(r"\bremote\b|\banywhere\b|\btelework\b", display, re.IGNORECASE))

    # Try to extract "City, ST" pattern
    match = re.search(r"([A-Za-z .\-]+),\s*([A-Z]{2})\b", display)
    if match:
        return {
            "display": display,
            "city": match.group(1).strip(),
            "state": match.group(2).strip(),
            "remote": remote,
        }

    return {"display": display, "city": "", "state": "", "remote": remote}


# --- Source adapters -------------------------------------------------------

def fetch_usajobs() -> list[dict]:
    """
    Federal jobs via USAJobs API.
    Docs: https://developer.usajobs.gov/api-reference/get-api-search
    """
    api_key = os.environ.get("USAJOBS_API_KEY")
    user_email = os.environ.get("USAJOBS_USER_EMAIL")

    if not api_key or not user_email:
        log("USAJobs: missing API key or user email, skipping")
        return []

    log("USAJobs: fetching...")
    headers = {
        "Host": "data.usajobs.gov",
        "User-Agent": user_email,
        "Authorization-Key": api_key,
    }

    # We search for each category keyword set to get broad coverage
    all_jobs = []
    # USAJobs occupational series codes for tech fields
    # 2210 = IT Management, 1550 = Computer Science, 0854 = Computer Engineering
    search_terms = [
        "cybersecurity", "information security", "cyber analyst",
        "IT specialist", "network engineer", "systems administrator",
        "software developer", "data analyst", "cloud engineer",
    ]

    seen_ids = set()
    for term in search_terms:
        try:
            params = {
                "Keyword": term,
                "ResultsPerPage": 100,
                "Page": 1,
            }
            r = requests.get(
                "https://data.usajobs.gov/api/search",
                headers=headers,
                params=params,
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()

            items = data.get("SearchResult", {}).get("SearchResultItems", [])
            for item in items:
                descr = item.get("MatchedObjectDescriptor", {})
                job_id = descr.get("PositionID", "")
                if job_id in seen_ids:
                    continue
                seen_ids.add(job_id)

                title = descr.get("PositionTitle", "")
                summary = descr.get("UserArea", {}).get("Details", {}).get("JobSummary", "") \
                          or descr.get("QualificationSummary", "")

                if not is_entry_level(title, summary):
                    continue

                # Location can be a list; pick the first
                locations = descr.get("PositionLocation", [])
                loc_str = locations[0].get("LocationName", "") if locations else ""
                loc = parse_location(loc_str)

                # Salary
                pay = descr.get("PositionRemuneration", [])
                salary_min = pay[0].get("MinimumRange") if pay else None
                salary_max = pay[0].get("MaximumRange") if pay else None

                job = {
                    "id": f"usajobs_{job_id}",
                    "title": title,
                    "company": descr.get("OrganizationName", "U.S. Federal Government"),
                    "location": loc,
                    "description": clean_description(summary),
                    "url": descr.get("PositionURI", ""),
                    "posted": descr.get("PublicationStartDate", ""),
                    "salary_min": float(salary_min) if salary_min else None,
                    "salary_max": float(salary_max) if salary_max else None,
                    "source": "USAJobs",
                    "federal": True,
                    "categories": categorize(title, summary),
                    "fingerprint": fingerprint(title, descr.get("OrganizationName", ""), loc_str),
                }
                all_jobs.append(job)
            time.sleep(0.3)  # gentle on the API
        except Exception as e:
            log(f"USAJobs error on '{term}': {e}")

    log(f"USAJobs: {len(all_jobs)} jobs")
    return all_jobs


def fetch_adzuna() -> list[dict]:
    """
    Adzuna — nationwide aggregator with good coverage.
    Docs: https://developer.adzuna.com/docs/search
    """
    app_id = os.environ.get("ADZUNA_APP_ID")
    app_key = os.environ.get("ADZUNA_APP_KEY")

    if not app_id or not app_key:
        log("Adzuna: missing credentials, skipping")
        return []

    log("Adzuna: fetching...")
    all_jobs = []
    seen_ids = set()

    # Search terms aligned with our categories
    search_terms = [
        "entry level cybersecurity", "junior security analyst",
        "entry level IT support", "help desk",
        "junior network engineer", "junior systems administrator",
        "entry level cloud engineer", "junior data analyst",
        "junior software developer", "SOC analyst entry",
    ]

    for term in search_terms:
        for page in [1, 2]:  # first 2 pages per term = up to 100 jobs
            try:
                url = f"https://api.adzuna.com/v1/api/jobs/us/search/{page}"
                params = {
                    "app_id": app_id,
                    "app_key": app_key,
                    "what": term,
                    "results_per_page": 50,
                    "max_days_old": 30,
                    "sort_by": "date",
                }
                r = requests.get(url, params=params, timeout=20)
                r.raise_for_status()
                data = r.json()

                for item in data.get("results", []):
                    job_id = str(item.get("id", ""))
                    if job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)

                    title = item.get("title", "")
                    desc = item.get("description", "")

                    if not is_entry_level(title, desc):
                        continue

                    loc = parse_location(item.get("location", {}).get("display_name", ""))

                    job = {
                        "id": f"adzuna_{job_id}",
                        "title": title,
                        "company": item.get("company", {}).get("display_name", "Unknown"),
                        "location": loc,
                        "description": clean_description(desc),
                        "url": item.get("redirect_url", ""),
                        "posted": item.get("created", ""),
                        "salary_min": item.get("salary_min"),
                        "salary_max": item.get("salary_max"),
                        "source": "Adzuna",
                        "federal": False,
                        "categories": categorize(title, desc),
                        "fingerprint": fingerprint(title, item.get("company", {}).get("display_name", ""), loc["display"]),
                    }
                    all_jobs.append(job)

                time.sleep(0.5)  # rate limit courtesy
            except Exception as e:
                log(f"Adzuna error on '{term}' page {page}: {e}")
                break

    log(f"Adzuna: {len(all_jobs)} jobs")
    return all_jobs


def fetch_the_muse() -> list[dict]:
    """
    The Muse — strong on entry-level tech jobs.
    Docs: https://www.themuse.com/developers/api/v2
    Works without API key but has lower rate limit.
    """
    log("The Muse: fetching...")
    all_jobs = []
    seen_ids = set()

    # The Muse uses category names, not free text search
    muse_categories = [
        "Data and Analytics", "Software Engineering",
        "Engineering", "IT",
        "Business Operations",  # includes many entry-level roles
    ]

    levels = ["Entry Level", "Internship"]

    for cat in muse_categories:
        for level in levels:
            for page in range(1, 3):  # 2 pages per combo = up to 40
                try:
                    params = {
                        "category": cat,
                        "level": level,
                        "location": "United States",
                        "page": page,
                        "descending": "true",
                    }
                    api_key = os.environ.get("THE_MUSE_API_KEY")
                    if api_key:
                        params["api_key"] = api_key

                    r = requests.get(
                        "https://www.themuse.com/api/public/jobs",
                        params=params,
                        timeout=20,
                    )
                    r.raise_for_status()
                    data = r.json()

                    for item in data.get("results", []):
                        job_id = str(item.get("id", ""))
                        if job_id in seen_ids:
                            continue
                        seen_ids.add(job_id)

                        title = item.get("name", "")
                        desc = item.get("contents", "")

                        # Extract location
                        locs = item.get("locations", [])
                        loc_str = locs[0].get("name", "") if locs else ""
                        loc = parse_location(loc_str)

                        # Filter to only tech-relevant categories
                        cats = categorize(title, desc)
                        if not cats:
                            continue

                        job = {
                            "id": f"muse_{job_id}",
                            "title": title,
                            "company": item.get("company", {}).get("name", "Unknown"),
                            "location": loc,
                            "description": clean_description(desc),
                            "url": item.get("refs", {}).get("landing_page", ""),
                            "posted": item.get("publication_date", ""),
                            "salary_min": None,
                            "salary_max": None,
                            "source": "The Muse",
                            "federal": False,
                            "categories": cats,
                            "fingerprint": fingerprint(title, item.get("company", {}).get("name", ""), loc_str),
                        }
                        all_jobs.append(job)

                    time.sleep(0.5)
                except Exception as e:
                    log(f"The Muse error on {cat}/{level} page {page}: {e}")
                    break

    log(f"The Muse: {len(all_jobs)} jobs")
    return all_jobs


def fetch_remotive() -> list[dict]:
    """
    Remotive — all remote jobs, no API key needed.
    Docs: https://remotive.com/api-documentation
    """
    log("Remotive: fetching...")
    all_jobs = []

    # Their API supports category filter
    categories = [
        "software-dev", "devops", "data", "customer-support",
        "qa", "sales", "product", "all-others",
    ]

    seen_ids = set()
    for cat in categories:
        try:
            r = requests.get(
                "https://remotive.com/api/remote-jobs",
                params={"category": cat, "limit": 100},
                timeout=20,
            )
            r.raise_for_status()
            data = r.json()

            for item in data.get("jobs", []):
                job_id = str(item.get("id", ""))
                if job_id in seen_ids:
                    continue
                seen_ids.add(job_id)

                title = item.get("title", "")
                desc = item.get("description", "")

                # Remotive mixes all levels - we filter to entry only
                if not is_entry_level(title, desc):
                    continue

                # Only include if it matches our tech categories
                cats = categorize(title, desc)
                if not cats:
                    continue

                job = {
                    "id": f"remotive_{job_id}",
                    "title": title,
                    "company": item.get("company_name", "Unknown"),
                    "location": {
                        "display": "Remote",
                        "city": "",
                        "state": "",
                        "remote": True,
                    },
                    "description": clean_description(desc),
                    "url": item.get("url", ""),
                    "posted": item.get("publication_date", ""),
                    "salary_min": None,
                    "salary_max": None,
                    "source": "Remotive",
                    "federal": False,
                    "categories": cats,
                    "fingerprint": fingerprint(title, item.get("company_name", ""), "remote"),
                }
                all_jobs.append(job)
            time.sleep(0.3)
        except Exception as e:
            log(f"Remotive error on '{cat}': {e}")

    log(f"Remotive: {len(all_jobs)} jobs")
    return all_jobs


# --- Main ------------------------------------------------------------------

def merge_and_dedupe(jobs_lists: list[list[dict]]) -> list[dict]:
    """Combine all sources, remove duplicates by fingerprint, sort by date."""
    all_jobs = []
    for jobs in jobs_lists:
        all_jobs.extend(jobs)

    log(f"Pre-dedup total: {len(all_jobs)}")

    # Dedupe - keep first occurrence (source priority: USAJobs > Adzuna > Muse > Remotive
    # based on order we called them)
    seen = {}
    for job in all_jobs:
        fp = job["fingerprint"]
        if fp not in seen:
            seen[fp] = job

    deduped = list(seen.values())
    log(f"Post-dedup total: {len(deduped)}")

    # Sort by posted date, newest first
    def sort_key(j):
        return j.get("posted") or ""
    deduped.sort(key=sort_key, reverse=True)

    return deduped


def main():
    start = time.time()
    log("=== CyberRoadmap scraper starting ===")

    # Fetch all sources in parallel
    sources = {
        "usajobs": fetch_usajobs,
        "adzuna": fetch_adzuna,
        "muse": fetch_the_muse,
        "remotive": fetch_remotive,
    }

    results = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        future_to_name = {pool.submit(fn): name for name, fn in sources.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as e:
                log(f"Source '{name}' failed entirely: {e}")
                results[name] = []

    jobs = merge_and_dedupe(list(results.values()))

    # Output file
    output = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_jobs": len(jobs),
            "sources": {name: len(jobs_list) for name, jobs_list in results.items()},
        },
        "jobs": jobs,
    }

    out_path = Path("public/data/jobs.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start
    log(f"=== Done in {elapsed:.1f}s — wrote {len(jobs)} jobs to {out_path} ===")


if __name__ == "__main__":
    main()
