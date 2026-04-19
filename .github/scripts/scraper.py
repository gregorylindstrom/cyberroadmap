#!/usr/bin/env python3
"""
CyberRoadmap Jobs Scraper v2
============================
Pulls entry-level cyber/IT/infrastructure/cloud/AI/data jobs from multiple
public APIs, aggressively filters noise, auto-categorizes, deduplicates, and
writes the result to public/data/jobs.json.

Major improvements over v1:
    - Non-federal jobs MUST match at least one tech category (excludes lifeguards, nurses, etc.)
    - Stronger entry-level filters (more senior patterns, salary cap, title blocklist)
    - 3-4x more search queries per source for better coverage
    - Broader AI/ML search terms (was underrepresented)
    - Deeper pagination on Adzuna (4 pages instead of 2)
    - Fixed The Muse category matching (was returning 2 jobs instead of ~100)
    - Salary-based filter: non-federal salary_min > $130K = excluded (senior)

Sources:
    - USAJobs (federal)
    - Adzuna (nationwide aggregator)
    - The Muse (tech-focused)
    - Remotive (remote-only)
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

# Category regex patterns. A job can belong to multiple categories.
CATEGORIES = {
    "Cyber": [
        r"\bcyber(security|\s+security)?\b", r"\binfosec\b",
        r"\binformation\s+security\b",
        r"\bsecurity\s+(analyst|engineer|architect|consultant|specialist|administrator|operations|intern|associate)\b",
        r"\bSOC\b", r"\bpen\s*test", r"\bpenetration\b", r"\bethical\s+hack",
        r"\bvulnerability\b", r"\bthreat\b", r"\bincident\s+response\b",
        r"\bGRC\b", r"\bgovernance.{0,20}risk.{0,20}compliance\b",
        r"\bCISSP\b", r"\bCISM\b", r"\bOSCP\b", r"\bSecurity\+\b",
        r"\bred\s+team\b", r"\bblue\s+team\b", r"\bpurple\s+team\b",
        r"\bmalware\b", r"\bforensic", r"\bCMMC\b", r"\bNIST\s+800\b",
        r"\bIAM\b", r"\bidentity\s+access\b", r"\bzero\s+trust\b",
        r"\bfirewall\s+(engineer|admin)\b",
        r"\b(junior|associate|entry)\s+(security|cyber)\b",
        r"\brisk\s+(analyst|assessor|specialist)\b.*(security|cyber|it)",
        r"\bcompliance\s+(analyst|specialist).*(cyber|security|information)",
    ],
    "IT": [
        r"\bIT\s+(support|analyst|specialist|technician|admin|helpdesk|associate|intern)",
        r"\bhelp\s*desk\b", r"\bservice\s*desk\b", r"\bdesktop\s+support\b",
        r"\btechnical\s+support\s+(specialist|analyst|engineer|technician)",
        r"\bsystems?\s+(admin|administrator|engineer|analyst)\b",
        r"\bsysadmin\b",
        r"\bnetwork\s+(admin|engineer|technician|analyst|specialist|administrator)\b",
        r"\bA\+\b", r"\bNetwork\+\b", r"\bCCNA\b",
        r"\bIT\s+(intern|trainee|associate)\b",
        r"\binformation\s+technology\s+(specialist|support|analyst)\b",
    ],
    "Infrastructure": [
        r"\binfrastructure\s+(engineer|analyst|administrator|specialist|intern)\b",
        r"\bdevops\b", r"\bSRE\b", r"\bsite\s+reliability\b",
        r"\bplatform\s+engineer", r"\bkubernetes\b",
        r"\bdocker\b", r"\bterraform\b", r"\bansible\b",
        r"\bCI/CD\b", r"\bcontinuous\s+(integration|deployment)\b",
    ],
    "Cloud": [
        r"\bcloud\s+(engineer|architect|administrator|analyst|specialist|developer|intern|associate)\b",
        r"\bAWS\s+(engineer|developer|architect|associate|intern)\b",
        r"\bAzure\s+(engineer|developer|architect|associate|intern|administrator)\b",
        r"\bGCP\s+(engineer|developer|architect)\b",
        r"\bgoogle\s+cloud\s+(engineer|platform)\b",
        r"\bcloud\s+security\b", r"\bcloud\s+operations\b",
    ],
    "AI/ML": [
        r"\b(AI|artificial\s+intelligence)\s+(engineer|developer|specialist|analyst|intern|associate|researcher)\b",
        r"\bmachine\s+learning\s+(engineer|scientist|analyst|developer|intern|associate|researcher)\b",
        r"\bML\s+(engineer|ops|intern|associate)\b",
        r"\bdata\s+scientist\b", r"\bMLOps\b",
        r"\bLLM\s+(engineer|researcher)\b", r"\bprompt\s+engineer",
        r"\bapplied\s+AI\b", r"\bAI\s+researcher\b",
        r"\bcomputer\s+vision\s+(engineer|researcher)\b",
        r"\bNLP\s+(engineer|researcher|scientist)\b",
    ],
    "Data": [
        r"\bdata\s+(analyst|engineer|architect|developer|intern|associate|specialist)\b",
        r"\bETL\s+(developer|engineer)\b", r"\bdatabase\s+admin",
        r"\bDBA\b", r"\bpower\s*BI\s+(developer|analyst)\b",
        r"\btableau\s+(developer|analyst)\b", r"\bsnowflake\s+developer\b",
        r"\bbusiness\s+intelligence\s+(analyst|developer|engineer|intern)\b",
        r"\bBI\s+(analyst|developer|engineer)\b",
        r"\bSQL\s+(developer|analyst)\b",
    ],
    "Software": [
        r"\bsoftware\s+(engineer|developer|intern|associate)\b",
        r"\bweb\s+(developer|engineer)\b",
        r"\b(full|fullstack)\s*stack\s+(developer|engineer)\b",
        r"\b(front|frontend)\s*end\s+(developer|engineer)\b",
        r"\b(back|backend)\s*end\s+(developer|engineer)\b",
        r"\bpython\s+developer\b", r"\bjava\s+developer\b",
        r"\bjunior\s+(developer|programmer|engineer)\b",
        r"\bapplication\s+developer\b", r"\bmobile\s+developer\b",
        r"\biOS\s+developer\b", r"\bandroid\s+developer\b",
    ],
}

# Entry-level indicators
ENTRY_LEVEL_POSITIVE = [
    r"\bentry\s*level\b", r"\bjunior\b", r"\bassociate\b",
    r"\bintern(ship)?\b", r"\btrainee\b", r"\bgraduate\b",
    r"\bnew\s+grad", r"\bearly\s+career\b", r"\bapprentice\b",
    r"\bjr\.?\b", r"\btier\s+1\b", r"\blevel\s+[1I]\b",
    r"\b0[-\s]?[123]\s+years\b", r"\b1[-\s]?2\s+years\b",
    r"\bno\s+experience\s+required\b",
]

SENIOR_NEGATIVE = [
    r"\bsenior\b", r"\bsr\.?\b", r"\blead\b", r"\bprincipal\b",
    r"\bstaff\s+(engineer|developer|analyst)\b",
    r"\barchitect\b", r"\bmanager\b", r"\bdirector\b",
    r"\b(5|6|7|8|9|10|12|15|20)\+?\s+years\b",
    r"\bexpert\b", r"\bhead\s+of\b", r"\bVP\b", r"\bchief\b",
    r"\bfellow\b", r"\bdistinguished\b",
    r"\btech\s+lead\b", r"\bteam\s+lead\b",
    r"\b(minimum|at\s+least)\s+(4|5|6|7|8|10)\s+years\b",
]

# Aggressive blocklist - titles that clearly aren't tech jobs even if
# Adzuna surfaces them for "entry level" searches
TITLE_BLOCKLIST = [
    r"\blifeguard\b", r"\bnurse\b", r"\bCNA\b",
    r"\bmedical\s+(assistant|technician|receptionist)\b",
    r"\bdental\s+(assistant|hygienist)\b",
    r"\bwarehouse\s+(associate|worker|clerk)\b",
    r"\bretail\s+(associate|clerk|manager)\b",
    r"\bcashier\b", r"\bserver\b", r"\bbartender\b",
    r"\bhousekeep", r"\bjanitor\b", r"\bcustodian\b",
    r"\bdriver\b(?!.*software)", r"\btruck\b",
    r"\bsales\s+(associate|representative)\b(?!.*tech)",
    r"\bteacher\b(?!.*(computer|technology|coding))",
    r"\bpharmacy\s+tech", r"\bphysical\s+therap",
    r"\breceptionist\b", r"\bmachine\s+operator\b",
    r"\bforklift\b", r"\bcook\b", r"\bchef\b",
    r"\bhair\s+stylist\b", r"\bbarber\b",
    r"\bmassage\s+therapist\b", r"\bcounselor\b",
    r"\bcase\s+manager\b", r"\bsocial\s+worker\b",
    r"\bconstruction\s+(worker|laborer)\b", r"\bplumber\b",
    r"\belectrician\b(?!.*(industrial|controls|electronics\s+tech))",
    r"\bmechanic\b(?!.*(software|aircraft.*systems))",
    r"\bassembler\b", r"\bfabricator\b",
    r"\bwelder\b", r"\bmaintenance\s+(worker|technician)\b(?!.*(IT|systems|server))",
]


# --- Utility functions -----------------------------------------------------

def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def fingerprint(title: str, company: str, location: str) -> str:
    normalized = f"{title.lower().strip()}|{company.lower().strip()}|{location.lower().strip()[:20]}"
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


def categorize(title: str, description: str = "") -> list[str]:
    text = f"{title} {description[:800]}".lower()
    matches = []
    for cat, patterns in CATEGORIES.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(cat)
                break
    return matches


def is_blocklisted(title: str) -> bool:
    """Is this a title we know is NOT a tech job despite keyword matches?"""
    for pattern in TITLE_BLOCKLIST:
        if re.search(pattern, title, re.IGNORECASE):
            return True
    return False


def is_entry_level(title: str, description: str = "") -> bool:
    combined = f"{title} {description[:1500]}".lower()

    # Strong positive signal
    for pattern in ENTRY_LEVEL_POSITIVE:
        if re.search(pattern, combined, re.IGNORECASE):
            return True

    # Strong negative signal
    for pattern in SENIOR_NEGATIVE:
        if re.search(pattern, combined, re.IGNORECASE):
            return False

    # Ambiguous — default to including (user can filter further)
    return True


def clean_description(text: str, max_len: int = 300) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


def parse_location(loc: str) -> dict:
    if not loc:
        return {"display": "Location not specified", "city": "", "state": "", "remote": False}

    display = loc.strip()
    remote = bool(re.search(r"\bremote\b|\banywhere\b|\btelework\b", display, re.IGNORECASE))

    match = re.search(r"([A-Za-z .\-]+),\s*([A-Z]{2})\b", display)
    if match:
        return {
            "display": display,
            "city": match.group(1).strip(),
            "state": match.group(2).strip(),
            "remote": remote,
        }

    return {"display": display, "city": "", "state": "", "remote": remote}


def passes_tech_filter(job: dict, is_federal: bool) -> bool:
    """
    Unified filter for whether to include a job.
    Federal jobs are more lenient; private-sector jobs must clearly be tech.
    """
    title = job.get("title", "")
    desc = job.get("description", "")

    # 1. Hard blocklist - never include these regardless of source
    if is_blocklisted(title):
        return False

    # 2. Entry-level check
    if not is_entry_level(title, desc):
        return False

    # 3. Non-federal salary cap: if min salary > $130K, likely senior
    if not is_federal:
        sal_min = job.get("salary_min")
        if sal_min and sal_min > 130000:
            return False

    # 4. Non-federal MUST match at least one tech category
    if not is_federal:
        cats = job.get("categories", [])
        if not cats:
            return False

    return True


# --- Source adapters -------------------------------------------------------

def fetch_usajobs() -> list[dict]:
    """Federal jobs via USAJobs API."""
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

    # Broader federal tech terms — USAJobs uses occupational series heavily
    search_terms = [
        "cybersecurity", "information security", "cyber analyst",
        "IT specialist", "information technology",
        "network engineer", "systems administrator",
        "software developer", "software engineer",
        "data analyst", "data scientist",
        "cloud engineer", "cloud architect",
        "security analyst", "security engineer",
        "information security analyst",
        "computer scientist", "computer engineer",
    ]

    all_jobs = []
    seen_ids = set()

    for term in search_terms:
        for page in [1, 2]:  # 2 pages per term for more coverage
            try:
                params = {
                    "Keyword": term,
                    "ResultsPerPage": 100,
                    "Page": page,
                }
                r = requests.get(
                    "https://data.usajobs.gov/api/search",
                    headers=headers, params=params, timeout=20,
                )
                r.raise_for_status()
                data = r.json()

                items = data.get("SearchResult", {}).get("SearchResultItems", [])
                if not items:
                    break  # no more pages

                for item in items:
                    descr = item.get("MatchedObjectDescriptor", {})
                    job_id = descr.get("PositionID", "")
                    if job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)

                    title = descr.get("PositionTitle", "")
                    summary = descr.get("UserArea", {}).get("Details", {}).get("JobSummary", "") \
                              or descr.get("QualificationSummary", "")

                    locations = descr.get("PositionLocation", [])
                    loc_str = locations[0].get("LocationName", "") if locations else ""
                    loc = parse_location(loc_str)

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

                    if passes_tech_filter(job, is_federal=True):
                        all_jobs.append(job)
                time.sleep(0.3)
            except Exception as e:
                log(f"USAJobs error on '{term}' page {page}: {e}")
                break

    log(f"USAJobs: {len(all_jobs)} jobs")
    return all_jobs


def fetch_adzuna() -> list[dict]:
    """Adzuna — nationwide aggregator."""
    app_id = os.environ.get("ADZUNA_APP_ID")
    app_key = os.environ.get("ADZUNA_APP_KEY")

    if not app_id or not app_key:
        log("Adzuna: missing credentials, skipping")
        return []

    log("Adzuna: fetching...")
    all_jobs = []
    seen_ids = set()

    # Broader search terms organized by category
    search_terms = [
        # Cyber
        "entry level cybersecurity", "junior security analyst",
        "security operations analyst", "SOC analyst",
        "cybersecurity intern", "junior cybersecurity engineer",
        "information security analyst",
        # IT
        "entry level IT support", "help desk analyst",
        "IT support specialist", "junior systems administrator",
        "desktop support technician", "IT technician",
        # Network/Infrastructure
        "junior network engineer", "network administrator",
        "junior devops engineer", "devops intern",
        # Cloud
        "entry level cloud engineer", "junior cloud engineer",
        "AWS associate", "Azure associate",
        # Data
        "junior data analyst", "entry level data analyst",
        "junior data engineer", "business intelligence analyst",
        # AI/ML
        "junior machine learning engineer", "machine learning intern",
        "entry level AI engineer", "junior data scientist",
        "ML engineer intern",
        # Software
        "junior software engineer", "junior developer",
        "entry level software engineer", "junior web developer",
        "software engineer intern", "associate software engineer",
    ]

    for term in search_terms:
        for page in range(1, 5):  # 4 pages per term
            try:
                url = f"https://api.adzuna.com/v1/api/jobs/us/search/{page}"
                params = {
                    "app_id": app_id, "app_key": app_key,
                    "what": term, "results_per_page": 50,
                    "max_days_old": 30, "sort_by": "date",
                }
                r = requests.get(url, params=params, timeout=20)
                r.raise_for_status()
                data = r.json()

                items = data.get("results", [])
                if not items:
                    break  # no more pages for this term

                for item in items:
                    job_id = str(item.get("id", ""))
                    if job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)

                    title = item.get("title", "")
                    desc = item.get("description", "")

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
                        "fingerprint": fingerprint(
                            title,
                            item.get("company", {}).get("display_name", ""),
                            loc["display"],
                        ),
                    }

                    if passes_tech_filter(job, is_federal=False):
                        all_jobs.append(job)
                time.sleep(0.3)
            except Exception as e:
                log(f"Adzuna error on '{term}' page {page}: {e}")
                break

    log(f"Adzuna: {len(all_jobs)} jobs")
    return all_jobs


def fetch_the_muse() -> list[dict]:
    """
    The Muse — strong on entry-level tech.
    FIX v2: Use broader categories AND no category (to catch more), and apply
    our own category filter post-fetch.
    """
    log("The Muse: fetching...")
    all_jobs = []
    seen_ids = set()

    # The Muse categories that contain tech jobs
    muse_categories = [
        "Data and Analytics", "Data Science",
        "Software Engineering", "Software Engineer",
        "Engineering", "IT",
        "Information Technology", "Computer & IT",
        "DevOps", "Cybersecurity",
        "Cloud", "Cloud Architecture",
    ]

    levels = ["Entry Level", "Internship"]

    for cat in muse_categories:
        for level in levels:
            for page in range(1, 5):  # 4 pages per combination
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
                        params=params, timeout=20,
                    )
                    r.raise_for_status()
                    data = r.json()

                    items = data.get("results", [])
                    if not items:
                        break

                    for item in items:
                        job_id = str(item.get("id", ""))
                        if job_id in seen_ids:
                            continue
                        seen_ids.add(job_id)

                        title = item.get("name", "")
                        desc = item.get("contents", "")

                        locs = item.get("locations", [])
                        loc_str = locs[0].get("name", "") if locs else ""
                        loc = parse_location(loc_str)

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
                            "categories": categorize(title, desc),
                            "fingerprint": fingerprint(
                                title,
                                item.get("company", {}).get("name", ""),
                                loc_str,
                            ),
                        }

                        if passes_tech_filter(job, is_federal=False):
                            all_jobs.append(job)

                    time.sleep(0.3)
                except Exception as e:
                    log(f"The Muse error on {cat}/{level} page {page}: {e}")
                    break

    log(f"The Muse: {len(all_jobs)} jobs")
    return all_jobs


def fetch_remotive() -> list[dict]:
    """Remotive — all remote jobs."""
    log("Remotive: fetching...")
    all_jobs = []

    # Broader category list
    categories = [
        "software-dev", "devops", "data",
        "qa", "product", "design", "all-others",
    ]

    seen_ids = set()
    for cat in categories:
        try:
            r = requests.get(
                "https://remotive.com/api/remote-jobs",
                params={"category": cat, "limit": 200},
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

                job = {
                    "id": f"remotive_{job_id}",
                    "title": title,
                    "company": item.get("company_name", "Unknown"),
                    "location": {
                        "display": "Remote",
                        "city": "", "state": "", "remote": True,
                    },
                    "description": clean_description(desc),
                    "url": item.get("url", ""),
                    "posted": item.get("publication_date", ""),
                    "salary_min": None,
                    "salary_max": None,
                    "source": "Remotive",
                    "federal": False,
                    "categories": categorize(title, desc),
                    "fingerprint": fingerprint(
                        title, item.get("company_name", ""), "remote",
                    ),
                }

                if passes_tech_filter(job, is_federal=False):
                    all_jobs.append(job)
            time.sleep(0.3)
        except Exception as e:
            log(f"Remotive error on '{cat}': {e}")

    log(f"Remotive: {len(all_jobs)} jobs")
    return all_jobs


# --- Main ------------------------------------------------------------------

def merge_and_dedupe(jobs_lists: list[list[dict]]) -> list[dict]:
    all_jobs = []
    for jobs in jobs_lists:
        all_jobs.extend(jobs)

    log(f"Pre-dedup total: {len(all_jobs)}")

    seen = {}
    for job in all_jobs:
        fp = job["fingerprint"]
        if fp not in seen:
            seen[fp] = job

    deduped = list(seen.values())
    log(f"Post-dedup total: {len(deduped)}")

    def sort_key(j):
        return j.get("posted") or ""
    deduped.sort(key=sort_key, reverse=True)

    return deduped


def main():
    start = time.time()
    log("=== CyberRoadmap scraper v2 starting ===")

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

    # Category summary
    cat_counts = {}
    for j in jobs:
        for c in j["categories"]:
            cat_counts[c] = cat_counts.get(c, 0) + 1
    log(f"Categories: {cat_counts}")

    fed_count = sum(1 for j in jobs if j.get("federal"))
    log(f"Federal jobs: {fed_count} / Non-federal: {len(jobs) - fed_count}")

    output = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_jobs": len(jobs),
            "sources": {name: len(jobs_list) for name, jobs_list in results.items()},
            "categories": cat_counts,
            "federal_count": fed_count,
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
