# CyberRoadmap

A free, curated career resource for anyone trying to break into cybersecurity, IT, or infrastructure.

Live at: **[cyberroadmap.org](https://cyberroadmap.org)**

## What's Here

- **Jobs** — entry-level openings scraped from federal and commercial sources, refreshed every 6 hours
- **Certifications** *(in build)* — which certs actually get you hired
- **Training** *(in build)* — curated directory of free and paid hands-on platforms
- **Resources** *(in build)* — résumé templates, interview prep, scholarships, events, community

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  cyberroadmap.org                                    │
│  Static site on Azure Static Web Apps (free tier)    │
│  ├── index.html      Landing page                    │
│  ├── jobs.html       Search UI, client-side filter   │
│  ├── certs.html      Placeholder                     │
│  ├── training.html   Placeholder                     │
│  ├── resources.html  Placeholder                     │
│  └── data/jobs.json  Pre-scraped job data            │
└──────────────────────────────────────────────────────┘
                         ▲
                         │ (reads jobs.json from same origin)
                         │
┌──────────────────────────────────────────────────────┐
│  GitHub Actions (runs every 6 hours)                 │
│  .github/workflows/scrape-jobs.yml                   │
│  .github/scripts/scraper.py                          │
│  ├── Queries USAJobs, Adzuna, The Muse, Remotive     │
│  ├── Filters to entry-level                          │
│  ├── Tags with categories (Cyber, IT, Cloud, etc.)   │
│  ├── Deduplicates across sources                     │
│  └── Commits updated jobs.json back to repo          │
└──────────────────────────────────────────────────────┘
```

**Cost:** $0/month. Scraper runs in GitHub's free tier (2000 min/mo), hosting is Azure's always-free Static Web Apps, DNS and CDN are Cloudflare free.

## Directory Structure

```
.
├── .github/
│   ├── workflows/
│   │   └── scrape-jobs.yml    # Runs the scraper on a 6-hour schedule
│   └── scripts/
│       └── scraper.py         # The actual scraper logic
├── public/
│   ├── index.html             # Landing page
│   ├── jobs.html              # Job search UI
│   ├── certs.html             # Placeholder
│   ├── training.html          # Placeholder
│   ├── resources.html         # Placeholder
│   └── data/
│       └── jobs.json          # Pre-computed job data (auto-updated)
├── staticwebapp.config.json   # Azure Static Web Apps config
└── README.md                  # This file
```


## Required GitHub Secrets

The scraper needs API credentials stored as repository secrets. Set these at
**Settings → Secrets and variables → Actions**:

| Secret | Required? | Where to get it |
|--------|-----------|-----------------|
| `USAJOBS_API_KEY` | Yes (for federal jobs) | https://developer.usajobs.gov/apirequest/ |
| `USAJOBS_USER_EMAIL` | Yes | Your email address (required by USAJobs TOS) |
| `ADZUNA_APP_ID` | Yes (for bulk jobs) | https://developer.adzuna.com/signup |
| `ADZUNA_APP_KEY` | Yes | Same signup |
| `THE_MUSE_API_KEY` | Optional | https://www.themuse.com/developers/api/v2 |

Without the first four, the scraper will still run but return fewer results.
Remotive and The Muse work without keys (lower rate limits without Muse key).

## Running the Scraper Manually

Two ways:

**1. Via GitHub UI** — Go to **Actions → Scrape Jobs → Run workflow**.

**2. Locally** (for testing) —
```bash
export USAJOBS_API_KEY=xxx
export USAJOBS_USER_EMAIL=you@example.com
export ADZUNA_APP_ID=xxx
export ADZUNA_APP_KEY=xxx
python .github/scripts/scraper.py
```

Output lands at `public/data/jobs.json`.

## Adding New Job Sources

Each source is a function in `scraper.py` that returns a list of normalized job
dicts. To add one:

1. Write `fetch_yoursource()` following the pattern of existing fetchers.
2. Normalize to the shared schema (see any existing fetcher for the fields).
3. Add it to the `sources` dict in `main()`.
4. Done — GitHub Actions will pick it up on next run.

The normalized job schema:
```python
{
    "id": "prefix_uniqueid",
    "title": str,
    "company": str,
    "location": {
        "display": str,
        "city": str,
        "state": str,  # 2-letter
        "remote": bool,
    },
    "description": str,  # cleaned, ~300 chars
    "url": str,          # where to apply
    "posted": str,       # ISO 8601 date
    "salary_min": float | None,
    "salary_max": float | None,
    "source": str,       # human-readable
    "federal": bool,
    "categories": list[str],  # e.g., ["Cyber", "Cloud"]
    "fingerprint": str,  # for dedup
}
```

## Categories & Entry-Level Filtering

The scraper tags jobs with categories based on regex patterns in `CATEGORIES`.
A single job can belong to multiple categories (e.g., "Cloud Security Engineer"
→ `["Cyber", "Cloud"]`).

Entry-level filtering uses two passes:
1. **Positive signals** (entry-level, junior, intern, I, 0-2 years, etc.)
2. **Negative signals** (senior, lead, principal, 5+ years, architect, etc.)

If positive signals match → include. If negative signals match (and no positive)
→ exclude. Otherwise → include (ambiguous, let the student filter further).

## Development Notes

- **Client-side filtering** keeps the backend simple, but breaks down past ~20k
  jobs or so. When we get there, consider Azure Postgres + a search endpoint.
- **Geocoding** uses ZIP codes via the free [zippopotam.us](https://zippopotam.us)
  API. No rate limit issues at student-site scale.
- **Radius filtering** uses approximate state centroids as the fallback for job
  locations that aren't fully geocoded. This is coarse but adequate for a
  discovery tool. A proper production app would geocode every job during scraping.

## Contact

Built by Dr. Gregory A. Lindstrom — Professor and Department Chair of
Cybersecurity at Lone Star College.

- Website: [cyberroadmap.org](https://cyberroadmap.org)
- Email: hello@cyberroadmap.org

## License


All code in this repo is MIT licensed. See `LICENSE`.
The content (job descriptions, etc.) belongs to the original job posters.
