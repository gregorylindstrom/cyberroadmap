# CyberRoadmap Security Review — July 2026

Scope: all site HTML/JS, the jobs data pipeline design, the GitHub Actions
workflow, and the local test tooling. The scraper (`scraper.py`) was NOT in
this review — see Residual Risks.

## Threat model (what actually matters here)
Static site, no auth, no user accounts, no server-side code, no stored user
data. The realistic attack surfaces are:
1. **Untrusted data injection** — jobs.json is built from six external APIs.
   A malicious or compromised job posting is attacker-controlled input that
   your site renders for every visitor.
2. **Supply chain** — GitHub Actions, PyPI, Google Fonts.
3. **Credential handling** — API keys/tokens (the issue we already hit).

## Findings and dispositions

### PASS — output encoding on external data (the big one)
`jobs.html` renders every API-derived field (title, company, location,
description, tags, source) via `textContent`, never string-interpolated
into `innerHTML`. The `innerHTML` templates contain only static markup.
This was verified line-by-line. A hostile `<script>` in a job title renders
as inert text. This is the control that matters most, and it was done right.

### FIXED — URL scheme injection (medium)
`card.href = job.url` accepted any string, so a `javascript:` or `data:`
URI supplied by a job source would execute on click. Now allowlisted to
`http(s)://` only; anything else becomes an inert `#`.

### FIXED — error-message reflection (low)
The jobs-load `catch` block interpolated `e.message` into `innerHTML`.
`JSON.parse` error messages quote fragments of the parsed input, so a
tampered response could reflect markup into the page (requires hosting/CDN
compromise, so low likelihood — but the fix costs nothing). Now rendered
via `textContent`.

### FIXED — missing security headers (medium)
No CSP, XCTO, or frame protections existed. `staticwebapp.config.json`
now sets: a Content-Security-Policy (self + Google Fonts + zippopotam
geocoding only, `frame-ancestors 'none'`, `object-src 'none'`),
X-Content-Type-Options, X-Frame-Options, Referrer-Policy, a restrictive
Permissions-Policy, and COOP. Deploy note: your Azure workflow sets
`app_location: "/public"`, so this file MUST go at `public/staticwebapp.config.json`
(next to index.html) or Azure will ignore it. If headers still don't appear,
the Cloudflare layer in front may need them set via a Transform Rule instead. Verify at securityheaders.com.

CSP honesty note: because all pages use inline `<script>` blocks,
`script-src` must include `'unsafe-inline'`, which weakens CSP's XSS
protection. It still blocks external script loads, framing, and plugin
content. Full strictness would require moving JS to external files with
hashes — reasonable future work, not urgent given the output-encoding
discipline above.

### PASS — link hygiene
All `target="_blank"` links carry `rel="noopener"` (job cards also
`noreferrer`). Scholarship/academy card data is author-controlled static
content.

### PASS / already fixed — credential handling
- GitHub secrets used for all six API sources; nothing in client code.
- Fine-grained PAT scoped to one repo, Contents read/write only.
- Local test script now env-var/.env based (`careeronestop_test.py`).
- Old inline-token `Cyberroadmap.py` scheduled for deletion + token rotation
  (DEPLOY.md step 1).

### PASS with note — third-party dependencies
- Google Fonts: standard practice; can't use SRI on their CSS. Optional
  hardening: self-host the two font families (also a small speed win).
- `api.zippopotam.us`: receives only a user-typed ZIP over HTTPS. Minimal
  exposure; now the only non-self entry in `connect-src`.
- No third-party JS libraries at all — genuinely small supply chain.

### NOTE — workflow hardening (optional)
- `pip install requests` is unpinned; pin (`requests==2.32.x`) for
  reproducibility.
- Actions are tag-pinned (`@v4`/`@v5`); SHA-pinning is the stricter
  standard if you want it.
- Runner is ephemeral, so PAT persistence in the checkout is acceptable.

## scraper.py — audited July 2026 (gap now closed)
- **PASS**: all 7 HTTP calls carry explicit timeouts (8–30s)
- **PASS**: no credentials in any log/print statement
- **PASS**: descriptions already HTML-stripped via `clean_description()`
- **FIXED**: titles, companies, locations, and categories passed through
  raw, and URLs were never scheme-validated (the origin of the
  `javascript:` URI vector fixed client-side). Added `sanitize_job()` —
  applied once post-dedup in `merge_and_dedupe()`, covering all six
  sources: strips markup and control characters, caps lengths, and
  rejects non-http(s) URLs. Unit-tested: hostile input neutralized,
  clean input passes through unchanged.
- Note: `THE_MUSE_API_KEY` exists in the workflow env but no Muse source
  exists in the scraper — vestigial, harmless, remove at leisure.

## Residual risks
1. **Hosting/CDN account security** — the site is only as safe as the
   Azure + GitHub + Cloudflare + registrar accounts behind it. Hardware-key
   MFA on all four is worth more than everything else in this document.
2. **jobs.json integrity** — anyone who can push to the repo can change
   site data. Branch protection on main (require PR for non-bot changes)
   is the cheap control if collaborators are ever added.

## Verification checklist after deploy
- [ ] securityheaders.com scan shows A grade (or headers visible in DevTools)
- [ ] A job card link with a bad URL renders as '#' (test by temporarily
      editing one entry in jobs.json locally)
- [ ] Mozilla Observatory scan: https://observatory.mozilla.org
- [ ] Rotated CareerOneStop token works (run careeronestop_test.py)

