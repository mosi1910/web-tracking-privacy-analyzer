# Web Tracking & Privacy Analyzer

An offline Python tool for examining HTTP Archive (HAR) traffic and comparing how cookie-consent choices and browser ad blockers affect network requests and third-party tracking.

This project began as an Online Tracking and Privacy university assignment. The public version separates the reusable analysis code from private browser captures and publishes only aggregate metrics.

## What it measures

- HTTP requests and cross-domain HTTP redirects
- Requests with `Cookie` headers and responses with `Set-Cookie` headers
- Distinct third-party registrable domains (eTLD+1) and mapped organizations
- Distinct server IPs and POST destination domains
- Cookies returned with `SameSite=None`
- A six-panel chart comparing four browsing variants

The four variants are **accept**, **reject**, **uBlock Origin Lite**, and **AdGuard AdBlocker**, based on separate visits to a Dutch retail pharmacy website (kruidvat.nl).

## Public results

[`results/summary.json`](results/summary.json) contains aggregated counts from the original captures, without cookie values, IPs, or individual request URLs. They are observational results from four separate browser sessions, not a general effectiveness benchmark. Differences can also reflect dynamic site content, network conditions, and capture timing.

| Variant | HTTP requests | Third-party domains | Third-party entities |
| --- | ---: | ---: | ---: |
| accept | 529 | 33 | 27 |
| reject | 388 | 12 | 6 |
| ublock | 239 | 4 | 1 |
| adguard | 441 | 16 | 12 |

## Public report

[Read the illustrated analysis report (PDF)](report/tracking_privacy_analysis.pdf). It presents the six comparisons and documents the scope and limitations of this four-session observation. The public report omits the original student identifiers and raw network identifiers.

## Public report

[Read the illustrated analysis report (PDF)](report/tracking_privacy_analysis.pdf). It presents the six comparisons and documents the scope and limitations of this four-session observation. The public report omits the original student identifiers and raw network identifiers.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Run on your own local captures

Place four HAR files in a **private local directory**, named `<site>_accept.har`, `<site>_reject.har`, `<site>_ublock.har`, and `<site>_adguard.har`. You also need a local `domain_map.json` in the domain-data format described by the assignment (a mapping of registrable domains to records with `displayName`). The script makes no API calls; the domain map must be supplied locally.

```bash
python src/tracking_analyzer.py --data-dir /path/to/private-data --site kruidvat.nl --output-dir /path/to/private-output --plot
```

This writes detailed per-variant JSON results and `plots.png` to the specified output directory. **Do not commit those detailed outputs without reviewing and removing sensitive fields.** For reproducibility, use the same capture procedure and map snapshot; browsing is inherently dynamic and counts may differ.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Technical notes and limitations

- The script computes registrable domains with `tldextract` and uses a locally supplied domain-to-entity map.
- `potential_tracking_cookies` is a heuristic: `SameSite=None` allows cross-site cookie use in some settings, but does **not** prove that a cookie is used for tracking.
- It skips requests with HTTP status 0 (no server response) and synthetic 307 redirects marked by `Non-Authoritative-Reason` before computing summary metrics.
- The HAR page title is expected to contain the first-party website URL; captures that do not follow this layout require adaptation.
- This is an observational analysis tool, not a security scanner or a full privacy audit.

## Security and privacy

Original HAR files were exported with sensitive headers and must **not** be published: they may expose session cookies, authorization headers, browser identifiers, query parameters, and personal data. Detailed per-request JSON exports can include cookie values. `.gitignore` excludes these by default. The published aggregate results do not include raw URLs, cookie values, or IP addresses.
