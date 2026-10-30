import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import matplotlib
import tldextract

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# offline accessibility
psl_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def read_export(path):
    with open(path, encoding="utf-8-sig") as src:
        return json.load(src)


def domain_of(url):
    if not isinstance(url, str):
        raise ValueError("A URL should be text.")
    host = urlsplit(url).hostname or ""
    return psl_extract(host).top_domain_under_public_suffix


def header_values(msg, wanted):
    wanted = wanted.lower()
    found = []
    headers = msg.get("headers")
    if headers is None:
        return found
    if not isinstance(headers, list):
        raise ValueError("The headers should be a list.")
    for hdr in headers:
        if not isinstance(hdr, dict):
            raise ValueError("Bad header entry in the HAR file.")
        name = hdr.get("name")
        value = hdr.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("A header needs a text name and value.")
        if name.lower() == wanted and value.strip():
            found.append(value)
    return found


def samesite_none_cookies(cookie_lines, req_site, source_name, row):
    if not req_site:
        return

    for line in cookie_lines:
        parts = line.split(";")
        attrs = (attr.partition("=") for attr in parts[1:])
        allows_cross_site = any(
            key.strip().lower() == "samesite"
            and value.strip().strip('"').lower() == "none"
            for key, _, value in attrs
        )
        if not allows_cross_site:
            continue

        name, equal_sign, val = parts[0].partition("=")
        if not equal_sign:
            note = f"{source_name}: skipping a bad cookie at entry {row}"
            print(note, file=sys.stderr)
            continue
        yield name.strip(), val.strip().strip('"'), req_site


def traffic_summary(har_file, owner_map):
    har_file = Path(har_file)
    har = read_export(har_file)
    log = har.get("log") if isinstance(har, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise ValueError("This file needs a HAR log.entries list.")

    entries = log["entries"]
    pages = log.get("pages")
    if not isinstance(pages, list) or not pages or not isinstance(pages[0], dict):
        raise ValueError("The first-party domain needs log.pages[0].")
    visited_domain = domain_of(pages[0].get("title"))
    if not visited_domain:
        raise ValueError("log.pages[0].title should contain the website URL.")

    num_requests = 0
    redirects = 0
    cookie_sends = 0
    cookie_responses = 0
    outside_domains = set()
    ips = set()
    cookie_candidates = set()
    post_targets = set()

    for row, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Entry {row} should be an object.")
        req = entry.get("request")
        resp = entry.get("response")
        if not isinstance(req, dict) or not isinstance(resp, dict):
            raise ValueError(f"Entry {row} needs a request and response.")
        if not isinstance(req.get("url"), str) or not isinstance(req.get("method"), str):
            raise ValueError(f"Entry {row} needs a request URL and method.")
        req_site = domain_of(req["url"])
        status = resp.get("status")
        if type(status) is not int:
            raise ValueError(f"entry {row} has an invalid HTTP status")

        # A blocked request has no server response. Chrome may record some
        # internal browser redirects as synthetic 307 responses.
        if status == 0:
            continue
        if status == 307 and header_values(resp, "Non-Authoritative-Reason"):
            continue

        if 300 <= status < 400:
            destination = resp.get("redirectURL") or ""
            if not isinstance(destination, str):
                raise ValueError(f"Bad redirect URL in entry {row}.")
            if not destination:
                redirect_headers = header_values(resp, "Location")
                destination = redirect_headers[0] if redirect_headers else ""

            next_url = urljoin(req["url"], destination) if destination else ""
            next_site = ""
            if next_url and req_site and not next_url.startswith("chrome-extension"):
                next_site = domain_of(next_url)
            if next_site and next_site != req_site:
                redirects += 1

        set_cookies = header_values(resp, "Set-Cookie")
        if set_cookies:
            cookie_responses += 1

        cookie_candidates.update(
            samesite_none_cookies(set_cookies, req_site, har_file.name, row)
        )

        ip = entry.get("serverIPAddress")
        if ip:
            if not isinstance(ip, str):
                raise ValueError(f"Bad server IP in entry {row}.")
            ips.add(ip)

        num_requests += 1
        if header_values(req, "Cookie"):
            cookie_sends += 1
        if req_site and req_site != visited_domain:
            outside_domains.add(req_site)
        if req_site and req["method"] == "POST":
            post_targets.add(req_site)

    companies = set()
    for domain in outside_domains:
        record = owner_map.get(domain)
        if record is None:
            continue
        if not isinstance(record, dict):
            raise ValueError(f"Bad owner record for {domain} in the domain map.")
        owner = record.get("displayName")
        if owner is not None and not isinstance(owner, str):
            raise ValueError(f"Bad owner name for {domain} in the domain map.")
        if owner:
            companies.add(owner)

    return {
        "num_requests": num_requests,
        "num_cross_domain_redirections": redirects,
        "num_requests_w_cookies": cookie_sends,
        "num_responses_w_cookies": cookie_responses,
        "third_party_domains": sorted(outside_domains),
        "server_ips": sorted(ips),
        "potential_tracking_cookies": sorted(cookie_candidates),
        "third_party_entities": sorted(companies),
        "post_request_origins": sorted(post_targets),
    }


def draw_charts(json_files, modes, png_path):
    reports = [read_export(path) for path in json_files]
    fields = [
        "num_requests",
        "third_party_domains",
        "third_party_entities",
        "num_cross_domain_redirections",
        "server_ips",
        "potential_tracking_cookies",
    ]

    fig, panels = plt.subplots(3, 2, figsize=(10, 10))
    for chart, field in zip(panels.flat, fields):
        bars = []
        for report in reports:
            value = report[field]
            bars.append(len(value) if isinstance(value, list) else value)

        chart.bar(modes, bars)
        caption = "Number of " + field.replace("num_", "").replace("_", " ")
        chart.set_title(caption, fontsize=10)
        chart.set_xlabel("Variant")
        chart.set_ylabel("Count")

    fig.tight_layout()
    fig.savefig(png_path, dpi=150)
    plt.close(fig)


def run_comparison(argv=None):
    cli = argparse.ArgumentParser(
        description="Compare cookies and third-party requests in the HAR files."
    )
    cli.add_argument(
        "--data-dir", type=Path, default=Path(__file__).resolve().parent,
        help="Folder with the HAR files (default: this script's folder).",
    )
    cli.add_argument(
        "--site", default="kruidvat.nl",
        help="Filename prefix, e.g. kruidvat.nl.",
    )
    cli.add_argument(
        "--variants", nargs="+", default=["accept", "reject", "ublock", "adguard"],
        help="Capture names (default: accept reject ublock adguard).",
    )
    cli.add_argument(
        "--domain-map", type=Path,
        help="Path to the domain-owner JSON file.",
    )
    cli.add_argument(
        "--output-dir", type=Path,
        help="Where to save the JSON files and any requested plot.",
    )
    cli.add_argument(
        "--plot", action="store_true",
        help="Also save the comparison charts to plots.png.",
    )
    args = cli.parse_args(argv)

    data_dir = args.data_dir.expanduser()
    out_dir = (args.output_dir or data_dir).expanduser()
    map_file = (args.domain_map or data_dir / "domain_map.json").expanduser()

    current_file = map_file
    reports = []
    try:
        owner_map = read_export(current_file)
        if not isinstance(owner_map, dict):
            raise ValueError("The domain map should be a dictionary.")

        for variant in args.variants:
            current_file = data_dir / f"{args.site}_{variant}.har"
            stats = traffic_summary(current_file, owner_map)
            reports.append(stats)
            print(
                f"{current_file.name}: {stats['num_requests']} requests, "
                f"{len(stats['third_party_domains'])} third-party domains"
            )
    except (OSError, ValueError) as err:
        print(f"Can't read {current_file}: {err}", file=sys.stderr)
        return 1

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        json_files = []
        for variant, stats in zip(args.variants, reports):
            json_path = out_dir / f"{args.site}_{variant}.json"
            with json_path.open("w", encoding="utf-8") as output:
                json.dump(stats, output, indent=2)
            json_files.append(json_path)
        if args.plot:
            draw_charts(json_files, args.variants, out_dir / "plots.png")
    except (OSError, ValueError) as err:
        print(f"Can't save files in {out_dir}: {err}", file=sys.stderr)
        return 1

    print(f"Done. Saved the JSON files in {out_dir}.")
    if args.plot:
        print(f"Saved the charts to {out_dir / 'plots.png'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_comparison())
