import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from tracking_analyzer import domain_of, header_values, samesite_none_cookies, traffic_summary


class AnalyzerTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(domain_of("https://shop.example.co.uk/cart"), "example.co.uk")

    def test_header_matching_is_case_insensitive(self):
        self.assertEqual(header_values({"headers": [{"name": "cookie", "value": "a=1"}]}, "Cookie"), ["a=1"])

    def test_samesite_none_only(self):
        lines = ["id=demo; Secure; SameSite=None", "other=demo; SameSite=Lax"]
        self.assertEqual(list(samesite_none_cookies(lines, "example.com", "sample", 1)), [("id", "demo", "example.com")])

    def test_response_exclusion_applies_to_all_metrics(self):
        import json
        import tempfile
        def entry(status, url, headers=None, ip=None):
            return {"request": {"url": url, "method": "GET", "headers": []},
                    "response": {"status": status, "headers": headers or []},
                    "serverIPAddress": ip}
        har={"log": {"pages": [{"title": "https://example.com/"}], "entries": [
            entry(200, "https://example.com/", ip="192.0.2.1"),
            entry(0, "https://tracker.example.net/", [{"name":"Set-Cookie","value":"id=private; SameSite=None"}], "192.0.2.2"),
            entry(307, "https://tracker.example.net/", [{"name":"Non-Authoritative-Reason","value":"HSTS"}], "192.0.2.3")
        ]}}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"fixture.har"
            path.write_text(json.dumps(har))
            out=traffic_summary(path,{})
        self.assertEqual(out["num_requests"],1)
        self.assertEqual(out["server_ips"],["192.0.2.1"])
        self.assertEqual(out["potential_tracking_cookies"],[])
        self.assertEqual(out["num_responses_w_cookies"],0)

if __name__ == "__main__":
    unittest.main()
