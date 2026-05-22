#!/usr/bin/env python3
import json
import time
import logging
import requests
from app import db
from app.models.apikey import APIKey

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SOCUrlInvestigator/1.0", "Accept": "application/json"})
        self.timeout = 30
        self.results = {}

    def _get_api_key(self, service_name):
        """Fetch API key from database."""
        try:
            entry = APIKey.query.filter_by(service=service_name, is_enabled=True).first()
            if entry and entry.api_key:
                return entry.api_key
        except Exception:
            pass
        return ""

    def check_virustotal(self, url):
        api_key = self._get_api_key("virustotal")
        if not api_key:
            self.results["virustotal"] = {"error": "No API key configured", "source": "virustotal"}
            return self.results["virustotal"]
        try:
            url_id = self._base64_url_encode(url)
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": api_key}
            resp = self.session.get(vt_url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                result = {
                    "source": "virustotal", "status": "completed",
                    "malicious": malicious, "suspicious": stats.get("suspicious", 0),
                    "total": total, "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attributes.get("reputation", 0),
                    "categories": attributes.get("categories", {}),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                }
                self.results["virustotal"] = result
                return result
            elif resp.status_code == 404:
                # Submit for scanning
                return self._submit_virustotal(url, api_key)
            else:
                result = {"source": "virustotal", "status": "error", "error": f"HTTP {resp.status_code}"}
                self.results["virustotal"] = result
                return result
        except Exception as e:
            result = {"source": "virustotal", "status": "error", "error": str(e)}
            self.results["virustotal"] = result
            return result

    def _submit_virustotal(self, url, api_key):
        try:
            headers = {"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"}
            resp = self.session.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                result = {"source": "virustotal", "status": "submitted", "message": "URL submitted for analysis"}
            else:
                result = {"source": "virustotal", "status": "error", "error": f"Submit failed: {resp.status_code}"}
            self.results["virustotal"] = result
            return result
        except Exception as e:
            result = {"source": "virustotal", "status": "error", "error": str(e)}
            self.results["virustotal"] = result
            return result

    def check_urlscan(self, url):
        api_key = self._get_api_key("urlscan")
        if not api_key:
            self.results["urlscan"] = {"error": "No API key configured", "source": "urlscan"}
            return self.results["urlscan"]
        try:
            search_url = "https://urlscan.io/api/v1/search/"
            params = {"q": f'page.url:"{url}"', "size": 1}
            headers = {"API-Key": api_key}
            resp = self.session.get(search_url, params=params, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    result = results[0]
                    verdict = result.get("verdicts", {}).get("overall", {})
                    page = result.get("page", {})
                    urlscan_result = {
                        "source": "urlscan", "status": "completed",
                        "has_result": True,
                        "malicious": verdict.get("malicious", False),
                        "score": verdict.get("score", 0),
                        "categories": page.get("categories", []),
                        "ip": page.get("ip"), "domain": page.get("domain"),
                        "country": page.get("country"), "asn": page.get("asn"),
                        "screenshot": result.get("screenshot"),
                        "permalink": result.get("task", {}).get("reportURL", ""),
                    }
                else:
                    urlscan_result = {"source": "urlscan", "status": "completed", "has_result": False}
                self.results["urlscan"] = urlscan_result
                return urlscan_result
            else:
                result = {"source": "urlscan", "status": "error", "error": f"HTTP {resp.status_code}"}
                self.results["urlscan"] = result
                return result
        except Exception as e:
            result = {"source": "urlscan", "status": "error", "error": str(e)}
            self.results["urlscan"] = result
            return result

    def check_abuseipdb(self, ip):
        api_key = self._get_api_key("abuseipdb")
        if not api_key:
            return {"error": "No API key configured", "source": "abuseipdb"}
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "source": "abuseipdb", "status": "completed",
                    "ip": data.get("ipAddress"),
                    "is_public": data.get("isPublic"),
                    "is_whitelisted": data.get("isWhitelisted"),
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                }
            else:
                return {"source": "abuseipdb", "status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"source": "abuseipdb", "status": "error", "error": str(e)}

    def aggregate(self, url, ips=[]):
        self.results = {}
        threats = []
        logger.info(f"Running threat intel for: {url[:60]}")
        vt = self.check_virustotal(url)
        if vt.get("source") == "virustotal":
            threats.append(vt)
        time.sleep(0.5)
        us = self.check_urlscan(url)
        if us.get("source") == "urlscan":
            threats.append(us)
        time.sleep(0.5)
        for ip in ips[:3]:
            ab = self.check_abuseipdb(ip)
            if ab.get("source") == "abuseipdb":
                threats.append(ab)
            time.sleep(0.5)
        return threats

    def _base64_url_encode(self, s):
        import base64
        return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
