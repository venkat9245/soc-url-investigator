#!/usr/bin/env python3
import re
import json
import math
import base64
import logging
import tldextract
import dns.resolver
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

class URLAnalyzer:
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
        ".bid", ".date", ".trade", ".webcam", ".men", ".loan", ".click",
        ".download", ".review", ".party", ".racing", ".win", ".stream",
    }
    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "verify", "update", "confirm", "account",
        "secure", "banking", "paypal", "amazon", "apple", "microsoft",
        "google", "dropbox", "password", "credential", "2fa", "mfa",
        "invoice", "payment", "shipment", "tracking", "refund",
        "download", "setup", "installer", "update", "plugin",
        "free", "prize", "winner", "lottery", "gift",
    ]
    SUSPICIOUS_PATTERNS = [
        r'(?:eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(',
        r'(?:base64_decode|gzinflate|str_rot13)\s*\(',
        r'(?:<script|javascript:|onerror=|onload=|onclick=)',
        r'(?:../../|..\\..\\|%2e%2e%2f|%252e%252e%252f)',
        r'(?:SELECT|UNION|INSERT|DROP|DELETE|UPDATE).*(?:FROM|INTO|TABLE)',
        r'(?:cmd=|exec=|command=|shell=)',
    ]

    def __init__(self, url):
        self.raw_url = url.strip()
        self.parsed = urlparse(self.raw_url)
        self.extracted = tldextract.extract(self.raw_url)
        self.results = {}

    def run_static_analysis(self):
        logger.info(f"Running static analysis on: {self.raw_url[:80]}")
        analysis = {
            "url_components": self._parse_url_components(),
            "domain_info": self._analyze_domain(),
            "suspicious_patterns": self._check_suspicious_patterns(),
            "query_analysis": self._analyze_query_params(),
            "entropy_scores": self._calculate_entropy(),
        }
        self.results["static_analysis"] = analysis
        return analysis

    def _parse_url_components(self):
        return {
            "scheme": self.parsed.scheme,
            "full_domain": self.parsed.netloc,
            "subdomain": self.extracted.subdomain,
            "domain": self.extracted.domain,
            "suffix": self.extracted.suffix,
            "fqdn": f"{self.extracted.subdomain}.{self.extracted.domain}.{self.extracted.suffix}".lstrip("."),
            "port": self.parsed.port,
            "path": self.parsed.path,
            "query_string": self.parsed.query,
            "fragment": self.parsed.fragment,
            "has_authentication": bool(self.parsed.username),
            "path_depth": len([p for p in self.parsed.path.split("/") if p]),
        }

    def _analyze_domain(self):
        fqdn = f"{self.extracted.domain}.{self.extracted.suffix}"
        return {
            "tld": f".{self.extracted.suffix}",
            "is_ip": self._is_ip_address(fqdn),
            "is_suspicious_tld": f".{self.extracted.suffix}" in self.SUSPICIOUS_TLDS,
            "subdomain_count": len(self.extracted.subdomain.split(".")) if self.extracted.subdomain else 0,
            "domain_length": len(self.extracted.domain),
            "fqdn_length": len(fqdn),
            "has_hyphen": "-" in self.extracted.domain,
            "digit_ratio": sum(1 for c in self.extracted.domain if c.isdigit()) / max(len(self.extracted.domain), 1),
        }

    def _is_ip_address(self, s):
        ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s)
        if ipv4:
            return True
        ipv6 = re.match(r"^[0-9a-fA-F:]+$", s)
        return bool(ipv6)

    def _check_suspicious_patterns(self):
        findings = []
        url_lower = self.raw_url.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                findings.append({"type": "suspicious_keyword", "match": keyword, "severity": "medium"})
        for pattern in self.SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, self.raw_url, re.IGNORECASE)
            for m in matches:
                findings.append({"type": "malicious_pattern", "match": m, "severity": "high"})
        special_chars = sum(1 for c in self.raw_url if c in "%&=$!@^*")
        if special_chars > 10:
            findings.append({"type": "excessive_special_chars", "match": f"{special_chars} special characters", "severity": "low"})
        return findings

    def _analyze_query_params(self):
        params = parse_qs(self.parsed.query)
        param_analysis = {
            "param_count": len(params),
            "has_redirect_params": any(p.lower() in ("redirect", "return", "next", "url", "goto") for p in params),
            "has_file_params": any("file" in p.lower() or "doc" in p.lower() for p in params),
            "param_names": list(params.keys()) if params else [],
        }
        for key, values in params.items():
            for val in values:
                if val and re.match(r"^[A-Za-z0-9+/=]{20,}$", val):
                    try:
                        decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                        if any(kw in decoded.lower() for kw in self.SUSPICIOUS_KEYWORDS):
                            param_analysis["suspicious_base64"] = {"param": key, "decoded_preview": decoded[:100]}
                    except Exception:
                        pass
        return param_analysis

    def _calculate_entropy(self):
        def shannon(s):
            if not s:
                return 0.0
            prob = [float(s.count(c)) / len(s) for c in set(s)]
            return -sum(p * math.log2(p) for p in prob)
        domain = self.extracted.domain
        path = self.parsed.path
        return {
            "domain_entropy": round(shannon(domain), 4),
            "path_entropy": round(shannon(path), 4),
            "full_url_entropy": round(shannon(self.raw_url), 4),
            "high_domain_entropy": shannon(domain) > 4.0,
            "high_path_entropy": shannon(path) > 4.5,
        }

    def run_dns_lookup(self):
        fqdn = f"{self.extracted.domain}.{self.extracted.suffix}"
        dns_results = {"resolvable": False, "ips": [], "records": {}}
        try:
            answers = dns.resolver.resolve(fqdn, "A")
            dns_results["resolvable"] = True
            dns_results["ips"] = [str(a) for a in answers]
        except Exception as e:
            dns_results["error"] = str(e)
        for rtype in ("MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(fqdn, rtype)
                dns_results["records"][rtype] = [str(a) for a in answers[:5]]
            except Exception:
                pass
        return dns_results

    def run_whois_lookup(self):
        whois_results = {"available": True}
        try:
            fqdn = f"{self.extracted.domain}.{self.extracted.suffix}"
            w = whois.whois(fqdn)
            whois_results["available"] = False
            whois_results["registrar"] = w.get("registrar", "Unknown")
            whois_results["creation_date"] = str(w.get("creation_date", ""))
            whois_results["expiration_date"] = str(w.get("expiration_date", ""))
            if w.get("creation_date"):
                cdate = w.get("creation_date")
                if isinstance(cdate, list):
                    cdate = cdate[0]
                if isinstance(cdate, datetime):
                    age = (datetime.now(timezone.utc) - cdate).days
                    whois_results["age_days"] = age
                    whois_results["is_new_domain"] = age < 30
        except Exception as e:
            whois_results["error"] = str(e)
        return whois_results

    def generate_iocs(self):
        iocs = []
        fqdn = f"{self.extracted.domain}.{self.extracted.suffix}"
        iocs.append({"type": "domain", "value": fqdn, "context": "Extracted from submitted URL", "severity": "medium"})
        if self._is_ip_address(fqdn):
            iocs.append({"type": "ip", "value": fqdn, "context": "URL direct IP address", "severity": "high"})
        if self.parsed.path and self.parsed.path != "/":
            iocs.append({"type": "url_path", "value": self.parsed.path, "context": "URL path component", "severity": "low"})
        params = parse_qs(self.parsed.query)
        for key, values in params.items():
            for val in values:
                if val and self._is_ip_address(val):
                    iocs.append({"type": "ip", "value": val, "context": f"Query parameter '{key}' contains IP address", "severity": "high"})
        return iocs

    def calculate_risk_score(self, threats=[]):
        score = 0
        factors = []
        static = self.results.get("static_analysis", {})
        domain_info = static.get("domain_info", {})
        if domain_info.get("is_suspicious_tld"):
            score += 15; factors.append("Suspicious TLD (+15)")
        if domain_info.get("digit_ratio", 0) > 0.5:
            score += 10; factors.append("High digit ratio in domain (+10)")
        if domain_info.get("domain_length", 0) > 20:
            score += 5; factors.append("Long domain name (+5)")
        entropy = static.get("entropy_scores", {})
        if entropy.get("high_domain_entropy"):
            score += 10; factors.append("High domain entropy (+10)")
        if entropy.get("high_path_entropy"):
            score += 5; factors.append("High path entropy (+5)")
        patterns = static.get("suspicious_patterns", [])
        for p in patterns:
            if p["severity"] == "high":
                score += 15; factors.append(f"Malicious pattern: {p['match'][:30]} (+15)")
            elif p["severity"] == "medium":
                score += 8; factors.append(f"Suspicious keyword: {p['match']} (+8)")
        qa = static.get("query_analysis", {})
        if qa.get("has_redirect_params"):
            score += 10; factors.append("Contains redirect parameters (+10)")
        if qa.get("param_count", 0) > 5:
            score += 5; factors.append(f"Excessive query params ({qa['param_count']}) (+5)")
        if qa.get("suspicious_base64"):
            score += 20; factors.append("Suspicious base64 in params (+20)")
        for threat in threats:
            if threat.get("source") == "virustotal":
                malicious = threat.get("malicious", 0)
                total = threat.get("total", 1)
                ratio = malicious / max(total, 1)
                score += ratio * 30
                if malicious > 0:
                    factors.append(f"VirusTotal: {malicious}/{total} detections")
            elif threat.get("source") == "abuseipdb":
                reports = threat.get("total_reports", 0)
                score += min(reports, 20)
                if reports > 0:
                    factors.append(f"AbuseIPDB: {reports} reports")
            elif threat.get("source") == "urlscan":
                if threat.get("malicious"):
                    score += 20; factors.append("URLScan.io: Marked malicious (+20)")
        score = min(score, 100)
        if score >= 80: level = "critical"
        elif score >= 60: level = "high"
        elif score >= 40: level = "medium"
        elif score >= 20: level = "low"
        else: level = "unknown"
        self.results["risk_score"] = score
        self.results["risk_level"] = level
        self.results["risk_factors"] = factors
        return score, level, factors
