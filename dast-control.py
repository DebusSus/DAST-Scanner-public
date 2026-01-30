#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Scanners: WhatWeb, testssl, WPScan, Droopescan, Joomscan, ZAP, nikto, w3af, wapiti, arachni, what web, nuclei

import os
import time
import sys
import json
import time
import uuid
import signal
import threading
import pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional, Tuple
import urllib.request
import docker
import re

# -------- Config / Env --------
API_PORT = int(os.getenv("API_PORT", "8080"))
REPORTS_DIR = os.getenv("REPORTS_DIR", "/reports")
pathlib.Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)

WPSCAN_IMAGE      = os.getenv("WPSCAN_IMAGE",      "wpscanteam/wpscan")
NIKTO_IMAGE       = os.getenv("NIKTO_IMAGE",       "frapsoft/nikto")
NUCLEI_IMAGE      = os.getenv("NUCLEI_IMAGE",      "projectdiscovery/nuclei:latest")
ZAP_IMAGE         = os.getenv("ZAP_IMAGE",         "zaproxy/zap-stable")
TESTSSL_IMAGE     = os.getenv("TESTSSL_IMAGE",     "drwetter/testssl.sh")
WHATWEB_IMAGE     = os.getenv("WHATWEB_IMAGE",     "urbanadventurer/whatweb")
DROOPESCAN_IMAGE  = os.getenv("DROOPESCAN_IMAGE",  "trolldbois/droopescan")
JOOMSCAN_IMAGE    = os.getenv("JOOMSCAN_IMAGE",    "owasp/joomscan")
DEFAULT_WPVULNDB_TOKEN = os.getenv("WPVULNDB_API_TOKEN", "")
NUCLEI_TEMPLATES       = os.getenv("NUCLEI_TEMPLATES", "/root/nuclei-templates")
NUCLEI_UPDATE_ON_START = os.getenv("NUCLEI_UPDATE_ON_START", "true").lower() == "true"

docker_client = docker.from_env(version='1.41')

SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "med": "MEDIUM",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "warning": "LOW",
    "warn": "LOW",
    "ok": "INFO",
    "green": "INFO",
}

CVEREG = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)
CWEREG = re.compile(r"(CWE-\d+)", re.I)
CVSSREG = re.compile(r"CVSS[:\s]*([0-9]+(?:\.[0-9]+)?)", re.I)

# -------- Job state --------
jobs_lock: threading.Lock = threading.Lock()
jobs: Dict[str, Dict[str, Any]] = {}

SCANNERS = [
    "whatweb", "testssl",
    "wpscan", "droopescan", "joomscan",
    "nikto", "nuclei", "zap",
]
CMS_SCANNERS = {"wordpress": "wpscan", "drupal": "droopescan", "joomla": "joomscan"}
CMS_SCANNER_SET = {"wpscan", "droopescan", "joomscan"}

# -------- Helpers: job registry --------
def new_job(target: str, scanners: List[str], options: Dict[str, Any], auto_mode: bool) -> str:
    jid = uuid.uuid4().hex[:8]
    with jobs_lock:
        jobs[jid] = {
            "target": target,
            "requested_scanners": scanners,
            "status": "running",
            "created_at": int(time.time()),
            "containers": {},
            "scanner_status": {s: "pending" for s in scanners},
            "scanner_exit_code": {},
            "scanner_results": {},
            "scanner_stdout": {},
            "scanner_stderr": {},
            "aggregate": None,
            "options": options or {},
            "auto_mode": auto_mode,
            "whatweb_detected_cms": [],
            "max_runtime": int(options.get("max_runtime", 0)) if isinstance(options, dict) else 0,
            "webhook_url": options.get("webhook_url") if isinstance(options, dict) else None,
        }
    return jid

def set_job(jid: str, **updates):
    with jobs_lock:
        if jid in jobs:
            jobs[jid].update(updates)

def get_job(jid: str) -> Optional[Dict[str, Any]]:
    with jobs_lock:
        return jobs.get(jid)

def list_jobs(limit=50):
    with jobs_lock:
        items = sorted(jobs.items(), key=lambda kv: kv[1]["created_at"], reverse=True)[:limit]
        return [{"job_id": jid, **{k:v for k,v in j.items()
                if k not in ("scanner_stdout","scanner_stderr","scanner_results","aggregate")}}
                for jid, j in items]

# -------- Utilities --------
def norm_sev(s: Optional[str]) -> str:
    if not s:
        return "INFO"
    s = s.strip().lower()
    s = s.split()[0]
    return SEV_MAP.get(s, s.upper())

def _mk_finding(name:str, desc:str, rec:str=None, sev:str="INFO",
                req:str=None, rep:str=None, cve:str=None, cwe:str=None, cvss:str=None, scanner: List[str]=None) -> Dict[str, Any]:
    vul = {
        "name": name or "Unnamed",
        "Description": desc or "",
        "Recommendation": rec or "",
        "severity": sev or "INFO",
        "request": req,
        "reply": rep,
        "CVE": cve,
        "CWE": cwe,
        "CVSS": cvss,
        "scanner": scanner or []
    }
    return {"vulnerability": {k:v for k,v in vul.items() if v not in (None, "") or k == "scanner"}}

def _best_rec(name:str) -> str:
    nl = name.lower()
    if "x-content-type-options" in nl:
        return "Set header 'X-Content-Type-Options: nosniff' on all responses."
    if "hsts" in nl or "strict-transport-security" in nl:
        return "Enable HSTS with an appropriate max-age and includeSubDomains if suitable."
    if "tls" in nl and "1.0" in nl:
        return "Disable legacy TLS versions and weak ciphers on the server."
    if "directory listing" in nl:
        return "Disable directory listing or restrict access."
    if "clickjacking" in nl or "x-frame-options" in nl:
        return "Set 'Content-Security-Policy: frame-ancestors' and/or 'X-Frame-Options: DENY'."
    return "Review and apply vendor or best-practice remediation for this issue."

ANSI_ESCAPE = re.compile(r'(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])')

def _strip_control(s: str) -> str:
    s = ANSI_ESCAPE.sub("", s)
    return re.sub(r"[^\x09\x0A\x0D\x20-\x7E]+", "", s)

def parse_last_json_blob(stdout: str) -> Optional[Dict[str, Any]]:
    try:
        first = stdout.find("{")
        last = stdout.rfind("}")
        if first != -1 and last != -1 and last > first:
            return json.loads(stdout[first:last+1])
    except Exception:
        pass
    return None

def parse_jsonl(stdout: str) -> List[Dict[str, Any]]:
    res = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                res.append(json.loads(line))
            except Exception:
                pass
    return res

def sev_rank(s: str) -> int:
    order = {"critical":5, "high":4, "medium":3, "low":2, "info":1, "unknown":0}
    return order.get(str(s).lower(), 0)

def merge_findings(lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]: # Merge dupa cve, nume normalizat
    
    merged: Dict[str, Dict[str, Any]] = {}
    
    def normalize_name(name: str) -> str:
        """Normalize vulnerability names for matching"""
        if not name:
            return ""
        
        # Remove scanner prefix
        name = re.sub(r'^(zap|nikto|testssl):\s*', '', name, flags=re.I)
        
        name = name.lower()
        
        # Define vulnerability indicators
        vuln_indicators = [
            "clickjacking",
            "x-content-type-options", 
            "nosniff",
            "csp",
            "content security policy",
            "hsts",
            "strict-transport-security",
            "caching",
            "cache-control",
            "storable",
            "info_disclosure",
            "server leaks",
            "permissions-policy",
            "spectre",
            "site isolation"
        ]
        
        
        replacements = {
            "x-frame-options": "clickjacking",
            "anti-clickjacking": "clickjacking",
            "strict-transport-security": "hsts",
            "x-content-type-options": "nosniff",
            "content security policy": "csp",
            "permissions policy": "permissions-policy",
            "server leaks": "info_disclosure",
            "cache-control": "caching",
            "storable and cacheable": "caching",
        }
        
        for old, new in replacements.items():
            if old in name:
                return new
        
        for indicator in vuln_indicators:
            if indicator in name:
                return indicator
        
        name = re.sub(r'[^a-z0-9\s\-]', ' ', name)
        words = name.split()
        if len(words) > 6:
            name = ' '.join(words[:6])
        
        return name.strip()
    
    def extract_domain(location: str) -> str:
        """Extract domain from any location string"""
        if not location or location == "":
            return ""
        
        try:
            first = location.split('\n')[0].strip()
            first = re.sub(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', '', first, flags=re.I)

            if '://' in first:
                return urlparse(first).netloc.lower()
            if re.match(r'^[a-z0-9\.:-]+$', first):
                return first
            return ""
        except:
            return ""
    
    def get_key(finding: Dict[str, Any]) -> str:
        """Generate matching key - CVE first, then normalized name"""
        vuln = finding.get("vulnerability", {})
        
        cve = vuln.get("CVE", "")
        if cve:
            return f"cve:{cve}"
        
        name = normalize_name(vuln.get("name", ""))
        domain = extract_domain(vuln.get("request", "") or vuln.get("reply", "") or "")
        
        if name and domain:
            return f"{name}::{domain}"
        
        return f"name:{name}"
    
    def sev_to_num(s: str) -> int:
        """Convert severity to numeric rank"""
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "warning": 2}
        return order.get(str(s).lower(), 0)
    
    def clean_scanner_prefix(name: str) -> str:
        if not name:
            return name
        # Remove scanner prefix
        return re.sub(r'^(?:zap|nikto|testssl):\s*', '', name, flags=re.I)
    
    all_findings = [f for sublist in lists for f in sublist]
    
    for finding in all_findings:
        key = get_key(finding)
        
        if key in merged:
            # Merge
            existing = merged[key]
            existing_vuln = existing["vulnerability"]
            new_vuln = finding["vulnerability"]
            
            # Combine scanners
            scanners = set(existing_vuln.get("scanner", []))
            scanners.update(new_vuln.get("scanner", []))
            existing_vuln["scanner"] = sorted(list(scanners))
            
            # Highest severity
            if sev_to_num(new_vuln["severity"]) > sev_to_num(existing_vuln["severity"]):
                existing_vuln["severity"] = new_vuln["severity"]
            
            if new_vuln["Description"] != existing_vuln["Description"]:
                existing_vuln.setdefault("descriptions", []).append({
                    "scanner": new_vuln["scanner"][0] if new_vuln.get("scanner") else "unknown",
                    "description": new_vuln["Description"]
                })
            
            # Merge CVE/CWE
            if new_vuln.get("CVE") and not existing_vuln.get("CVE"):
                existing_vuln["CVE"] = new_vuln["CVE"]
            if new_vuln.get("CWE") and not existing_vuln.get("CWE"):
                existing_vuln["CWE"] = new_vuln["CWE"]
            
        else:
            # New finding - create a clean copy
            new_finding = {
                "vulnerability": finding["vulnerability"].copy()
            }
            
            # Clean the name - remove scanner prefixes
            vuln = new_finding["vulnerability"]
            original_name = vuln.get("name", "")
            vuln["name"] = clean_scanner_prefix(original_name)
            
            # Ensure scanner is always a list
            scanner = vuln.get("scanner", [])
            if isinstance(scanner, str):
                vuln["scanner"] = [scanner]
            elif not isinstance(scanner, list):
                vuln["scanner"] = []
            
            merged[key] = new_finding
    
    result = list(merged.values())
    
    print(f"[MERGE] Reduced {len(all_findings)} findings to {len(result)} unique", file=sys.stderr)
    
    return result

# -------- Docker helpers --------
def split_target_for_http_tools(target: str) -> dict:
    p = urlparse(target if "://" in target else f"http://{target}")
    host = p.hostname or target
    port = p.port
    is_https = (p.scheme.lower() == "https")
    if port is None:
        port = 443 if is_https else 80
    return {"scheme": p.scheme.lower(), "host": host, "port": port, "is_https": is_https}

def ensure_image(image: str):
    try:
        docker_client.images.get(image)
    except docker.errors.ImageNotFound:
        docker_client.images.pull(image)

def run_container(image: str, cmd: List[str],
                  volumes: Optional[Dict[str, Dict[str, str]]] = None,
                  **extra_kwargs) -> Tuple[str, int, str, str]:
    ensure_image(image)
    container = docker_client.containers.run(
        image=image,
        command=cmd,
        detach=True,
        remove=False,
        stdout=True,
        stderr=True,
        volumes=volumes or {},
        environment={},
        **extra_kwargs
    )
    cid = container.id
    exit_code = container.wait().get("StatusCode", 1)
    try:
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
    except Exception as e:
        stdout = f"[logs stdout error] {e}"
    try:
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
    except Exception as e:
        stderr = f"[logs stderr error] {e}"
    try:
        container.remove(force=True)
    except:
        pass
    return cid, exit_code, stdout, stderr

# -------- Command builders --------
def build_wpscan_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    cmd = ["wpscan", "--url", target, "--format", "json"]
    token = opts.get("api_token") or DEFAULT_WPVULNDB_TOKEN
    if token: cmd += ["--api-token", token]
    if opts.get("random_user_agent", True): cmd.append("--random-user-agent")
    if isinstance(opts.get("enumerate"), list) and opts["enumerate"]:
        cmd += ["--enumerate", ",".join(opts["enumerate"])]
    for key, flag in [
        ("plugins_detection","--plugins-detection"),
        ("themes_detection","--themes-detection"),
        ("users_detection","--users-detection"),
        ("max_threads","--max-threads"),
        ("request_timeout","--request-timeout"),
        ("wp_content_dir","--wp-content-dir"),
        ("wp_plugins_dir","--wp-plugins-dir"),
    ]:
        v = opts.get(key)
        if v is not None: cmd += [flag, str(v)]
    if isinstance(opts.get("headers"), dict):
        for k,v in opts["headers"].items(): cmd += ["--header", f"{k}: {v}"]
    if opts.get("cookie_string"): cmd += ["--cookie-string", opts["cookie_string"]]
    if opts.get("throttle_ms") is not None: cmd += ["--throttle", str(opts["throttle_ms"])]
    if opts.get("rate_limit") is not None: cmd += ["--rate-limit", str(opts["rate_limit"])]
    if opts.get("proxy"): cmd += ["--proxy", opts["proxy"]]
    if opts.get("ignore_main_redirect"): cmd.append("--ignore-main-redirect")
    if opts.get("disable_tls_checks"): cmd.append("--disable-tls-checks")
    if opts.get("no_banner", True): cmd.append("--no-banner")
    return cmd

def build_nikto_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    t = split_target_for_http_tools(target)
    
    cmd = [
        "-h", t["host"],
        "-p", str(t["port"]),
    ]
    
    if t["is_https"]:
        cmd.append("-ssl")
    
    # Optional parameters
    if opts.get("host_header"):
        cmd += ["-hostheader", str(opts["host_header"])]
    if opts.get("useragent"):
        cmd += ["-useragent", str(opts["useragent"])]
    if opts.get("cookie"):
        cmd += ["-cookie", str(opts["cookie"])]
    if isinstance(opts.get("headers"), dict) and opts["headers"]:
        header_str = "; ".join(f"{k}: {v}" for k,v in opts["headers"].items())
        cmd += ["-headers", header_str]
    if opts.get("tuning"): 
        cmd += ["-Tuning", str(opts["tuning"])]
    
    plugins = opts.get("plugins")
    if isinstance(plugins, list): 
        plugins = ",".join(plugins)
    if isinstance(plugins, str) and plugins.strip():
        cmd += ["-Plugins", plugins.strip()]
        
    if opts.get("timeout"):  
        cmd += ["-timeout", str(int(opts["timeout"]))]
    if opts.get("maxtime"):  
        cmd += ["-maxtime", str(opts["maxtime"])]
    if opts.get("nocache"):  
        cmd.append("-nocache")
    if opts.get("follow_redirects"): 
        cmd.append("-followredirects")
    
    return cmd

def build_zap_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    mode = (opts.get("mode") or "baseline").lower()
    script = "/zap/zap-baseline.py" if mode == "baseline" else "/zap/zap-full-scan.py"
    
    cmd = [
        script,
        "-t", target,
        "-T", "60",
        "-w", "/zap/wrk/zap_report.md"
    ]
    
    if opts.get("timeout"):
        cmd += ["-m", str(int(opts["timeout"]))]
    if opts.get("config_file"):
        cmd += ["-c", opts["config_file"]]
    if opts.get("ajax_spider"):
        cmd += ["-j"]
    if opts.get("alpha_rules"):
        cmd += ["-a"]
    cmd += ["-d"]
    
    return cmd

def build_testssl_cmd(target: str, opts: dict) -> list:
    
    p = urlparse(target if "://" in target else f"http://{target}")
    host = p.hostname or target
    is_https = (p.scheme.lower() == "https")
    port = p.port or (443 if is_https else 80)
    hostport = f"{host}:{port}"

    cmd = [
        "--quiet",
        "--jsonfile-pretty", "/dev/stdout",
    ]
    if opts.get("fast"):
        cmd.append("--fast")
    cmd.append(hostport)
    return cmd

def build_whatweb_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    return ["whatweb", "-a", str(opts.get("aggression", 3)), "-v", "--log-json=-", target]

def build_droopescan_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    return ["droopescan", "scan", "drupal", "-u", target, "-j"]

def build_joomscan_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    cmd = ["joomscan", "-u", target]
    if opts.get("json", True): cmd += ["-o", "json"]
    return cmd

# -------- Normalizers (unified schema) --------
# ---------- testssl.sh ----------
def normalize_testssl(raw_json_text: str, asset: str) -> List[Dict[str, Any]]:
    
    findings: List[Dict[str, Any]] = []

    if not raw_json_text or not raw_json_text.strip():
        return findings

    raw_clean = _strip_control(raw_json_text)

    data = {}
    try:
        data = json.loads(raw_clean)
    except json.JSONDecodeError:
        json_candidates = re.findall(r'\{.*?}', raw_clean, re.DOTALL)
        for candidate in json_candidates:
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict) and "severity" in obj:
                    data.setdefault("extracted", []).append(obj)
            except json.JSONDecodeError:
                pass

    def _first(arr): return arr[0] if arr else None

    def walk(obj):
        if isinstance(obj, dict):
            if "severity" in obj:
                sev = norm_sev(obj.get("severity"))
                if sev in ['INFO', 'OK']:
                    return
                name = obj.get("id") or obj.get("finding") or obj.get("idString") or "TLS finding"
                desc = _strip_control(obj.get("finding") or obj.get("id") or "").strip()
                blob = json.dumps(obj, ensure_ascii=False)
                cve  = _first(CVEREG.findall(blob))
                cwe  = _first(CWEREG.findall(blob))
                cvss = _first(CVSSREG.findall(blob))
                findings.append(_mk_finding(
                    name=name,
                    desc=desc,
                    rec=_best_rec(name),
                    sev=sev,
                    req=None,
                    rep=blob,
                    cve=cve,
                    cwe=cwe,
                    cvss=cvss,
                    scanner=["testssl"]
                ))
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(data)

    if not findings:
        # non TLS handling
        if "doesn't seem to be a TLS/SSL enabled server" in raw_json_text:
            findings.append(_mk_finding(
                "Not a TLS/SSL enabled server",
                "The target does not appear to support TLS/SSL. No further scanning performed.",
                rec="Ensure the target is HTTPS-enabled if TLS scanning is intended.",
                sev="WARN",
                scanner=["testssl"]
            ))
        else: 
            pass 
    return findings

# ---------- Nikto ----------
def normalize_nikto(raw_text: str, asset: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    
    if not raw_text or "No web server found" in raw_text:
        return findings
        
    raw_clean = _strip_control(raw_text)
    
    if not asset.startswith(('http://', 'https://')):
        base_url = f"http://{asset}"
    else:
        base_url = asset
    base_url = base_url.rstrip('/')
    
    if raw_clean:
        print(f"[DEBUG NIKTO NORMALIZER] Sample: {raw_clean[:400]}", file=sys.stderr)
    
    finding_pattern = re.compile(r'^\+\s*(?!ERROR|WARN)(?:([A-Z\s]+):\s*)?(/\S+):\s*(.+)$', re.MULTILINE)
    
    for match in finding_pattern.finditer(raw_clean):
        message_type = match.group(1) or "Finding"
        path = match.group(2)
        description = match.group(3).strip()
        
        if message_type in ["Target IP", "Target Hostname", "Target Port", "Start Time", "End Time", "Server"]:
            continue
            
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in ["sql injection", "rce", "remote code", "command injection", "file upload"]):
            sev = "CRITICAL"
        elif any(kw in desc_lower for kw in ["xss", "csrf", "brute force", "dos", "shell"]):
            sev = "HIGH"
        elif any(kw in desc_lower for kw in ["directory", "backup", "config", "info disclosure", "version"]):
            sev = "MEDIUM"
        else:
            sev = "LOW"
        
        finding = _mk_finding(
            name=f"Nikto: {message_type}",
            desc=f"{description} at {path}",
            rec=_best_rec(description),
            sev=sev,
            req=f"GET {base_url}{path}",
            rep=None,
            scanner=['nikto']
        )
        findings.append(finding)
    
    if not findings:
        generic_pattern = re.compile(r'^\+\s*(?!ERROR|WARN)([^:]+):\s*(.+)$', re.MULTILINE)
        for match in generic_pattern.finditer(raw_clean):
            name = match.group(1).strip()
            desc = match.group(2).strip()
            
            if name in ["0 host(s) tested", "items checked", "item(s) reported"]:
                continue
                
            finding = _mk_finding(
                name=f"Nikto: {name}",
                desc=desc,
                rec=_best_rec(name),
                sev="LOW",
                req=f"GET {base_url}/",
                scanner=['nikto']
            )
            findings.append(finding)
    
    return findings

# ---------- Nuclei ----------
def normalize_nuclei(raw_text: str, asset: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    def _first(arr): return arr[0] if arr else None
    for line in (raw_text or "").splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        name = o.get("info", {}).get("name") or o.get("name") or o.get("template-id") or "Nuclei finding"
        sev = norm_sev(o.get("info", {}).get("severity") or o.get("severity"))
        matched = o.get("matched-at") or o.get("host") or asset
        evidence_parts = []
        if "extracted-results" in o and o["extracted-results"]:
            evidence_parts.append("Extracted: " + ", ".join(map(str, o["extracted-results"])))
        if "matcher-name" in o and o["matcher-name"]:
            evidence_parts.append(f"Matcher: {o['matcher-name']}")
        desc = _strip_control((o.get("info", {}).get("description") or "").strip())
        if evidence_parts:
            desc = (desc + ("\n" if desc else "")) + "; ".join(evidence_parts)
        cve = _first(CVEREG.findall(json.dumps(o.get("info", {}))))
        cwe = _first(CWEREG.findall(json.dumps(o.get("info", {}))))
        cvss = None
        if "classification" in o.get("info", {}):
            cvss = str(o["info"]["classification"].get("cvss-score") or "") or None
            if not cvss:
                cvss = _first(CVSSREG.findall(json.dumps(o["info"]["classification"])))
        findings.append(_mk_finding(name, desc or "Detected by Nuclei.", _best_rec(name), sev, req=None, rep=matched, cve=cve, cwe=cwe, cvss=cvss, scanner=["nuclei"]))
    return findings

# ---------- ZAP ----------
def normalize_zap(raw_text: str, asset: str) -> List[Dict[str, Any]]:
    
    if not raw_text or not raw_text.strip():
        print("[ZAP] Empty input to normalizer", file=sys.stderr)
        return []
        
    raw_clean = _strip_control(raw_text)
    
    # TRY JSON
    try:
        data = json.loads(raw_clean)
        print("[ZAP] Successfully parsed JSON format", file=sys.stderr)
        return _normalize_zap_json(data, asset)
    except json.JSONDecodeError as e:
        print(f"[ZAP] JSON parse failed ({e}), using text fallback", file=sys.stderr)
        return normalize_zap_fallback(raw_text, asset)
    
def _normalize_zap_json(data: Dict[str, Any], asset: str) -> List[Dict[str, Any]]:
    """Process ZAP JSON structure into findings."""
    findings: List[Dict[str, Any]] = []
    
    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            name = alert.get('name', 'Unnamed ZAP Alert')
            desc = alert.get('desc', '').strip()
            rec = alert.get('solution', '').strip() or _best_rec(name)
            
            riskdesc = alert.get('riskdesc', 'Informational')
            sev = norm_sev(riskdesc.split(' (')[0])
            
            cve_match = CVEREG.search(desc)
            cve = cve_match.group(1) if cve_match else None
            
            cwe_id = alert.get('cweid')
            cwe = f"CWE-{cwe_id}" if cwe_id else None
            
            cvss_match = CVSSREG.search(desc)
            cvss = cvss_match.group(1) if cvss_match else None
            
            instances = alert.get('instances', [])
            req_parts = []
            rep_parts = []
            
            for inst in instances:
                method = inst.get('method', 'N/A')
                uri = inst.get('uri', 'N/A')
                param = inst.get('param', 'N/A')
                attack = inst.get('attack', 'N/A')
                evidence = inst.get('evidence', 'N/A')
                
                req_parts.append(f"{method} {uri}")
                if param:
                    req_parts[-1] += f" | Param: {param}"
                if attack:
                    req_parts[-1] += f" | Attack: {attack}"
                    
                rep_parts.append(f"Evidence: {evidence}")
            
            req = "\n".join(req_parts) if req_parts else None
            rep = "\n".join(rep_parts) if rep_parts else None
            
            finding = _mk_finding(
                name=name,
                desc=desc,
                rec=rec,
                sev=sev,
                req=req,
                rep=rep,
                cve=cve,
                cwe=cwe,
                cvss=cvss,
                scanner=['zap']
            )
            findings.append(finding)
            
    return findings

def normalize_zap_fallback(stdout_text: str, asset: str) -> List[Dict[str, Any]]:
    """
    Parses ZAP's text output format. Works with actual ZAP output format.
    """
    findings: List[Dict[str, Any]] = []
    raw_clean = _strip_control(stdout_text)
    
    alert_pattern = re.compile(
        r'^(WARN-NEW|FAIL-NEW|INFO):\s+(.+?)\s*\[(\d+)\](?:\s+x\s+(\d+))?\s*$',
        re.MULTILINE
    )
    
    url_pattern = re.compile(r'^\s+(https?://[^\s]+?)\s+\((\d{3} [A-Za-z\s]+)\)$', re.MULTILINE)
    
    alerts_found = 0
    
    for match in alert_pattern.finditer(raw_clean):
        alerts_found += 1
        status, name, alert_id, count = match.groups()
        count = int(count) if count else 1
        
        severity_map = {
            'FAIL-NEW': 'CRITICAL',
            'WARN-NEW': 'HIGH',
            'INFO': 'INFO'
        }
        sev = severity_map.get(status, 'INFO')
        
        alert_start = match.end()
        next_alert = alert_pattern.search(raw_clean, alert_start)
        search_end = next_alert.start() if next_alert else len(raw_clean)
        
        urls = []
        for url_match in url_pattern.finditer(raw_clean, alert_start, search_end):
            urls.append(f"{url_match.group(1)} ({url_match.group(2)})")
        
        desc = f"ZAP Alert {alert_id}: {name}. Affected {count} URL(s)."
        if urls:
            desc += "\nSample URLs:\n" + "\n".join(urls[:5])
        
        # Create finding
        finding = _mk_finding(
            name=f"ZAP: {name}",
            desc=desc,
            rec=_best_rec(name),
            sev=sev,
            req="\n".join([u.split(" (")[0] for u in urls[:3]]) if urls else None,
            rep="\n".join([u.split(" (")[1].rstrip(")") for u in urls[:3]]) if urls else None,
            scanner=['zap']
        )
        findings.append(finding)
    
    print(f"[ZAP Fallback] Parsed {alerts_found} alerts into {len(findings)} findings", file=sys.stderr)
    return findings

# ---------- WhatWeb ----------
def normalize_whatweb(raw_text: str, asset: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    
    f: List[Dict[str, Any]] = []
    cms_hits: List[str] = []
    raw_clean = _strip_control(raw_text)
    try:
        data = json.loads(raw_clean)
        obj = data[0] if isinstance(data, list) and data else {}
        plugins = (obj.get("plugins") or {})
        for tech, meta in plugins.items():
            name = f"Technology detected: {tech}"
            desc = json.dumps(meta, ensure_ascii=False)
            f.append(_mk_finding(name, desc, "Inventory only.", "INFO", scanner=["whatweb"]))
        meta_keys = {k.lower() for k in plugins.keys()}
        if "wordpress" in meta_keys: cms_hits.append("wordpress")
        if "drupal" in meta_keys: cms_hits.append("drupal")
        if "joomla" in meta_keys: cms_hits.append("joomla")
        return f, cms_hits
    except Exception:
        m = re.findall(r"([A-Za-z0-9._-]+)\[", raw_clean or "")
        for tech in set(m or []):
            f.append(_mk_finding(f"Technology detected: {tech}", "Detected by WhatWeb.", "Inventory only.", "INFO", scanner=["whatweb"]))
        low = (raw_clean or "").lower()
        if "wordpress" in low: cms_hits.append("wordpress")
        if "drupal" in low: cms_hits.append("drupal")
        if "joomla" in low: cms_hits.append("joomla")
        return f, cms_hits

# ---------- WPScan / Droopescan / Joomscan ----------
def normalize_wpscan(raw_json_text: str, asset: str) -> List[Dict[str, Any]]:
    f: List[Dict[str, Any]] = []
    raw_clean = _strip_control(raw_json_text)
    try:
        data = json.loads(raw_clean)
    except Exception:
        return f
    def _first(arr): return arr[0] if arr else None
    for sect in ("version","plugins","themes","timthumbs"):
        node = data.get(sect)
        if isinstance(node, dict) and "vulnerabilities" in node:
            vulns = node.get("vulnerabilities") or []
            for v in vulns:
                name = v.get("title") or v.get("name") or "WP vulnerability"
                desc = _strip_control(v.get("detail") or v.get("references",""))
                sev  = norm_sev(v.get("severity"))
                cve  = _first(CVEREG.findall(json.dumps(v)))
                cwe  = _first(CWEREG.findall(json.dumps(v)))
                cvss = str(v.get("cvss") or v.get("cvss_score") or "") or None
                f.append(_mk_finding(name, desc, _best_rec(name), sev, cve=cve, cwe=cwe, cvss=cvss, scanner=["wpscan"]))
    return f

def normalize_droopescan(raw_text: str, asset: str) -> List[Dict[str, Any]]:
    f: List[Dict[str, Any]] = []
    raw_clean = _strip_control(raw_text)
    for line in (raw_clean or "").splitlines():
        if "VULNERABILITY" in line.upper():
            name = line.strip()
            f.append(_mk_finding(name, "Detected by Droopescan.", _best_rec(name), "MEDIUM", scanner=["droopescan"]))
    return f

def normalize_joomscan(raw_text: str, asset: str) -> List[Dict[str, Any]]:
    f: List[Dict[str, Any]] = []
    raw_clean = _strip_control(raw_text)
    def _first(arr): return arr[0] if arr else None
    for line in (raw_clean or "").splitlines():
        if "vuln" in line.lower() or "cve-" in line.lower():
            blob = line.strip()
            f.append(_mk_finding("JoomScan finding", blob, _best_rec(blob), "MEDIUM",
                                 cve=_first(CVEREG.findall(blob)), cwe=_first(CWEREG.findall(blob)), scanner=["joomscan"]))
    return f

# ---------- Build final normalized document ----------
def normalize_all(asset: str,
                  scanner_payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    
    scanners_dict = {}
    all_findings_lists = []

    get = lambda name: (scanner_payloads.get(name) or {})
    s_out = lambda name: (get(name).get("stdout") or "")

    if "nuclei" in scanner_payloads:   
        findings = normalize_nuclei(s_out("nuclei"), asset)
        scanners_dict["nuclei"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "zap" in scanner_payloads:      
        findings = normalize_zap(s_out("zap"), asset)
        scanners_dict["zap"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "nikto" in scanner_payloads:    
        findings = normalize_nikto(s_out("nikto"), asset)
        scanners_dict["nikto"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "testssl" in scanner_payloads:  
        findings = normalize_testssl(s_out("testssl"), asset)
        scanners_dict["testssl"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "whatweb" in scanner_payloads:  
        findings, _ = normalize_whatweb(s_out("whatweb"), asset)
        scanners_dict["whatweb"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "wpscan" in scanner_payloads:   
        findings = normalize_wpscan(s_out("wpscan"), asset)
        scanners_dict["wpscan"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "droopescan" in scanner_payloads: 
        findings = normalize_droopescan(s_out("droopescan"), asset)
        scanners_dict["droopescan"] = {"findings": findings}
        all_findings_lists.append(findings)

    if "joomscan" in scanner_payloads: 
        findings = normalize_joomscan(s_out("joomscan"), asset)
        scanners_dict["joomscan"] = {"findings": findings}
        all_findings_lists.append(findings)

    overall_findings = merge_findings(all_findings_lists)

    return {
        "asset": asset,
        "scanners": scanners_dict,
        "overall_findings": overall_findings
    }

# =====================================================
# -------- Runners / finish helper --------
def finish_scanner(jid: str, name: str, code: int, findings: List[Dict[str, Any]], out: str, err: str, parsed_ok: bool):
    job = get_job(jid)
    job["scanner_results"][name] = findings
    job["scanner_exit_code"][name] = code
    job["scanner_stdout"][name] = out or ""
    job["scanner_stderr"][name] = err or ""
    job["scanner_status"][name] = "done"
    set_job(jid, **job)
    
    # Write individual scanner report
    try:
        scanner_report = {
            "job_id": jid,
            "scanner": name,
            "target": job["target"],
            "status": "done",
            "exit_code": code,
            "findings": findings,
            "scanner_stdout": out,
            "scanner_stderr": err,
            "created_at": job["created_at"],
            "finished_at": int(time.time())
        }
        scanner_report_path = os.path.join(REPORTS_DIR, f"{jid}_{name}.json")
        with open(scanner_report_path, "w", encoding="utf-8") as f:
            json.dump(scanner_report, f, ensure_ascii=False, indent=2)
        print(f"[finish_scanner] Individual report written: {scanner_report_path} ({len(findings)} findings)", file=sys.stderr)
    except Exception as e:
        print(f"[finish_scanner] Failed to write individual report for {name}: {e}", file=sys.stderr)
    
    print(f"[finish_scanner] Scanner {name} finished with {len(findings)} findings", file=sys.stderr)

def write_job_state(jid: str) -> str:
    fn = os.path.join(REPORTS_DIR, f"{jid}_state.json")
    with open(fn, "wb") as f:
        f.write(job_json_blob(jid))
    return fn

def runner_wpscan(jid: str, target: str, opts: Dict[str, Any]):
    job = get_job(jid); job["scanner_status"]["wpscan"]="running"; set_job(jid, **job)
    try:
        cmd = build_wpscan_cmd(target, opts.get("wpscan", {}))
        cid, code, out, err = run_container(WPSCAN_IMAGE, cmd, volumes={"wpscan_cache":{"bind":"/root/.wpscan","mode":"rw"}})
        job = get_job(jid); job["containers"]["wpscan"]=cid
        findings = normalize_wpscan(out, target)
        finish_scanner(jid, "wpscan", code, findings, out, err, parsed_ok=bool(findings))
    except Exception as e:
        job = get_job(jid); job["scanner_status"]["wpscan"]="error"; job["scanner_stderr"]["wpscan"]=str(e); set_job(jid, **job)

def runner_nikto(jid: str, target: str, opts: Dict[str, Any]):
    job = get_job(jid); job["scanner_status"]["nikto"]="running"; set_job(jid, **job)
    try:
        cmd = build_nikto_cmd(target, opts.get("nikto", {}))
        
        print(f"[DEBUG NIKTO] Command: {cmd}", file=sys.stderr)
        
        cid, code, out, err = run_container(NIKTO_IMAGE, cmd)
        
        job = get_job(jid); job["containers"]["nikto"]=cid
        
        print(f"[DEBUG NIKTO] Exit: {code}, stdout: {len(out)}b, stderr: {len(err)}b", file=sys.stderr)
        if err:
            print(f"[DEBUG NIKTO] Stderr: {err[:300]}", file=sys.stderr)
        
        findings = normalize_nikto(out, target)
        print(f"[DEBUG NIKTO] Parsed {len(findings)} findings", file=sys.stderr)
        
        finish_scanner(jid, "nikto", code, findings, out, err, parsed_ok=True)
    except Exception as e:
        print(f"[DEBUG NIKTO] Exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        job = get_job(jid); job["scanner_status"]["nikto"]="error"; job["scanner_stderr"]["nikto"]=str(e); set_job(jid, **job)

def runner_nuclei(jid: str, target: str, opts: Dict[str, Any]):
    job = get_job(jid); job["scanner_status"]["nuclei"]="running"; set_job(jid, **job)
    try:
        if NUCLEI_UPDATE_ON_START:
            try:
                ensure_image(NUCLEI_IMAGE)
                docker_client.containers.run(
                    image=NUCLEI_IMAGE,
                    command=["nuclei","-update","-ut","-ud",NUCLEI_TEMPLATES],
                    detach=False, remove=True, stdout=True, stderr=True,
                    volumes={"nuclei_templates":{"bind":NUCLEI_TEMPLATES,"mode":"rw"},
                             "nuclei_data":{"bind":"/root/.config/nuclei","mode":"rw"}},
                )
            except Exception:
                pass
        cmd = build_nuclei_cmd(target, opts.get("nuclei", {}))
        volumes = {"nuclei_templates": {"bind": NUCLEI_TEMPLATES, "mode":"rw"},
                   "nuclei_data": {"bind": "/root/.config/nuclei", "mode":"rw"}}
        cid, code, out, err = run_container(NUCLEI_IMAGE, cmd, volumes=volumes)
        job = get_job(jid); job["containers"]["nuclei"]=cid
        findings = normalize_nuclei(out, target)
        finish_scanner(jid, "nuclei", code, findings, out, err, parsed_ok=bool(findings))
    except Exception as e:
        job = get_job(jid); job["scanner_status"]["nuclei"]="error"; job["scanner_stderr"]["nuclei"]=str(e); set_job(jid, **job)

def runner_zap(jid: str, target: str, opts: Dict[str, Any]):
    name = "zap"
    job = get_job(jid)
    job["scanner_status"][name] = "running"
    set_job(jid, **job)
    
    try:
        # Create dedicated directory scanner
        output_dir = os.path.join(REPORTS_DIR, jid, name)
        os.makedirs(output_dir, exist_ok=True)
        os.chmod(output_dir, 0o777)
        
        # Mount
        volumes = {output_dir: {"bind": "/zap/wrk", "mode": "rw"}}
        
        cmd = build_zap_cmd(target, opts.get(name, {}))
        cid, code, out, err = run_container(ZAP_IMAGE, cmd, volumes=volumes, user='root')
        
        # Update container ID
        job = get_job(jid)
        job["containers"][name] = cid
        set_job(jid, **job)
        
        print(f"[DEBUG ZAP] Exit code: {code}", file=sys.stderr)
        print(f"[DEBUG ZAP] Stdout length: {len(out)}", file=sys.stderr)
        print(f"[DEBUG ZAP] Stderr length: {len(err)}", file=sys.stderr)
        
        findings = None
        
        # Check if JSON file was created
        json_path = os.path.join(output_dir, "zap_report.json")
        if os.path.exists(json_path):
            print(f"[DEBUG ZAP] Found JSON file at {json_path}", file=sys.stderr)
            with open(json_path, 'r', encoding='utf-8') as f:
                raw_json = f.read()
            findings = normalize_zap(raw_json, target)
        else:
            print(f"[DEBUG ZAP] JSON file NOT found at {json_path}", file=sys.stderr)
            
        # If no file, try to extract from stdout
        if not findings:
            print("[DEBUG ZAP] Attempting to extract JSON from stdout...", file=sys.stderr)
            json_start = out.find('{"site":')
            if json_start != -1:
                json_end = out.find('\n', json_start)
                if json_end == -1:
                    json_end = len(out)
                try:
                    json_str = out[json_start:json_end]
                    findings = normalize_zap(json_str, target)
                    print("[DEBUG ZAP] Successfully extracted JSON from stdout", file=sys.stderr)
                except:
                    pass
            
        if not findings:
            print("[DEBUG ZAP] Using text fallback parser", file=sys.stderr)
            findings = normalize_zap_fallback(out, target)
            
        if not findings:
            print("[DEBUG ZAP] No findings extracted!", file=sys.stderr)
            findings = []
            
        with open(os.path.join(output_dir, "stdout.log"), 'w') as f:
            f.write(out)
        with open(os.path.join(output_dir, "stderr.log"), 'w') as f:
            f.write(err)
            
        finish_scanner(jid, name, code, findings, out, err, parsed_ok=bool(findings))
        
    except Exception as e:
        print(f"[DEBUG ZAP] Exception in runner: {e}", file=sys.stderr)
        job = get_job(jid)
        job["scanner_status"][name] = "error"
        job["scanner_stderr"][name] = str(e)
        set_job(jid, **job)
        
    except Exception as e:
        job = get_job(jid)
        job["scanner_status"][name] = "error"
        job["scanner_stderr"][name] = str(e)
        set_job(jid, **job)

def runner_testssl(jid: str, target: str, opts: Dict[str, Any]):
    job = get_job(jid); job["scanner_status"]["testssl"]="running"; set_job(jid, **job)
    try:
        cmd = build_testssl_cmd(target, opts.get("testssl", {}))
        cid, code, out, err = run_container(TESTSSL_IMAGE, cmd)
        job = get_job(jid); job["containers"]["testssl"]=cid
        findings = normalize_testssl(out, target)
        finish_scanner(jid, "testssl", code, findings, out, err, parsed_ok=bool(findings))
    except Exception as e:
        job = get_job(jid); job["scanner_status"]["testssl"]="error"; job["scanner_stderr"]["testssl"]=str(e); set_job(jid, **job)

def runner_whatweb(jid: str, target: str, opts: Dict[str, Any]):
    job = get_job(jid); job["scanner_status"]["whatweb"]="running"; set_job(jid, **job)
    try:
        cmd = build_whatweb_cmd(target, opts.get("whatweb", {}))
        cid, code, out, err = run_container(WHATWEB_IMAGE, cmd)
        job = get_job(jid); job["containers"]["whatweb"]=cid
        findings, cms_hits = normalize_whatweb(out, target)
        job["whatweb_detected_cms"] = cms_hits
        finish_scanner(jid, "whatweb", code, findings, out, err, parsed_ok=True)
    except Exception as e:
        job = get_job(jid); job["scanner_status"]["whatweb"]="error"; job["scanner_stderr"]["whatweb"]=str(e); set_job(jid, **job)

def runner_droopescan(jid: str, target: str, opts: Dict[str, Any]):
    name = "droopescan"
    job = get_job(jid); job["scanner_status"][name]="running"; set_job(jid, **job)
    try:
        cmd = build_droopescan_cmd(target, opts.get(name, {}))
        cid, code, out, err = run_container(DROOPESCAN_IMAGE, cmd)
        job = get_job(jid); job["containers"][name]=cid
        findings = normalize_droopescan(out, target)
        finish_scanner(jid, name, code, findings, out, err, parsed_ok=bool(findings))
    except Exception as e:
        job = get_job(jid); job["scanner_status"][name]="error"; job["scanner_stderr"][name]=str(e); set_job(jid, **job)

def runner_joomscan(jid: str, target: str, opts: Dict[str, Any]):
    name="joomscan"
    job = get_job(jid); job["scanner_status"][name]="running"; set_job(jid, **job)
    try:
        cmd = build_joomscan_cmd(target, opts.get(name, {}))
        cid, code, out, err = run_container(JOOMSCAN_IMAGE, cmd)
        job = get_job(jid); job["containers"][name]=cid
        findings = normalize_joomscan(out, target)
        finish_scanner(jid, name, code, findings, out, err, parsed_ok=bool(findings))
    except Exception as e:
        job = get_job(jid); job["scanner_status"][name]="error"; job["scanner_stderr"][name]=str(e); set_job(jid, **job)

# -------- Finalize & orchestrator --------
def finalize_job_if_complete(jid: str):
    job = get_job(jid)
    if not job:
        return

    if any(job["scanner_status"].get(s) in ("running", "pending") for s in job["requested_scanners"]):
        return

    job["status"] = "done"
    job["finished_at"] = int(time.time())

    scanner_payloads = {
        name: {
            "stdout": job["scanner_stdout"].get(name, ""),
            "stderr": job["scanner_stderr"].get(name, "")
        }
        for name in job["requested_scanners"]
    }
    
    final_doc = normalize_all(job["target"], scanner_payloads)
    job["aggregate"] = final_doc

    total_findings = sum(len(v.get("findings", [])) for v in final_doc.get("scanners", {}).values())
    unique_findings = len(final_doc.get("overall_findings", []))
    print(f"[DEBUG FINALIZE] Job {jid} has {total_findings} total findings, {unique_findings} unique", file=sys.stderr)

    try:
        write_report(jid)
        print(f"[finalize] Overall report written to /reports/{jid}.json", file=sys.stderr)
    except Exception as e:
        job.setdefault("errors", []).append(f"write_report_failed: {e}")

    try:
        write_job_state(jid)
        print(f"[finalize] Job state written to /reports/{jid}_state.json", file=sys.stderr)
    except Exception as e:
        print(f"[finalize] Failed to write job state: {e}", file=sys.stderr)

    set_job(jid, **job)

    try:
        send_webhook(jid)
    except Exception as e:
        job = get_job(jid) or {}
        job.setdefault("errors", []).append(f"webhook_failed: {e}")
        set_job(jid, **job)

def orchestrator(jid: str):
    job = get_job(jid)
    if not job: return
    target = job["target"]; opts = job["options"]; req = job["requested_scanners"]
    explicit_cms = any(s in CMS_SCANNER_SET for s in req)

    threads: List[threading.Thread] = []

    def start(name, func):
        t = threading.Thread(target=func, args=(jid,target,opts), daemon=True)
        t.start(); threads.append(t)

    if job["auto_mode"] and not explicit_cms:
        # Run WhatWeb synchronously to decide CMS scanner
        try:
            set_job(jid, scanner_status={**job["scanner_status"], "whatweb":"running"})
            cmd = build_whatweb_cmd(target, opts.get("whatweb", {}))
            cid, code, out, err = run_container(WHATWEB_IMAGE, cmd)
            job = get_job(jid); job["containers"]["whatweb"]=cid
            ww_findings, cms_hits = normalize_whatweb(out, target)
            job["whatweb_detected_cms"] = cms_hits
            finish_scanner(jid, "whatweb", code, ww_findings, out, err, parsed_ok=True)
        except Exception as e:
            job = get_job(jid); job["scanner_status"]["whatweb"]="error"; job["scanner_stderr"]["whatweb"]=str(e); set_job(jid, **job)

        # Decide CMS scanner
        cms_to_run = None
        for cms in ["wordpress","drupal","joomla"]:
            if cms in (get_job(jid).get("whatweb_detected_cms") or []):
                cms_to_run = CMS_SCANNERS[cms]; break

        effective = []
        for s in req:
            if s not in CMS_SCANNER_SET:
                effective.append(s)
        if cms_to_run:
            effective.append(cms_to_run)

        with jobs_lock:
            jobs[jid]["requested_scanners"] = effective
            for s in effective:
                jobs[jid]["scanner_status"].setdefault(s, "pending")

        for s in effective:
            if s == "wpscan":      start("wpscan", runner_wpscan)
            elif s == "droopescan": start("droopescan", runner_droopescan)
            elif s == "joomscan":  start("joomscan", runner_joomscan)
            elif s == "nikto":     start("nikto", runner_nikto)
            elif s == "nuclei":    start("nuclei", runner_nuclei)
            elif s == "zap":       start("zap", runner_zap)
            elif s == "testssl":   start("testssl", runner_testssl)
    else:
        # Honor explicit list exactly
        for s in req:
            if s == "whatweb":     start("whatweb", runner_whatweb)
            elif s == "wpscan":    start("wpscan", runner_wpscan)
            elif s == "droopescan":start("droopescan", runner_droopescan)
            elif s == "joomscan":  start("joomscan", runner_joomscan)
            elif s == "nikto":     start("nikto", runner_nikto)
            elif s == "nuclei":    start("nuclei", runner_nuclei)
            elif s == "zap":       start("zap", runner_zap)
            elif s == "testssl":   start("testssl", runner_testssl)

    started_at = get_job(jid)["created_at"]
    max_runtime = int(get_job(jid).get("max_runtime", 0) or 0)

    while True:
        time.sleep(1.0)
        if max_runtime > 0 and (time.time() - started_at) > max_runtime:
            job = get_job(jid)
            for s in job["requested_scanners"]:
                if job["scanner_status"].get(s) == "running":
                    cid = job["containers"].get(s)
                    if cid:
                        try:
                            docker_client.containers.get(cid).kill()
                            job["scanner_status"][s] = "killed"
                        except Exception as e:
                            job["scanner_stderr"][s] = f"kill error: {e}"
            job["status"] = "killed"
            set_job(jid, **job)
            write_report(jid)
            send_webhook(jid)
            break

        finalize_job_if_complete(jid)
        job = get_job(jid)
        if job and job["status"] in ("done","error","killed"):
            break

# -------- Reports & Webhook --------
def job_json_blob(jid: str) -> bytes:
    job = get_job(jid)
    payload = {"job_id": jid, **(job or {})}
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")

def write_report(jid: str) -> str:
    job = get_job(jid)
    if not job:
        return ""
    
    # Collect findings from completed scanners only
    all_findings_lists = []
    for name in job["requested_scanners"]:
        if job["scanner_status"].get(name) == "done":
            findings = job["scanner_results"].get(name, [])
            all_findings_lists.append(findings)
    
    # Merge findings
    overall_findings = merge_findings(all_findings_lists)
    
    # Create overall report structure
    overall_report = {
        "job_id": jid,
        "target": job["target"],
        "status": job["status"],
        "created_at": job["created_at"],
        "finished_at": job.get("finished_at", int(time.time())),
        "scanners_used": job["requested_scanners"],
        "scanner_status": {name: job["scanner_status"].get(name) for name in job["requested_scanners"]},
        "summary": {
            "total_findings": sum(len(findings) for findings in all_findings_lists),
            "unique_findings": len(overall_findings)
        },
        "overall_findings": overall_findings
    }
    
    fn = os.path.join(REPORTS_DIR, f"{jid}.json")
    try:
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(overall_report, f, ensure_ascii=False, indent=2)
        print(f"[write_report] Overall report written: {fn}", file=sys.stderr)
        return fn
    except Exception as e:
        print(f"[write_report] Failed to write overall report: {e}", file=sys.stderr)
        return ""

def send_webhook(jid: str):
    job = get_job(jid)
    url = (job or {}).get("webhook_url")
    if not url:
        return
    req = urllib.request.Request(
        url, data=job_json_blob(jid),
        headers={"Content-Type":"application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as _:
            pass
    except Exception:
        print(f"[webhook] delivery failed for job {jid}", file=sys.stderr)

# -------- HTTP Server --------
class Handler(BaseHTTPRequestHandler):
    server_version = "DASTControl/1.3"

    def _send(self, code: int, obj: Dict[str, Any]):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/healthz":
            try:
                docker_client.ping()
                return self._send(200, {"ok": True, "images": {
                    "whatweb":WHATWEB_IMAGE,"testssl":TESTSSL_IMAGE,
                    "wpscan":WPSCAN_IMAGE,"droopescan":DROOPESCAN_IMAGE,"joomscan":JOOMSCAN_IMAGE,
                    "nikto":NIKTO_IMAGE,"nuclei":NUCLEI_IMAGE,"zap":ZAP_IMAGE}})
            except Exception as e:
                return self._send(500, {"ok": False, "error": str(e)})

        if p.path == "/scanners":
            return self._send(200, {"available": SCANNERS, "cms_auto_rules": CMS_SCANNERS})

        if p.path == "/scan":
            limit = int(parse_qs(p.query).get("limit", ["50"])[0])
            return self._send(200, {"jobs": list_jobs(limit)})

        if p.path.startswith("/scan/"):
            jid = p.path.split("/", 2)[2]
            job = get_job(jid)
            if not job:
                return self._send(404, {"error": "job not found"})
            qs = parse_qs(p.query); tail = int(qs.get("tail", ["0"])[0])
            body = {"job_id": jid, **job}
            if tail > 0:
                for s, raw in job["scanner_stdout"].items():
                    if raw: body["scanner_stdout"][s] = raw[-tail:]
            return self._send(200, body)

        if p.path.startswith("/reports/") and p.path.endswith(".json"):
            jid = os.path.basename(p.path).replace(".json","")
            job = get_job(jid)
            if not job:
                return self._send(404, {"error": "job not found"})
            fn = os.path.join(REPORTS_DIR, f"{jid}.json")
            if not os.path.exists(fn):
                write_report(jid)
            try:
                with open(fn, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", f'attachment; filename="{jid}.json"')
                self.end_headers()
                self.wfile.write(data)
                return
            except Exception as e:
                return self._send(500, {"error": f"cannot read report: {e}"})

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urlparse(self.path)
        if p.path != "/scan":
            return self._send(404, {"error": "not found"})
        if "application/json" not in (self.headers.get("Content-Type","").lower()):
            return self._send(415, {"error":"Content-Type must be application/json"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 5*1024*1024:
                return self._send(400, {"error":"Invalid Content-Length"})
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return self._send(400, {"error":"Invalid JSON"})

        try:
            target = payload.get("target")
            if not target:
                return self._send(400, {"error":"Missing 'target' (http/https URL or host)"})
            scanners = payload.get("scanners")
            auto_mode = False
            if scanners == "all" or scanners is None:
                scanners = ["whatweb","testssl","nikto","nuclei","zap"]
                auto_mode = True
            elif isinstance(scanners, list):
                scanners = [s for s in scanners if s in SCANNERS]
                if not scanners:
                    return self._send(400, {"error": f"'scanners' must include any of {SCANNERS} or 'all'"})
            else:
                return self._send(400, {"error": "Invalid 'scanners' value"})

            options = payload.get("options", {})
            jid = new_job(target, scanners, options, auto_mode)
            threading.Thread(target=orchestrator, args=(jid,), daemon=True).start()
            return self._send(202, {"job_id": jid, "status": "running", "scanners": scanners, "auto_mode": auto_mode})
        except Exception as e:
            return self._send(400, {"error": str(e)})

    def do_DELETE(self):
        p = urlparse(self.path)
        if not p.path.startswith("/scan/"):
            return self._send(404, {"error": "not found"})
        jid = p.path.split("/", 2)[2]
        job = get_job(jid)
        if not job:
            return self._send(404, {"error":"job not found"})
        running = False
        for s in job["requested_scanners"]:
            if job["scanner_status"].get(s) == "running":
                running = True
                cid = job["containers"].get(s)
                if cid:
                    try:
                        c = docker_client.containers.get(cid); c.kill()
                        job["scanner_status"][s] = "killed"
                    except Exception as e:
                        job["scanner_stderr"][s] = f"kill error: {e}"
        if running:
            job["status"]="killed"
        set_job(jid, **job)
        write_report(jid)
        send_webhook(jid)
        return self._send(200, {"job_id": jid, "status": job["status"], "scanner_status": job["scanner_status"]})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

# -------- Main --------
def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", API_PORT), Handler)
    def shutdown(signum, frame):
        try: httpd.shutdown()
        finally: os._exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    print(f"[*] DAST Control API listening on :{API_PORT}", flush=True)
    httpd.serve_forever()

if __name__ == "__main__":
    main()