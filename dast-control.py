#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Scanners: WhatWeb, testssl, WPScan, Droopescan, Joomscan, ZAP, nikto, w3af, wapiti, arachni, nuclei

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
import socket

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
W3AF_IMAGE             = os.getenv("W3AF_IMAGE",             "andresriancho/w3af")

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
    "nikto", "nuclei", "zap", "w3af"
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
    """Build WPScan command with proper JSON output"""
    cmd = ["wpscan", "--url", target, "--format", "json", "--no-banner"]
    
    token = opts.get("api_token") or DEFAULT_WPVULNDB_TOKEN
    if token: 
        cmd += ["--api-token", token]
    
    # Enumeration options
    enumerate_opts = []
    if opts.get("enumerate_plugins", True):
        enumerate_opts.append("vp")
    if opts.get("enumerate_themes", True):
        enumerate_opts.append("vt")
    if opts.get("enumerate_users", False):
        enumerate_opts.append("u")
    
    if enumerate_opts:
        cmd += ["--enumerate", ",".join(enumerate_opts)]
    
    # Stealth/performance options
    if opts.get("random_user_agent", True): 
        cmd.append("--random-user-agent")
    if opts.get("stealthy", False):
        cmd.append("--stealthy")
    if opts.get("throttle"):
        cmd += ["--throttle", str(opts["throttle"])]
    if opts.get("request_timeout"):
        cmd += ["--request-timeout", str(opts["request_timeout"])]
    
    # Proxy support
    if opts.get("proxy"):
        cmd += ["--proxy", opts["proxy"]]
    
    return cmd

def build_w3af_cmd(target: str, opts: Dict[str, Any]) -> Tuple[List[str], str]:
    """
    Build w3af command and generate scan script.
    Returns (command, script_content) - script needs to be written to a temp file.
    """
    # Generate w3af script
    script_lines = [
        "plugins",  # Enter plugins menu
        "output config text_file",  # Configure text output
        f"set output_file /w3af/output/w3af_report.txt",
        "set verbose True",
        "back",  # Back to plugins menu
        "output config xml_file",
        f"set output_file /w3af/output/w3af_report.xml",
        "back",
        # Enable audit plugins (vulnerability detection)
        "audit all,!sqli",  # Enable all audit plugins except SQLi (enable separately if needed)
        "audit sqli",  # SQL injection
        "back",
        # Enable grep plugins (passive detection)
        "grep all",
        "back",
        # Enable discovery plugins (spidering)
        "discovery web_spider",
        "discovery config web_spider",
        "set only_forward True",
        "back",
        "back",
        # Set target
        "target",
        f"set target {target}",
        "back",
        # Start scan
        "start",
        "exit"
    ]
    
    script_content = "\n".join(script_lines)
    
    # Command to run script
    cmd = ["w3af_console", "-s", "/w3af/script/w3af_script.txt"]
    
    return cmd, script_content


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

def build_nuclei_cmd(target: str, opts: Dict[str, Any]) -> List[str]:
    cmd = ["nuclei", "-u", target]
    
    # Handle Host header when using IP instead of hostname
    original_host = opts.get("_original_host") if isinstance(opts, dict) else None
    resolved_ip = opts.get("_resolved_ip") if isinstance(opts, dict) else None
    
    if original_host and resolved_ip:
        # Check if target is using IP (not hostname)
        parsed_target = urlparse(target)
        if parsed_target.hostname == resolved_ip or parsed_target.hostname != original_host:
            cmd.extend(["-H", f"Host: {original_host}"])
            print(f"[NUCLEI CMD] Adding Host header: {original_host}", file=sys.stderr)
    
    # Handle auto-tags from WhatWeb
    auto_tags = opts.get("_auto_tags", []) if isinstance(opts, dict) else []
    
    if auto_tags:
        # Map common tags to Nuclei tag names
        tag_mapping = {
            "javascript": "js",
            "jquery": "js",
            "misconfiguration": "misconfig",
            "tech": "tech",
            "detection": "detect",
            "wordpress": "wordpress,wp-plugin,wp-theme",
            "drupal": "drupal",
            "joomla": "joomla",
            "nginx": "nginx",
            "apache": "apache",
            "php": "php"
        }
        
        fixed_tags = set()
        for tag in auto_tags:
            tag_lower = tag.lower()
            if tag_lower in tag_mapping:
                # Split comma-separated mapped tags
                for mapped in tag_mapping[tag_lower].split(","):
                    fixed_tags.add(mapped)
            else:
                fixed_tags.add(tag_lower)
        
        # Add vulnerability-related tags unless explicitly in strict mode
        if not opts.get("tag_mode") == "strict":
            fixed_tags.update(["misconfig", "exposure", "vulnerability", "config"])
        
        if fixed_tags:
            tags_str = ",".join(sorted(fixed_tags))
            cmd.extend(["-tags", tags_str])
            print(f"[NUCLEI CMD] Using tags: {tags_str}", file=sys.stderr)
    
    # Severity filter (always include all severities)
    cmd.extend(["-severity", "info,low,medium,high,critical"])
    
    # Performance settings - increased timeout for connection issues
    cmd.extend(["-c", "25", "-rate-limit", "150"])
    
    # Connection timeouts - generous to ensure connections work
    cmd.extend(["-timeout", "15", "-max-host-error", "30"])
    
    # Output to file (ensures we capture results even if stdout buffered)
    cmd.extend(["-jsonl", "-o", "/tmp/nuclei_results.jsonl"])
    
    # Stats for monitoring (removed -silent to see debug info)
    cmd.extend(["-stats"])
    
    # Debug if requested
    if opts.get("debug") if isinstance(opts, dict) else False:
        cmd.append("-debug")
        cmd.append("-verbose")
    
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

# ---------- w3af --------------
def normalize_w3af(raw_text: str, raw_xml: str, asset: str) -> List[Dict[str, Any]]:
    """
    Parse w3af output. Tries XML first, falls back to text parsing.
    """
    findings: List[Dict[str, Any]] = []
    
    # Try XML parsing first (more reliable)
    if raw_xml and raw_xml.strip():
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_xml)
            
            for vuln in root.findall(".//vulnerability"):
                name = vuln.get("name", "w3af Finding")
                severity = vuln.get("severity", "Low")
                description = ""
                
                desc_elem = vuln.find("description")
                if desc_elem is not None and desc_elem.text:
                    description = desc_elem.text
                
                url_elem = vuln.find("url")
                method_elem = vuln.find("method")
                
                url = url_elem.text if url_elem is not None else asset
                method = method_elem.text if method_elem is not None else "GET"
                
                # CWE extraction from description
                cwe = None
                cwe_match = CWEREG.search(description)
                if cwe_match:
                    cwe = cwe_match.group(1)
                
                findings.append(_mk_finding(
                    name=f"w3af: {name}",
                    desc=description,
                    rec="Review the vulnerability details and apply appropriate patches or configuration fixes.",
                    sev=norm_sev(severity),
                    req=f"{method} {url}",
                    scanner=["w3af"]
                ))
            
            if findings:
                return findings
        except Exception as e:
            print(f"[w3af] XML parsing failed: {e}, falling back to text", file=sys.stderr)
    
    # Fallback to text parsing
    if not raw_text:
        return findings
        
    # Parse text format
    # Format: "New <severity> vulnerability found:\nURL: <url>\nMethod: <method>\nDescription: <desc>"
    vuln_pattern = re.compile(
        r'New\s+(?:(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+)?vulnerability\s+found:\s*'
        r'URL:\s*([^\n]+)\s*'
        r'(?:Method:\s*([^\n]+)\s*)?'
        r'(?:Vulnerable\s+parameter:\s*([^\n]+)\s*)?'
        r'(?:Description:\s*([^\n]+(?:\n(?!\s*(?:New|URL:|Method:|Vulnerable|End|Traceback))[^\n]+)*))',
        re.IGNORECASE | re.MULTILINE
    )
    
    for match in vuln_pattern.finditer(raw_text):
        severity = match.group(1) or "MEDIUM"
        url = match.group(2).strip()
        method = match.group(3) or "GET"
        param = match.group(4)
        description = match.group(5).strip() if match.group(5) else "No description"
        
        # Clean up the description
        description = re.sub(r'\n\s+', ' ', description)
        description = _strip_control(description)
        
        name = f"w3af: {description[:50]}..." if len(description) > 50 else f"w3af: {description}"
        
        req_parts = [f"{method} {url}"]
        if param:
            req_parts.append(f"Param: {param}")
        
        findings.append(_mk_finding(
            name=name,
            desc=description,
            rec="Review vulnerability details and apply vendor patches or mitigations.",
            sev=norm_sev(severity),
            req="\n".join(req_parts),
            scanner=["w3af"]
        ))
    
    # Also look for "Information" findings (passive grep results)
    info_pattern = re.compile(
        r'Information:\s*([^\n]+)\s*\n'
        r'URL:\s*([^\n]+)\s*\n'
        r'(?:Method:\s*([^\n]+)\s*\n)?',
        re.IGNORECASE
    )
    
    for match in info_pattern.finditer(raw_text):
        description = match.group(1).strip()
        url = match.group(2).strip()
        method = match.group(3) or "GET"
        
        findings.append(_mk_finding(
            name=f"w3af Info: {description[:40]}",
            desc=description,
            rec="Review information disclosure issues.",
            sev="INFO",
            req=f"{method} {url}",
            scanner=["w3af"]
        ))
    
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
            
        # Extract info
        info = o.get("info", {})
        name = info.get("name") or o.get("template-id") or "Nuclei Finding"
        severity = norm_sev(info.get("severity"))
        matched = o.get("matched-at") or o.get("host") or asset
        
        # Build description
        desc = info.get("description", "")
        if o.get("extracted-results"):
            desc += f"\nExtracted: {', '.join(map(str, o['extracted-results']))}"
        if o.get("matcher-name"):
            desc += f"\nMatcher: {o['matcher-name']}"
        desc = _strip_control(desc.strip())
        
        # Extract CVE/CWE/CVSS from classification
        classification = info.get("classification", {})
        cve = None
        cwe = None
        cvss = None
        
        if classification:
            cve_id = classification.get("cve-id")
            if cve_id:
                cve = cve_id if isinstance(cve_id, str) else ",".join(cve_id)
            cwe_id = classification.get("cwe-id")
            if cwe_id:
                cwe = f"CWE-{cwe_id}" if isinstance(cwe_id, int) else str(cwe_id)
            cvss = str(classification.get("cvss-score") or "")
        
        # Fallback to regex extraction from JSON blob
        if not cve:
            cve = _first(CVEREG.findall(json.dumps(o)))
        if not cwe:
            cwe = _first(CWEREG.findall(json.dumps(o)))
            
        findings.append(_mk_finding(
            name=name,
            desc=desc or f"Detected by template: {o.get('template-id')}",
            rec=_best_rec(name),
            sev=severity,
            req=o.get("request", ""),
            rep=o.get("response", "") or matched,
            cve=cve,
            cwe=cwe,
            cvss=cvss,
            scanner=["nuclei"]
        ))
        
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
    """Parse WPScan JSON output into standardized findings"""
    f: List[Dict[str, Any]] = []
    
    if not raw_json_text or not raw_json_text.strip():
        return f
        
    raw_clean = _strip_control(raw_json_text)
    
    try:
        data = json.loads(raw_clean)
    except Exception as e:
        print(f"[WPScan] JSON parse error: {e}", file=sys.stderr)
        return f
    
    def cvss_to_severity(score):
        """Convert CVSS score to severity"""
        try:
            score = float(score)
            if score >= 9.0: return "CRITICAL"
            elif score >= 7.0: return "HIGH"
            elif score >= 4.0: return "MEDIUM"
            elif score > 0: return "LOW"
            else: return "INFO"
        except:
            return "MEDIUM"  # Default for WP vulns

    # Process each section: version, plugins, themes, timthumbs
    for sect_key in ("version", "plugins", "themes", "timthumbs"):
        section = data.get(sect_key)
        if not isinstance(section, dict):
            continue
            
        vulns = section.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
            
        for v in vulns:
            title = v.get("title") or "WordPress Vulnerability"
            
            # Build description
            desc_parts = []
            if v.get("description"):
                desc_parts.append(v["description"])
            elif v.get("detail"):
                desc_parts.append(v["detail"])
            
            # Handle references (CVEs, exploits, etc)
            refs = v.get("references", {})
            ref_strs = []
            cve = None
            
            if isinstance(refs, dict):
                for ref_type, ref_val in refs.items():
                    if isinstance(ref_val, list):
                        for url in ref_val:
                            ref_strs.append(f"{ref_type}: {url}")
                            # Extract CVE from URLs
                            if not cve and isinstance(url, str):
                                cve_match = CVEREG.search(url)
                                if cve_match:
                                    cve = cve_match.group(1)
                    else:
                        ref_strs.append(f"{ref_type}: {ref_val}")
                        if not cve and isinstance(ref_val, str):
                            cve_match = CVEREG.search(ref_val)
                            if cve_match:
                                cve = cve_match.group(1)
            else:
                ref_strs.append(str(refs))
            
            if ref_strs:
                desc_parts.append("References: " + ", ".join(ref_strs))
            
            description = _strip_control(" ".join(desc_parts))
            
            # Get CVSS score for severity
            cvss_data = v.get("cvss", {})
            cvss_score = None
            if isinstance(cvss_data, dict):
                cvss_score = cvss_data.get("score") or cvss_data.get("base_score")
            else:
                cvss_score = cvss_data
            
            cvss_str = str(cvss_score) if cvss_score else None
            sev = cvss_to_severity(cvss_score) if cvss_score else "MEDIUM"
            
            f.append(_mk_finding(
                name=f"WPScan: {title}",
                desc=description,
                rec="Update WordPress core/plugins/themes to the latest version. Review vulnerability references for specific patches.",
                sev=sev,
                cve=cve,
                cvss=cvss_str,
                scanner=["wpscan"]
            ))
    
    # Also add interesting findings (version detection, etc) as INFO
    if data.get("version") and data["version"].get("number"):
        version = data["version"]["number"]
        f.append(_mk_finding(
            name=f"WordPress Version Detected: {version}",
            desc=f"Running WordPress version {version}",
            rec="Verify this is the latest stable version",
            sev="INFO",
            scanner=["wpscan"]
        ))
    
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

# [ADDED: Audit trail helper for CMS auto-detection]
def add_cms_audit_finding(jid: str, detected_cms: Optional[str], triggered_scanner: Optional[str]):
    """
    Add an audit trail finding documenting the auto-detection decision.
    This creates transparency in the report about why specific scanners were selected.
    """
    job = get_job(jid)
    if not job:
        return
    
    if detected_cms:
        name = f"CMS Auto-Detection: {detected_cms.title()} Identified"
        desc = (f"Automated fingerprinting via WhatWeb detected {detected_cms} technology signatures. "
                f"Consequently, {triggered_scanner} was automatically engaged for targeted assessment. "
                f"Timestamp: {int(time.time())}")
        sev = "INFO"
    else:
        name = "CMS Auto-Detection: No CMS Found"
        desc = ("WhatWeb completed technology fingerprinting but did not detect WordPress, Drupal, or Joomla. "
                "CMS-specific scanners were automatically excluded to optimize scan duration.")
        sev = "INFO"
    
    finding = _mk_finding(
        name=name,
        desc=desc,
        rec="Verify that auto-detection results align with expected target technologies.",
        sev=sev,
        scanner=["whatweb", "orchestrator"]
    )
    
    # Inject into WhatWeb results so it appears in final aggregation
    if "whatweb" in job.get("scanner_results", {}):
        job["scanner_results"]["whatweb"].append(finding)
        
        # Also update the individual scanner report file if it exists
        try:
            scanner_report_path = os.path.join(REPORTS_DIR, f"{jid}_whatweb.json")
            if os.path.exists(scanner_report_path):
                with open(scanner_report_path, 'r', encoding='utf-8') as f:
                    report = json.load(f)
                report["findings"].append(finding)
                with open(scanner_report_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[add_cms_audit_finding] Failed to update report file: {e}", file=sys.stderr)
    
    set_job(jid, **job)

# [ADDED: Helper to extract Nuclei template tags from WhatWeb findings - PREP for next integration]
def extract_nuclei_tags_from_whatweb(findings: List[Dict[str, Any]]) -> List[str]:
    
    tags = set()
    tech_mapping = {
        # CMS
        "wordpress": "wordpress",
        "drupal": "drupal", 
        "joomla": "joomla",
        "magento": "magento",
        "prestashop": "prestashop",
        #Moder apps
        "jquery": "jquery",
        "html5": "generic",
        "script": "javascript",
        "x-frame-options": "misconfiguration",
        "uncommonheaders": "misconfiguration",
         # Node.js/Express
        "node.js": "nodejs",
        "express": "express",
        "angular": "angular",
        "webpack": "javascript",
        # Web Servers
        "nginx": "nginx",
        "apache": "apache",
        "iis": "iis",
        "tomcat": "tomcat",
        "jboss": "jboss",
        # Languages/Frameworks
        "php": "php",
        "jquery": "jquery",
        "bootstrap": "bootstrap",
        "angular": "angular",
        "react": "react",
        # Middleware
        "weblogic": "weblogic",
        "websphere": "websphere",
        "coldfusion": "coldfusion",
        # Databases (indirect detection)
        "mysql": "mysql",
        "postgresql": "postgresql",
        "mssql": "mssql",
        "mongodb": "mongodb",
        # Cloud/Infra
        "aws": "aws",
        "azure": "azure",
        "gcp": "gcp",
        "docker": "docker",
        "kubernetes": "k8s",
        # Panels
        "cpanel": "cpanel",
        "plesk": "plesk",
        "phpmyadmin": "phpmyadmin",
    }
    
    for finding in findings:
        vuln = finding.get("vulnerability", {})
        name = vuln.get("name", "").lower()
        desc = vuln.get("Description", "").lower()
        
        # Check technology detection findings
        if "technology detected:" in name:
            tech = name.split("technology detected:")[-1].strip().lower()
            
            # Direct matches
            for key, tag in tech_mapping.items():
                if key in tech or key in desc:
                    tags.add(tag)
            
            # Pattern matching for versioned tech (e.g., "Apache/2.4.41")
            if "apache" in tech or "apache" in desc:
                tags.add("apache")
            if "nginx" in tech or "nginx" in desc:
                tags.add("nginx")
                
    return list(tags)

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
    """WPScan runner with better error handling"""
    job = get_job(jid)
    job["scanner_status"]["wpscan"] = "running"
    set_job(jid, **job)
    
    try:
        cmd = build_wpscan_cmd(target, opts.get("wpscan", {}))
        print(f"[WPScan] Command: {' '.join(cmd)}", file=sys.stderr)
        
        # Use named volume for WPScan cache to avoid re-downloading data files
        volumes = {
            "wpscan_cache": {"bind": "/root/.wpscan", "mode": "rw"}
        }
        
        cid, code, out, err = run_container(WPSCAN_IMAGE, cmd, volumes=volumes)
        
        job = get_job(jid)
        job["containers"]["wpscan"] = cid
        set_job(jid, **job)
        
        print(f"[WPScan] Exit code: {code}", file=sys.stderr)
        
        # WPScan returns 0 on success, 1 on vulnerabilities found (which is good for us), 5 on critical errors
        if code not in [0, 1]:
            print(f"[WPScan] Warning: Exit code {code} may indicate scan issues", file=sys.stderr)
        
        if err:
            print(f"[WPScan] Stderr: {err[:500]}", file=sys.stderr)
        
        findings = normalize_wpscan(out, target)
        print(f"[WPScan] Parsed {len(findings)} findings", file=sys.stderr)
        
        finish_scanner(jid, "wpscan", code, findings, out, err, parsed_ok=True)
        
    except Exception as e:
        print(f"[WPScan] Exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        job = get_job(jid)
        job["scanner_status"]["wpscan"] = "error"
        job["scanner_stderr"]["wpscan"] = str(e)
        set_job(jid, **job)


def runner_w3af(jid: str, target: str, opts: Dict[str, Any]):
    """w3af runner with script file generation"""
    name = "w3af"
    job = get_job(jid)
    job["scanner_status"][name] = "running"
    set_job(jid, **job)
    
    try:
        import tempfile
        import os
        
        # Build command and script content
        cmd, script_content = build_w3af_cmd(target, opts.get(name, {}))
        
        # Create temp directory for w3af files
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "w3af_script.txt")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(output_dir, exist_ok=True)
            
            # Write script file
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            print(f"[w3af] Script written to {script_path}", file=sys.stderr)
            print(f"[w3af] Script content:\n{script_content}", file=sys.stderr)
            
            # Mount volumes: script dir and output dir
            volumes = {
                tmpdir: {"bind": "/w3af", "mode": "rw"}
            }
            
            # Run w3af (can take a long time, default timeout 30 mins)
            print(f"[w3af] Starting scan...", file=sys.stderr)
            cid, code, out, err = run_container(
                "andresriancho/w3af",  # Official w3af image
                cmd,
                volumes=volumes,
                **({"timeout": 1800} if not opts.get(name, {}).get("fast") else {"timeout": 600})
            )
            
            job = get_job(jid)
            job["containers"][name] = cid
            set_job(jid, **job)
            
            print(f"[w3af] Exit code: {code}", file=sys.stderr)
            
            # Read output files
            xml_output = ""
            txt_output = ""
            
            txt_path = os.path.join(output_dir, "w3af_report.txt")
            xml_path = os.path.join(output_dir, "w3af_report.xml")
            
            if os.path.exists(txt_path):
                with open(txt_path, 'r', encoding='utf-8', errors='replace') as f:
                    txt_output = f.read()
                print(f"[w3af] Text report: {len(txt_output)} bytes", file=sys.stderr)
            
            if os.path.exists(xml_path):
                with open(xml_path, 'r', encoding='utf-8', errors='replace') as f:
                    xml_output = f.read()
                print(f"[w3af] XML report: {len(xml_output)} bytes", file=sys.stderr)
            
            # Parse findings
            findings = normalize_w3af(txt_output, xml_output, target)
            print(f"[w3af] Parsed {len(findings)} findings", file=sys.stderr)
            
            # Save raw outputs for debugging
            full_stdout = f"=== TEXT OUTPUT ===\n{txt_output}\n=== XML OUTPUT ===\n{xml_output}\n=== CONSOLE STDOUT ===\n{out}"
            
            finish_scanner(jid, name, code, findings, full_stdout, err, parsed_ok=True)
            
    except Exception as e:
        print(f"[w3af] Exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        job = get_job(jid)
        job["scanner_status"][name] = "error"
        job["scanner_stderr"][name] = str(e)
        set_job(jid, **job)

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
    job = get_job(jid)
    job["scanner_status"]["nuclei"] = "running"
    set_job(jid, **job)
    
    try:
        # === IP RESOLUTION + HOST NETWORK ===
        original_target = target
        original_host = None
        parsed = urlparse(target if "://" in target else f"http://{target}")
        
        try:
            original_host = parsed.hostname
            ip = socket.gethostbyname(parsed.hostname)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            nuclei_target = f"{parsed.scheme}://{ip}:{port}{parsed.path or '/'}"
            
            print(f"[NUCLEI] Resolved {original_host} → {ip} | Using target: {nuclei_target}", file=sys.stderr)
            
            # Store network translation info for Host header
            if "nuclei" not in opts:
                opts["nuclei"] = {}
            opts["nuclei"]["_original_host"] = original_host
            opts["nuclei"]["_resolved_ip"] = ip
            
        except Exception as e:
            print(f"[NUCLEI] Resolution failed ({e}) — falling back to original", file=sys.stderr)
            nuclei_target = original_target
            original_host = parsed.hostname

        # Update templates
        if NUCLEI_UPDATE_ON_START:
            try:
                ensure_image(NUCLEI_IMAGE)
                print(f"[NUCLEI] Updating templates...", file=sys.stderr)
                docker_client.containers.run(
                    image=NUCLEI_IMAGE,
                    command=["nuclei", "-update-templates"],
                    detach=False, remove=True, stdout=True, stderr=True,
                    volumes={"nuclei_templates": {"bind": NUCLEI_TEMPLATES, "mode": "rw"}},
                    network="host"
                )
                print(f"[NUCLEI] Templates updated", file=sys.stderr)
            except Exception as e:
                print(f"[NUCLEI] Template update warning: {e}", file=sys.stderr)

        # Build command
        cmd = build_nuclei_cmd(nuclei_target, opts.get("nuclei", {}))
        print(f"[NUCLEI] Final command: {' '.join(cmd)}", file=sys.stderr)

        # === CONNECTION DEBUG TEST ===
        print(f"[NUCLEI DEBUG] Testing connectivity from inside container...", file=sys.stderr)
        test_url = f"http://{ip}:{port}/" if 'ip' in locals() else nuclei_target
        debug_cmd = ["curl", "-s", "-o", "/dev/null", "-w", 
                     "HTTP Code: %{http_code}, Time: %{time_total}s, Size: %{size_download}\n", 
                     "--max-time", "10", test_url]
        if original_host:
            debug_cmd.extend(["-H", f"Host: {original_host}"])
        
        _, debug_code, debug_out, debug_err = run_container(
            NUCLEI_IMAGE, debug_cmd, network="host"
        )
        print(f"[NUCLEI DEBUG] Curl test result: {debug_out.strip()} (exit: {debug_code})", file=sys.stderr)

        # Setup volumes - add tmp volume for output file
        volumes = {
            "nuclei_templates": {"bind": NUCLEI_TEMPLATES, "mode": "rw"},
            "nuclei_data": {"bind": "/root/.config/nuclei", "mode": "rw"},
            "nuclei_output": {"bind": "/tmp", "mode": "rw"}  # For output file
        }

        # === ACTUAL SCAN ===
        print(f"[NUCLEI] Starting scan... This may take a while", file=sys.stderr)
        cid, code, out, err = run_container(
            NUCLEI_IMAGE, cmd, volumes=volumes, network="host",
            **({"timeout": 3600} if opts.get("nuclei", {}).get("extended_timeout") else {})
        )

        print(f"[NUCLEI] Scan finished — Exit code: {code}", file=sys.stderr)
        
        # === READ OUTPUT FILE ===
        # Try to read the output file from the container
        print(f"[NUCLEI] Reading output file...", file=sys.stderr)
        cat_cmd = ["cat", "/tmp/nuclei_results.jsonl"]
        _, cat_code, file_content, cat_err = run_container(
            NUCLEI_IMAGE, cat_cmd, volumes=volumes, network="host"
        )
        
        # Use file content if stdout was empty or file has content
        if file_content and len(file_content.strip()) > 0:
            print(f"[NUCLEI] Found {len(file_content)} bytes in output file", file=sys.stderr)
            out = file_content
        elif out and len(out.strip()) > 0:
            print(f"[NUCLEI] Using stdout ({len(out)} bytes)", file=sys.stderr)
        else:
            print(f"[NUCLEI] WARNING: No output in file or stdout", file=sys.stderr)

        # === TEMPLATE COUNT VERIFICATION ===
        template_count = 0
        if err:
            # Parse template count from stderr
            match = re.search(r'Templates loaded for current scan:\s*(\d+)', err)
            if match:
                template_count = int(match.group(1))
                print(f"[NUCLEI] Template count: {template_count}", file=sys.stderr)
                
                # Warning if suspiciously low
                if template_count < 1000:
                    print(f"[NUCLEI] WARNING: Low template count ({template_count})!", file=sys.stderr)
            else:
                print(f"[NUCLEI] Could not determine template count", file=sys.stderr)
            
            # Check for connection errors in stderr
            if "context deadline exceeded" in err or "connection refused" in err.lower():
                print(f"[NUCLEI] WARNING: Connection errors detected!", file=sys.stderr)
            
            print(f"[NUCLEI] Stderr preview:\n{err[:2000]}", file=sys.stderr)

        job = get_job(jid)
        job["containers"]["nuclei"] = cid
        set_job(jid, **job)
        
        findings = normalize_nuclei(out, original_target)
        print(f"[NUCLEI] Parsed {len(findings)} findings from output", file=sys.stderr)
        
        # If no findings but templates were loaded, log details
        if not findings and template_count > 1000:
            print(f"[NUCLEI] NOTE: {template_count} templates executed but 0 findings", file=sys.stderr)
            print(f"[NUCLEI] This may mean the target doesn't match Nuclei signatures", file=sys.stderr)
        
        finish_scanner(jid, "nuclei", code, findings, out, err, parsed_ok=bool(findings))
        
    except Exception as e:
        print(f"[NUCLEI] Exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        job = get_job(jid)
        job["scanner_status"]["nuclei"] = "error"
        job["scanner_stderr"]["nuclei"] = str(e)
        set_job(jid, **job)
        

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
    
    # [ADDED: Enhanced error handling with graceful degradation]
    try:
        cmd = build_whatweb_cmd(target, opts.get("whatweb", {}))
        print(f"[DEBUG WHATWEB] Command: {cmd}", file=sys.stderr)
        
        cid, code, out, err = run_container(WHATWEB_IMAGE, cmd)
        
        job = get_job(jid)
        job["containers"]["whatweb"] = cid
        set_job(jid, **job)
        
        # Handle non-zero exit codes gracefully (WhatWeb returns non-zero on some redirects/Errors)
        if code != 0 and not out:
            print(f"[DEBUG WHATWEB] Non-zero exit {code} with empty output, attempting to continue", file=sys.stderr)
            # Create empty findings but don't fail the scan
            ww_findings = []
            cms_hits = []
        else:
            ww_findings, cms_hits = normalize_whatweb(out, target)
            
        job["whatweb_detected_cms"] = cms_hits
        finish_scanner(jid, "whatweb", code, ww_findings, out, err, parsed_ok=True)
        
        print(f"[DEBUG WHATWEB] Detected technologies: {len(ww_findings)}, CMS hits: {cms_hits}", file=sys.stderr)
        
    except Exception as e:
        print(f"[DEBUG WHATWEB] Exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        job = get_job(jid)
        job["scanner_status"]["whatweb"] = "error"
        job["scanner_stderr"]["whatweb"] = str(e)
        # [ADDED: Graceful degradation - ensure scan continues even if WhatWeb fails]
        job["whatweb_detected_cms"] = []
        set_job(jid, **job)

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
        # [ADDED: Enhanced WhatWeb execution with audit trail and Nuclei prep]
        print(f"[ORCHESTRATOR] Auto-mode: Running WhatWeb first for CMS detection", file=sys.stderr)
        
        # Run WhatWeb synchronously to decide CMS scanner
        try:
            set_job(jid, scanner_status={**job["scanner_status"], "whatweb":"running"})
            cmd = build_whatweb_cmd(target, opts.get("whatweb", {}))
            cid, code, out, err = run_container(WHATWEB_IMAGE, cmd)
            job = get_job(jid)
            job["containers"]["whatweb"] = cid
            
            # Parse results with error handling
            try:
                ww_findings, cms_hits = normalize_whatweb(out, target)
            except Exception as parse_err:
                print(f"[ORCHESTRATOR] WhatWeb parsing error: {parse_err}, continuing with empty results", file=sys.stderr)
                ww_findings, cms_hits = [], []
            
            job["whatweb_detected_cms"] = cms_hits
            finish_scanner(jid, "whatweb", code, ww_findings, out, err, parsed_ok=True)
            
            # [ADDED: Prep for Nuclei - extract tags from WhatWeb findings]
            nuclei_tags = extract_nuclei_tags_from_whatweb(ww_findings)
            if nuclei_tags:
                print(f"[ORCHESTRATOR] WhatWeb suggests Nuclei tags: {nuclei_tags}", file=sys.stderr)
                # Store for when Nuclei runner executes
                if "nuclei" not in opts:
                    opts["nuclei"] = {}
                opts["nuclei"]["_auto_tags"] = nuclei_tags

                # Also add specific CMS templates if detected
                cms_templates = {
                "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
                "drupal": ["drupal"],
                "joomla": ["joomla"]
            }
            for cms in cms_hits:
                if cms in cms_templates:
                    opts["nuclei"]["_auto_tags"].extend(cms_templates[cms])
                    opts["nuclei"]["_auto_tags"] = list(set(opts["nuclei"]["_auto_tags"]))  # dedupe
                
        except Exception as e:
            print(f"[ORCHESTRATOR] WhatWeb failed: {e}, continuing without CMS detection", file=sys.stderr)
            job = get_job(jid)
            job["scanner_status"]["whatweb"] = "error"
            job["scanner_stderr"]["whatweb"] = str(e)
            job["whatweb_detected_cms"] = []
            cms_hits = []
            set_job(jid, **job)
            # Continue with empty cms_hits (graceful degradation)

        # Decide CMS scanner based on WhatWeb results
        cms_to_run = None
        detected_cms_name = None
        for cms in ["wordpress","drupal","joomla"]:
            if cms in (get_job(jid).get("whatweb_detected_cms") or []):
                cms_to_run = CMS_SCANNERS[cms]
                detected_cms_name = cms
                break

        # [ADDED: Add audit trail finding documenting the decision]
        add_cms_audit_finding(jid, detected_cms_name, cms_to_run)

        effective = []
        for s in req:
            if s not in CMS_SCANNER_SET:
                effective.append(s)
        if cms_to_run:
            effective.append(cms_to_run)
            print(f"[ORCHESTRATOR] Auto-selected {cms_to_run} based on WhatWeb detection", file=sys.stderr)
        else:
            print(f"[ORCHESTRATOR] No CMS detected by WhatWeb, skipping CMS-specific scanners", file=sys.stderr)

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