#!/usr/bin/env python3
"""
ReconStarter - Authorized Bug Bounty Reconnaissance Tool
Safe, low-impact reconnaissance and enumeration for authorized testing only.

SAFETY NOTICE: This tool is designed for authorized bug bounty testing only.
It defaults to conservative, non-destructive behavior with rate limiting.
Do not use against targets without explicit written authorization.
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple, Any
import fnmatch

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "1.3.1"
USER_AGENT_DEFAULT = f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

class RateLimiter:
    """Thread-safe rate limiter for network requests"""

    def __init__(self, requests_per_second: float):
        if requests_per_second == 0:
            # No rate limiting when rate is 0
            self.min_interval = 0
        else:
            self.min_interval = 1.0 / requests_per_second
        self.last_request = 0.0
        self.lock = Lock()

    def wait(self):
        """Wait if necessary to respect rate limit"""
        if self.min_interval == 0:
            return  # No rate limiting

        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            self.last_request = time.time()


class SafeHTTPRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom redirect handler that respects scope boundaries"""

    def __init__(self, in_scope_patterns: List[str], out_of_scope_patterns: List[str],
                 allow_out_of_scope: bool = False):
        self.in_scope_patterns = in_scope_patterns
        self.out_of_scope_patterns = out_of_scope_patterns
        self.allow_out_of_scope = allow_out_of_scope
        self.redirect_info = {}  # Store redirect information

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Check if redirect is allowed based on scope"""
        parsed_new = urllib.parse.urlparse(newurl)
        new_host = parsed_new.netloc.split(':')[0]

        if not is_in_scope(new_host, self.in_scope_patterns, self.out_of_scope_patterns):
            if not self.allow_out_of_scope:
                # Block redirect and store information
                original_url = req.get_full_url()
                self.redirect_info[original_url] = {
                    'blocked_redirect_to': newurl,
                    'reason': 'out_of_scope'
                }
                return None

        # Allow redirect
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def log_info(message: str, logger: Optional[logging.Logger] = None):
    """Log info message to both logger and console"""
    if logger:
        logger.info(message)
    if HAS_RICH:
        console.print(f"[green][INFO][/green] {message}")
    else:
        print(f"[INFO] {message}")


def log_warning(message: str, logger: Optional[logging.Logger] = None):
    """Log warning message to both logger and console"""
    if logger:
        logger.warning(message)
    if HAS_RICH:
        console.print(f"[yellow][WARNING][/yellow] {message}")
    else:
        print(f"[WARNING] {message}")


def log_error(message: str, logger: Optional[logging.Logger] = None):
    """Log error message to both logger and console"""
    if logger:
        logger.error(message)
    if HAS_RICH:
        console.print(f"[red][ERROR][/red] {message}")
    else:
        print(f"[ERROR] {message}")


def is_valid_domain(domain: str) -> bool:
    """Basic domain validation"""
    if not domain or '.' not in domain:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    if len(domain) > 253:
        return False
    # Allow wildcards for patterns but not in actual domains
    if '*' in domain:
        return domain.count('*') == 1 and domain.startswith('*.')
    return True


def is_in_scope(host: str, in_scope_patterns: List[str], out_of_scope_patterns: List[str]) -> bool:
    """Check if a host is in scope based on patterns"""
    # First check out-of-scope patterns (exclusions take priority)
    for pattern in out_of_scope_patterns:
        if fnmatch.fnmatch(host, pattern):
            return False

    # Then check in-scope patterns
    for pattern in in_scope_patterns:
        if fnmatch.fnmatch(host, pattern):
            return True

    return False


def setup_logging(run_dir: Path, verbose: bool = False) -> logging.Logger:
    """Setup file and console logging with fixed configuration"""
    logger = logging.getLogger('recon_starter')
    logger.handlers.clear()  # Clear any existing handlers

    # Set logger level
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False  # Prevent duplicate messages

    # File handler only (no console handler to prevent duplicates)
    log_file = run_dir / "recon.log"
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=3)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def create_run_directory(base_dir: Path) -> Path:
    """Create a timestamped run directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base_dir / "runs" / timestamp

    # Create directory structure
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "raw").mkdir(exist_ok=True)
    (run_dir / "results").mkdir(exist_ok=True)

    return run_dir


def get_latest_run_directory(base_dir: Path) -> Optional[Path]:
    """Get the most recent run directory"""
    runs_dir = base_dir / "runs"
    if not runs_dir.exists():
        return None

    run_dirs = [d for d in runs_dir.iterdir() if d.is_dir()]
    if not run_dirs:
        return None

    # Sort by modification time, most recent first
    run_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return run_dirs[0]


def load_targets(domain: Optional[str], domains_file: Optional[str], logger: logging.Logger) -> List[str]:
    """Load target domains from command line or file"""
    targets = []

    if domain:
        if is_valid_domain(domain):
            targets.append(domain.lower())
        else:
            log_error(f"Invalid domain: {domain}", logger)
            sys.exit(1)

    if domains_file:
        try:
            with open(domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if is_valid_domain(line):
                            targets.append(line.lower())
                        else:
                            log_warning(f"Skipping invalid domain: {line}", logger)
        except FileNotFoundError:
            log_error(f"Domains file not found: {domains_file}", logger)
            sys.exit(1)
        except Exception as e:
            log_error(f"Error reading domains file: {e}", logger)
            sys.exit(1)

    # Remove duplicates while preserving order
    unique_targets = []
    seen = set()
    for target in targets:
        if target not in seen:
            unique_targets.append(target)
            seen.add(target)

    if not unique_targets:
        log_error("No valid target domains specified", logger)
        sys.exit(1)

    return unique_targets


def check_tool_availability() -> Dict[str, bool]:
    """Check which external tools are available in PATH"""
    tools = {
        "subfinder": False,
        "httpx": False,
        "dnsx": False,
        "tlsx": False,
        "whois": False,
        "dig": False,
        "jq": False,
        "gau": False,
        "waybackurls": False
    }
    for tool in tools:
        tools[tool] = shutil.which(tool) is not None
    return tools


def get_tool_version(tool: str) -> Optional[str]:
    """Get version of external tool if available"""
    try:
        if tool == "subfinder":
            result = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
        elif tool == "httpx":
            result = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
        elif tool in ["dnsx", "tlsx"]:
            result = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
        elif tool in ["gau", "waybackurls"]:
            result = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def print_dependency_status():
    """Print status of all dependencies and installation hints"""
    print("ReconStarter Dependency Status:")
    print("=" * 40)

    # Required dependencies
    print("\nRequired Dependencies:")
    if HAS_DNSPYTHON:
        print("✓ dnspython - Available")
    else:
        print("✗ dnspython - Missing")
        print("  Install with: pip install dnspython")

    # Optional dependencies
    print("\nOptional Dependencies:")
    if HAS_RICH:
        print("✓ rich - Available (enhanced output)")
    else:
        print("✗ rich - Missing")
        print("  Install with: pip install rich")

    if HAS_REQUESTS:
        print("✓ requests - Available (CT logs)")
    else:
        print("✗ requests - Missing")
        print("  Install with: pip install requests")

    # External tools
    print("\nExternal Tools:")
    tools = check_tool_availability()
    tool_info = {
        "subfinder": "subdomain discovery",
        "httpx": "HTTP probing",
        "dnsx": "DNS resolution",
        "tlsx": "TLS analysis",
        "gau": "archived URL discovery (optional)",
        "waybackurls": "archived URL discovery (optional)"
    }

    for tool, available in tools.items():
        if tool in tool_info:
            status = "✓" if available else "✗"
            desc = tool_info[tool]
            print(f"{status} {tool} - {'Available' if available else 'Missing'} ({desc})")

    print("\nInstallation hints:")
    print("- Go tools: Use 'go install' or download from GitHub releases")
    print("- subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    print("- httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    print("- dnsx: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    print("- gau: go install github.com/lc/gau/v2/cmd/gau@latest")
    print("- waybackurls: go install github.com/tomnomnom/waybackurls@latest")


def run_subfinder(domain: str, raw_dir: Path, rate_limiter: RateLimiter,
                  logger: logging.Logger, host_sources: Dict[str, Set[str]],
                  reuse_cache: bool = True, dry_run: bool = False) -> Set[str]:
    """Run subfinder for subdomain discovery"""
    cache_file = raw_dir / f"subfinder_{domain}.txt"

    if reuse_cache and cache_file.exists():
        log_info(f"Using cached subfinder results for {domain}", logger)
        try:
            with open(cache_file, 'r') as f:
                subdomains = set()
                for line in f:
                    subdomain = line.strip().lower()
                    if subdomain and is_valid_domain(subdomain):
                        subdomains.add(subdomain)
                        host_sources[subdomain].add("subfinder")
                return subdomains
        except Exception as e:
            log_warning(f"Failed to read subfinder cache for {domain}: {e}", logger)

    if dry_run:
        log_info(f"[DRY RUN] Would run subfinder for {domain}", logger)
        return set()

    if not shutil.which("subfinder"):
        log_warning("subfinder not found, skipping subdomain discovery", logger)
        return set()

    log_info(f"Running subfinder for {domain}", logger)

    try:
        rate_limiter.wait()
        result = subprocess.run([
            "subfinder", "-d", domain, "-silent", "-o", str(cache_file)
        ], capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            if result.stderr:
                log_warning(f"subfinder completed with warnings for {domain}: {result.stderr.strip()}", logger)
            else:
                log_warning(f"subfinder exited with code {result.returncode} for {domain}", logger)

        # Read results from output file
        subdomains = set()
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                for line in f:
                    subdomain = line.strip().lower()
                    if subdomain and is_valid_domain(subdomain):
                        subdomains.add(subdomain)
                        host_sources[subdomain].add("subfinder")

        log_info(f"Found {len(subdomains)} unique subdomains for {domain}", logger)
        return subdomains

    except subprocess.TimeoutExpired:
        log_error(f"subfinder timeout for {domain} (120s limit)", logger)
        return set()
    except Exception as e:
        log_error(f"subfinder error for {domain}: {e}", logger)
        return set()


def collect_ct_logs(domain: str, raw_dir: Path, rate_limiter: RateLimiter,
                   logger: logging.Logger, host_sources: Dict[str, Set[str]],
                   user_agent: str, timeout: int = 10, reuse_cache: bool = True,
                   dry_run: bool = False) -> Set[str]:
    """Collect subdomains from Certificate Transparency logs with caching and retries"""
    cache_file = raw_dir / f"ct_{domain}.json"

    if reuse_cache and cache_file.exists():
        log_info(f"Using cached CT results for {domain}", logger)
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            subdomains = set()
            for name in cache_data.get('names', []):
                if is_valid_domain(name):
                    subdomains.add(name.lower())
                    host_sources[name.lower()].add("ct")

            return subdomains
        except Exception as e:
            log_warning(f"Failed to read CT cache for {domain}: {e}", logger)

    if dry_run:
        log_info(f"[DRY RUN] Would query CT logs for {domain}", logger)
        return set()

    if not HAS_REQUESTS:
        log_warning("requests package not available, skipping CT log collection", logger)
        return set()

    log_info(f"Querying Certificate Transparency logs for {domain}", logger)

    try:
        import requests
        session = requests.Session()
        session.headers.update({'User-Agent': user_agent})

        # Retry logic with exponential backoff
        max_retries = 3
        backoff_base = 2.0

        for attempt in range(max_retries):
            try:
                rate_limiter.wait()  # Respect rate limit

                # Query crt.sh API
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = session.get(url, timeout=timeout)

                # Handle specific error codes gracefully
                if response.status_code == 503:
                    if attempt < max_retries - 1:
                        sleep_time = backoff_base ** attempt
                        logger.debug(f"CT service unavailable (503), retrying in {sleep_time}s")
                        time.sleep(sleep_time)
                        continue
                    else:
                        log_warning(f"CT service temporarily unavailable for {domain} (503 Service Unavailable)", logger)
                        return set()

                response.raise_for_status()
                ct_data = response.json()
                subdomains = set()

                for cert in ct_data:
                    name_value = cert.get('name_value', '')
                    # Split on newlines as multiple domains can be in one field
                    for name in name_value.split('\n'):
                        name = name.strip()

                        # Apply CT scope filtering: only accept exact domain or subdomains
                        if name == domain or name.endswith(f".{domain}"):
                            # Skip wildcards and validate format
                            if not name.startswith('*') and is_valid_domain(name):
                                subdomains.add(name.lower())
                                host_sources[name.lower()].add("ct")

                # Cache results with metadata
                cache_data = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'domain': domain,
                    'names': sorted(list(subdomains)),
                    'total_certs': len(ct_data)
                }

                with open(cache_file, 'w') as f:
                    json.dump(cache_data, f, indent=2)

                log_info(f"Found {len(subdomains)} unique domains from CT logs for {domain}", logger)
                return subdomains

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    sleep_time = backoff_base ** attempt
                    logger.debug(f"CT query failed (attempt {attempt + 1}), retrying in {sleep_time}s: {e}")
                    time.sleep(sleep_time)
                else:
                    log_warning(f"CT log collection failed for {domain} after {max_retries} attempts: {e}", logger)
                    return set()
            except json.JSONDecodeError as e:
                log_warning(f"Invalid JSON response from CT logs for {domain}: {e}", logger)
                return set()

    except Exception as e:
        log_warning(f"CT log collection failed for {domain}: {e}", logger)
        return set()


def run_dnsx_resolve(hosts: Set[str], raw_dir: Path, rate_limiter: RateLimiter,
                    logger: logging.Logger, host_sources: Dict[str, Set[str]],
                    host_notes: Dict[str, List[Dict]], timeout: int = 5,
                    reuse_cache: bool = True, dry_run: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run dnsx for DNS resolution with caching and error handling"""
    if not hosts:
        return {}

    cache_file = raw_dir / f"dnsx_resolve_{len(hosts)}_hosts.json"

    # Try to use cached results first
    if reuse_cache and cache_file.exists():
        log_info(f"Using cached DNS results for {len(hosts)} hosts", logger)
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            # Validate cache and filter to requested hosts
            dns_results = {}
            for host in hosts:
                if host in cache_data.get('results', {}):
                    dns_results[host] = cache_data['results'][host]
                    # Update host sources to include dnsx
                    host_sources[host].add("dnsx")

            if len(dns_results) == len(hosts):
                log_info(f"All {len(hosts)} hosts found in cache", logger)
                return dns_results
            else:
                log_info(f"Partial cache hit: {len(dns_results)}/{len(hosts)} hosts", logger)
        except Exception as e:
            log_warning(f"Failed to read DNS cache: {e}", logger)

    if dry_run:
        log_info(f"[DRY RUN] Would resolve DNS for {len(hosts)} hosts", logger)
        return {}

    # Check if dnsx is available
    if not shutil.which('dnsx'):
        log_warning("dnsx tool not found, skipping DNS resolution", logger)
        return {}

    log_info(f"Running DNS resolution for {len(hosts)} hosts", logger)

    try:
        # Create temporary file with hosts
        hosts_file = raw_dir / f"dnsx_hosts_{int(time.time())}.txt"
        with open(hosts_file, 'w') as f:
            for host in sorted(hosts):
                f.write(f"{host}\n")

        # Construct dnsx command with json output
        cmd = [
            'dnsx',
            '-l', str(hosts_file),
            '-json',
            '-silent',
            '-a',      # Query A records
            '-aaaa',   # Query AAAA records
            '-retry', '2',
            '-timeout', f'{timeout}s'
        ]

        # Add rate limiting if specified
        if hasattr(rate_limiter, 'min_interval') and rate_limiter.min_interval > 0:
            rps = int(1.0 / rate_limiter.min_interval)
            if rps > 0:
                cmd.extend(['-rate-limit', str(rps)])

        log_info(f"Running: {' '.join(cmd[:6])} ... (truncated)", logger)

        # Run dnsx with timeout
        start_time = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=max(60, len(hosts) * 2))

            duration = time.time() - start_time

            if result.returncode != 0:
                if result.stderr:
                    log_warning(f"dnsx completed with warnings: {result.stderr.strip()}", logger)
                else:
                    log_warning(f"dnsx exited with code {result.returncode}", logger)

            # Parse JSON results
            dns_results = {}
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            dns_data = json.loads(line)
                            host = dns_data.get('host', '').lower()

                            if host and host in hosts:
                                # Check if host has any A or AAAA records
                                a_records = dns_data.get('a', [])
                                aaaa_records = dns_data.get('aaaa', [])
                                ip_count = len(a_records) + len(aaaa_records)

                                # Only include hosts with actual IP addresses
                                if ip_count > 0:
                                    dns_results[host] = {
                                        'a_records': a_records,
                                        'aaaa_records': aaaa_records,
                                        'resolver': dns_data.get('resolver', ''),
                                        'timestamp': datetime.now(timezone.utc).isoformat()
                                    }

                                    # Update host sources
                                    host_sources[host].add("dnsx")

                                    # Add note about successful resolution
                                    note = {
                                        "type": "dns_resolved",
                                        "ip_count": ip_count,
                                        "a_records": len(a_records),
                                        "aaaa_records": len(aaaa_records)
                                    }
                                    host_notes[host].append(note)
                                else:
                                    # Add note about failed resolution (no IP records)
                                    note = {
                                        "type": "dns_no_records",
                                        "message": "Host resolved but has no A or AAAA records",
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    }
                                    host_notes[host].append(note)

                        except json.JSONDecodeError as e:
                            logger.debug(f"Failed to parse dnsx output line: {line}: {e}")
                            continue

            # Track hosts that failed DNS resolution
            failed_hosts = hosts - set(dns_results.keys())
            for host in failed_hosts:
                note = {
                    "type": "dns_resolution_failed",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                host_notes[host].append(note)

            log_info(f"DNS resolution completed in {duration:.1f}s: {len(dns_results)} resolved, {len(failed_hosts)} failed", logger)

            # Cache results
            cache_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'total_hosts': len(hosts),
                'resolved_hosts': len(dns_results),
                'failed_hosts': len(failed_hosts),
                'duration': duration,
                'results': dns_results
            }

            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)

            return dns_results

        except subprocess.TimeoutExpired:
            log_error(f"dnsx timeout for {len(hosts)} hosts", logger)
            return {}

        finally:
            # Clean up temporary file
            if hosts_file.exists():
                hosts_file.unlink()

    except Exception as e:
        log_error(f"dnsx resolution error: {e}", logger)
        return {}


def resolve_dns_records(host: str, rate_limiter: RateLimiter, logger: logging.Logger) -> Dict[str, List[str]]:
    """Resolve DNS records for a host using dnspython with rate limiting"""
    if not HAS_DNSPYTHON:
        logger.debug("dnspython not available, skipping DNS resolution")
        return {}

    import dns.resolver
    import dns.exception

    records = {
        'A': [],
        'AAAA': [],
        'CNAME': [],
        'MX': [],
        'NS': [],
        'TXT': []
    }

    for record_type in records.keys():
        try:
            rate_limiter.wait()
            answers = dns.resolver.resolve(host, record_type)
            for answer in answers:
                if record_type == 'MX':
                    records[record_type].append(f"{answer.preference} {answer.exchange}")
                else:
                    records[record_type].append(str(answer))
        except (dns.exception.DNSException, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Record type not found, continue
        except Exception as e:
            logger.debug(f"DNS resolution error for {host} {record_type}: {e}")

    return records


def get_tls_info(host: str, port: int, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Get TLS certificate information for a host with improved parsing"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                # Preserve certificate structure as list of key-value pairs
                subject_list = []
                for item in cert.get('subject', []):
                    for key, value in item:
                        subject_list.append({"key": key, "value": value})

                issuer_list = []
                for item in cert.get('issuer', []):
                    for key, value in item:
                        issuer_list.append({"key": key, "value": value})

                tls_info = {
                    'subject': subject_list,
                    'issuer': issuer_list,
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'sans': []
                }

                # Extract Subject Alternative Names
                for ext in cert.get('subjectAltName', []):
                    if ext[0] == 'DNS':
                        tls_info['sans'].append(ext[1])

                return tls_info
    except Exception:
        return None


def calculate_cache_key(hosts: Set[str], ports: List[int], enable_get: bool,
                       follow_redirects: bool) -> str:
    """Calculate a cache key for httpx results based on parameters"""
    # Create a deterministic string from the parameters
    hosts_str = '|'.join(sorted(hosts))
    ports_str = '|'.join(map(str, sorted(ports)))
    params_str = f"{enable_get}|{follow_redirects}"

    # Create hash
    full_str = f"{hosts_str}|{ports_str}|{params_str}"
    return hashlib.md5(full_str.encode()).hexdigest()[:16]


def find_cached_httpx_results(raw_dir: Path, cache_key: str) -> Optional[Path]:
    """Find cached httpx results file by cache key"""
    cache_pattern = f"httpx_*_{cache_key}.json"
    for cache_file in raw_dir.glob(cache_pattern):
        return cache_file

    # Also check for exact cache key match
    cache_key_file = raw_dir / f"httpx_{cache_key}.json"
    if cache_key_file.exists():
        return cache_key_file
    return None


def parse_cached_httpx_results(cache_file: Path, logger: logging.Logger,
                              host_notes: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Parse cached httpx results from JSON file"""
    results = []

    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)

        # Handle both direct results list and metadata wrapper
        if isinstance(cache_data, list):
            parsed_results = cache_data
        else:
            parsed_results = cache_data.get('results', [])

        for result in parsed_results:
            if 'host' in result and 'http_result' in result:
                results.append(result)

        log_info(f"Loaded {len(results)} cached HTTP results", logger)

    except Exception as e:
        log_warning(f"Failed to parse cached httpx results: {e}", logger)

    return results


def run_httpx_probe(hosts: Set[str], raw_dir: Path, in_scope_patterns: List[str],
                   out_of_scope_patterns: List[str], ports: List[int],
                   enable_get: bool, rate: float, concurrency: int, timeout: int,
                   follow_redirects: bool, user_agent: str, logger: logging.Logger,
                   host_sources: Dict[str, Set[str]], host_notes: Dict[str, List[Dict]],
                   reuse_cache: bool = True, dry_run: bool = False) -> List[Dict[str, Any]]:
    """Run httpx for HTTP probing with caching and robust parsing"""

    if not hosts:
        return []

    # Calculate cache key
    cache_key = calculate_cache_key(hosts, ports, enable_get, follow_redirects)

    if reuse_cache:
        cached_file = find_cached_httpx_results(raw_dir, cache_key)
        if cached_file:
            log_info(f"Using cached httpx results (key: {cache_key})", logger)
            return parse_cached_httpx_results(cached_file, logger, host_notes)

    if not shutil.which("httpx"):
        log_warning("httpx not found in PATH, performing manual HTTP probing", logger)
        return run_manual_http_probe(hosts, in_scope_patterns, out_of_scope_patterns,
                                   ports, enable_get, rate, timeout, follow_redirects,
                                   user_agent, logger, host_sources, host_notes, dry_run)

    if dry_run:
        log_info(f"[DRY RUN] Would probe {len(hosts)} hosts with httpx (cache key: {cache_key})", logger)
        return []

    # Convert hosts to list and batch them
    host_list = sorted(list(hosts))
    batch_size = 100
    all_results = []

    for i in range(0, len(host_list), batch_size):
        batch_hosts = host_list[i:i + batch_size]
        batch_results = run_httpx_batch(batch_hosts, raw_dir, ports, enable_get,
                                      rate, concurrency, timeout, follow_redirects,
                                      user_agent, logger, cache_key)
        all_results.extend(batch_results)

    # Process results and add host information
    processed_results = []
    for probe_result in all_results:
        try:
            # Extract host from URL - httpx may use 'url', 'input', or 'host'
            url = probe_result.get('url', probe_result.get('input', ''))
            if not url:
                continue

            parsed_url = urllib.parse.urlparse(url)
            original_host = parsed_url.netloc.split(':')[0]

            # Handle final URL (redirects) - httpx may use 'final-url' or 'final_url'
            final_url = probe_result.get('final-url', probe_result.get('final_url', url))
            parsed_final = urllib.parse.urlparse(final_url)
            final_host = parsed_final.netloc.split(':')[0]

            # Check for redirects and scope violations
            redirect_blocked = False
            if original_host != final_host:
                if not is_in_scope(final_host, in_scope_patterns, out_of_scope_patterns):
                    if not follow_redirects:
                        # Record blocked redirect
                        redirect_blocked = True
                        note = {
                            "type": "redirect_blocked",
                            "from": url,
                            "to": final_url
                        }
                        host_notes[original_host].append(note)

                        # Use original URL since redirect was blocked
                        final_url = url
                        final_host = original_host

            # Extract status code - httpx may use different field names
            status = probe_result.get('status-code', probe_result.get('status_code', probe_result.get('status', 0)))

            # Extract port
            port = parsed_final.port or (443 if parsed_final.scheme == 'https' else 80)

            http_result = {
                'scheme': parsed_final.scheme or parsed_url.scheme,
                'port': port,
                'status': status,
                'final_url': final_url,
                'method': probe_result.get('method', 'HEAD'),
                'headers': {},
                'content_length': probe_result.get('content-length', probe_result.get('content_length')),
            }

            # Add redirect info if blocked
            if redirect_blocked:
                http_result['redirect_blocked_to'] = probe_result.get('final-url', probe_result.get('final_url', ''))

            # Extract server header - httpx may use 'webserver' or 'web-server'
            server = probe_result.get('webserver', probe_result.get('web-server', probe_result.get('server')))
            if server:
                http_result['headers']['server'] = server

            # Add title if present (only when GET was used)
            if 'title' in probe_result:
                http_result['title'] = probe_result['title']

            # Add TLS info if HTTPS
            if parsed_final.scheme == 'https':
                tls_info = get_tls_info(final_host, port, timeout)
                if tls_info:
                    http_result['tls'] = tls_info

            processed_results.append({
                'host': original_host,
                'http_result': http_result
            })

        except Exception as e:
            logger.debug(f"HTTP probe error for {url}: {e}")

    return processed_results


def run_httpx_batch(hosts: List[str], raw_dir: Path, ports: List[int],
                   enable_get: bool, rate: float, concurrency: int, timeout: int,
                   follow_redirects: bool, user_agent: str, logger: logging.Logger,
                   cache_key: str) -> List[Dict[str, Any]]:
    """Run httpx for a batch of hosts"""
    timestamp = int(time.time())
    hosts_file = raw_dir / f"httpx_hosts_{timestamp}_{cache_key}.txt"
    output_file = raw_dir / f"httpx_results_{timestamp}_{cache_key}.json"

    try:
        # Write hosts to file
        with open(hosts_file, 'w') as f:
            for host in hosts:
                f.write(f"{host}\n")

        # Build httpx command
        cmd = [
            'httpx',
            '-l', str(hosts_file),
            '-json',
            '-silent',
            '-timeout', str(timeout),
            '-threads', str(concurrency),
            '-o', str(output_file)
        ]

        # Add ports
        if ports and ports != [80, 443]:
            cmd.extend(['-ports', ','.join(map(str, ports))])

        # Add method
        if enable_get:
            cmd.extend(['-method', 'GET'])

        # Add rate limiting
        if rate > 0:
            cmd.extend(['-rate-limit', str(int(rate))])

        # Add redirect handling
        if follow_redirects:
            cmd.extend(['-follow-redirects'])

        # User agent
        cmd.extend(['-user-agent', user_agent])

        # Additional useful flags
        cmd.extend(['-title', '-tech-detect', '-web-server'])

        log_info(f"Running httpx for {len(hosts)} hosts", logger)

        # Run httpx
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max(300, len(hosts) * 3))

        # Handle httpx results
        results = []
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                probe_result = json.loads(line)
                                results.append(probe_result)
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                logger.debug(f"Error reading httpx output: {e}")

        if result.returncode != 0:
            # Enhanced error handling
            if result.stderr.strip():
                log_warning(f"httpx completed with issues: {result.stderr.strip()}", logger)
            else:
                log_warning(f"httpx exited with code {result.returncode} (command: {' '.join(cmd[:3])} ...)", logger)

        log_info(f"httpx found {len(results)} responding services", logger)
        return results

    except subprocess.TimeoutExpired:
        log_error(f"httpx timeout for {len(hosts)} hosts", logger)
        return []
    except Exception as e:
        log_error(f"httpx error: {e}", logger)
        return []
    finally:
        # Cleanup temporary files
        for temp_file in [hosts_file, output_file]:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except:
                    pass


def run_manual_http_probe(hosts: Set[str], in_scope_patterns: List[str],
                         out_of_scope_patterns: List[str], ports: List[int],
                         enable_get: bool, rate: float, timeout: int,
                         follow_redirects: bool, user_agent: str,
                         logger: logging.Logger, host_sources: Dict[str, Set[str]],
                         host_notes: Dict[str, List[Dict]], dry_run: bool = False) -> List[Dict[str, Any]]:
    """Manual HTTP probing when httpx is not available"""
    if dry_run:
        log_info(f"[DRY RUN] Would manually probe {len(hosts)} hosts", logger)
        return []

    results = []
    rate_limiter = RateLimiter(rate)

    log_info(f"Manually probing {len(hosts)} hosts (httpx not available)", logger)

    # Create safe redirect handler
    redirect_handler = SafeHTTPRedirectHandler(in_scope_patterns, out_of_scope_patterns, follow_redirects)
    opener = urllib.request.build_opener(redirect_handler)
    opener.addheaders = [('User-Agent', user_agent)]

    for host in hosts:
        for port in ports:
            for scheme in ['https', 'http'] if port == 443 else (['https'] if port == 443 else ['http']):
                try:
                    rate_limiter.wait()

                    url = f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}"
                    method = "GET" if enable_get else "HEAD"

                    if method == "HEAD":
                        req = urllib.request.Request(url, method='HEAD')
                    else:
                        req = urllib.request.Request(url)

                    try:
                        response = opener.open(req, timeout=timeout)

                        http_result = {
                            'scheme': scheme,
                            'port': port,
                            'status': response.code,
                            'final_url': response.url,
                            'method': method,
                            'headers': dict(response.headers),
                            'content_length': response.headers.get('content-length')
                        }

                        # Check for blocked redirects
                        if url in redirect_handler.redirect_info:
                            redirect_info = redirect_handler.redirect_info[url]
                            http_result['redirect_blocked_to'] = redirect_info['blocked_redirect_to']
                            note = {
                                "type": "redirect_blocked",
                                "from": url,
                                "to": redirect_info['blocked_redirect_to']
                            }
                            host_notes[host].append(note)

                        # Add TLS info for HTTPS
                        if scheme == 'https':
                            tls_info = get_tls_info(host, port, timeout)
                            if tls_info:
                                http_result['tls'] = tls_info

                        results.append({
                            'host': host,
                            'http_result': http_result
                        })

                    except urllib.error.HTTPError as e:
                        # Still record HTTP errors as they indicate a responding service
                        http_result = {
                            'scheme': scheme,
                            'port': port,
                            'status': e.code,
                            'final_url': e.url or url,
                            'method': method,
                            'headers': dict(e.headers) if e.headers else {},
                        }

                        results.append({
                            'host': host,
                            'http_result': http_result
                        })

                except Exception as e:
                    logger.debug(f"Manual probe error for {scheme}://{host}:{port}: {e}")

    return results


def generate_wordlist_subdomains(domain: str, wordlist_file: str, logger: logging.Logger,
                                host_sources: Dict[str, Set[str]]) -> Set[str]:
    """Generate subdomains using a wordlist"""
    if not os.path.isfile(wordlist_file):
        log_error(f"Wordlist file not found: {wordlist_file}", logger)
        return set()

    try:
        with open(wordlist_file, 'r') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        subdomains = set()
        for word in words:
            subdomain = f"{word}.{domain}"
            if is_valid_domain(subdomain):
                subdomains.add(subdomain.lower())
                host_sources[subdomain.lower()].add("wordlist")

        log_info(f"Generated {len(subdomains)} wordlist subdomains for {domain}", logger)
        return subdomains

    except Exception as e:
        log_error(f"Error reading wordlist {wordlist_file}: {e}", logger)
        return set()


def fetch_archived_urls(domain: str, raw_dir: Path, rate_limiter: RateLimiter,
                       logger: logging.Logger, host_sources: Dict[str, Set[str]],
                       max_urls: int = 200, reuse_cache: bool = True,
                       dry_run: bool = False) -> Set[str]:
    """Fetch archived URLs using gau or waybackurls (optional feature)"""
    cache_file = raw_dir / f"archived_{domain}.txt"

    if reuse_cache and cache_file.exists():
        log_info(f"Using cached archived URLs for {domain}", logger)
        try:
            with open(cache_file, 'r') as f:
                urls = set()
                for line in f:
                    url = line.strip()
                    if url:
                        parsed = urllib.parse.urlparse(url)
                        host = parsed.netloc.split(':')[0]
                        if host:
                            urls.add(host.lower())
                            host_sources[host.lower()].add("archived")
                return urls
        except Exception as e:
            log_warning(f"Failed to read archived URL cache for {domain}: {e}", logger)

    if dry_run:
        log_info(f"[DRY RUN] Would fetch archived URLs for {domain}", logger)
        return set()

    # Check for available tools
    gau_available = shutil.which('gau')
    wayback_available = shutil.which('waybackurls')

    if not gau_available and not wayback_available:
        log_warning("Neither gau nor waybackurls available, skipping archived URL discovery", logger)
        return set()

    log_info(f"Fetching archived URLs for {domain} (limited to {max_urls} URLs)", logger)

    urls = set()
    try:
        # Try gau first
        if gau_available:
            try:
                rate_limiter.wait()
                result = subprocess.run([
                    'gau', '--threads', '1', '--timeout', '30', domain
                ], capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n')[:max_urls]:
                        if line.strip():
                            parsed = urllib.parse.urlparse(line.strip())
                            host = parsed.netloc.split(':')[0]
                            if host and (host == domain or host.endswith(f".{domain}")):
                                urls.add(host.lower())
                                host_sources[host.lower()].add("archived")

            except subprocess.TimeoutExpired:
                log_warning(f"gau timeout for {domain}", logger)
            except Exception as e:
                log_warning(f"gau error for {domain}: {e}", logger)

        # Try waybackurls if we don't have enough URLs
        if len(urls) < max_urls and wayback_available:
            try:
                rate_limiter.wait()
                result = subprocess.run([
                    'waybackurls', domain
                ], capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n')[:max_urls - len(urls)]:
                        if line.strip():
                            parsed = urllib.parse.urlparse(line.strip())
                            host = parsed.netloc.split(':')[0]
                            if host and (host == domain or host.endswith(f".{domain}")):
                                urls.add(host.lower())
                                host_sources[host.lower()].add("archived")

            except subprocess.TimeoutExpired:
                log_warning(f"waybackurls timeout for {domain}", logger)
            except Exception as e:
                log_warning(f"waybackurls error for {domain}: {e}", logger)

        # Cache results
        with open(cache_file, 'w') as f:
            for url in urls:
                f.write(f"https://{url}\n")

        log_info(f"Found {len(urls)} unique hosts from archived URLs for {domain}", logger)

    except Exception as e:
        log_warning(f"Archived URL collection failed for {domain}: {e}", logger)

    return urls


def run_enrichment_checks(live_hosts: List[Dict[str, Any]], raw_dir: Path,
                         rate_limiter: RateLimiter, logger: logging.Logger,
                         user_agent: str, timeout: int, enable_get: bool,
                         max_js_per_host: int, max_bytes: int,
                         dry_run: bool = False) -> Dict[str, Dict[str, Any]]:
    """Run safe enrichment checks on live hosts"""
    if dry_run:
        log_info(f"[DRY RUN] Would run enrichment checks on {len(live_hosts)} hosts", logger)
        return {}

    if not HAS_REQUESTS:
        log_warning("requests package not available, skipping enrichment", logger)
        return {}

    log_info(f"Running enrichment checks on {len(live_hosts)} live hosts", logger)

    import requests
    enrichment_results = {}

    # Fixed list of endpoints to check (no brute forcing)
    check_paths = [
        '/robots.txt',
        '/.well-known/security.txt',
        '/.well-known/openid-configuration',
        '/api',
        '/api/v1',
        '/api/v2',
        '/v1',
        '/v2',
        '/graphql',
        '/health',
        '/health/ready',
        '/healthcheck',
        '/metrics',
        '/status',
        '/swagger.json',
        '/openapi.json',
        '/oauth/authorize',
        '/.git',
        '/.env',
        '/admin',
        '/login',
        '/wp-admin',
        '/wp-login.php',
        '/sitemap.xml'
    ]

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    for i, host_data in enumerate(live_hosts, 1):
        host = host_data['host']
        http_results = host_data.get('http', [])

        if not http_results:
            continue

        log_info(f"Enrichment [{i}/{len(live_hosts)}]: Analyzing {host}", logger)

        enrichment = {
            'security_headers': {},
            'cookies': {},
            'cors': {},
            'well_known': {},
            'js_endpoints': [],
            'endpoint_checks': {}
        }

        # Process existing HTTP results for headers
        for http_result in http_results:
            scheme = http_result['scheme']
            port = http_result['port']
            base_url = f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}"

            # Analyze existing headers
            headers = http_result.get('headers', {})
            enrichment['security_headers'] = analyze_security_headers(headers)
            enrichment['cors'] = analyze_cors_headers(headers)

            # Check for cookies in Set-Cookie headers
            set_cookie = headers.get('set-cookie', headers.get('Set-Cookie', ''))
            if set_cookie:
                enrichment['cookies'] = analyze_cookies(set_cookie)

        # Perform additional endpoint checks
        primary_http = http_results[0]  # Use first HTTP result as primary
        scheme = primary_http['scheme']
        port = primary_http['port']
        base_url = f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}"

        for path in check_paths:
            try:
                rate_limiter.wait()

                method = 'GET' if enable_get else 'HEAD'
                url = f"{base_url}{path}"

                response = session.request(
                    method, url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True
                )

                endpoint_result = {
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'content_type': response.headers.get('content-type', ''),
                    'size': response.headers.get('content-length', 0)
                }

                # For certain endpoints, read a small amount of content
                if enable_get and path in ['/.well-known/openid-configuration', '/api', '/graphql']:
                    try:
                        content = response.content[:max_bytes]
                        if content:
                            endpoint_result['content_sample'] = content.decode('utf-8', errors='ignore')[:1000]
                    except Exception:
                        pass

                enrichment['endpoint_checks'][path] = endpoint_result

                # Special handling for well-known endpoints
                if path.startswith('/.well-known/'):
                    if response.status_code == 200:
                        enrichment['well_known'][path] = {
                            'status': response.status_code,
                            'content_type': response.headers.get('content-type', '')
                        }

            except Exception as e:
                logger.debug(f"Endpoint check error for {host}{path}: {e}")
                continue

        # JavaScript discovery (if GET enabled)
        if enable_get:
            log_info(f"Enrichment [{i}/{len(live_hosts)}]: Discovering JS endpoints for {host}", logger)
            try:
                js_endpoints = discover_js_endpoints(
                    base_url, session, rate_limiter, logger,
                    max_js_per_host, max_bytes, timeout
                )
                enrichment['js_endpoints'] = js_endpoints
                if js_endpoints:
                    log_info(f"Enrichment [{i}/{len(live_hosts)}]: Found {len(js_endpoints)} JS endpoints for {host}", logger)
            except Exception as e:
                logger.debug(f"JS discovery error for {host}: {e}")

        # Count findings for progress reporting
        endpoint_count = len([ep for ep in enrichment['endpoint_checks'].values() if ep.get('status', 0) < 400])
        security_headers_count = len([h for h in enrichment['security_headers'].values() if h.get('present')])

        log_info(f"Enrichment [{i}/{len(live_hosts)}]: Completed {host} - {endpoint_count} endpoints, {security_headers_count} security headers", logger)

        enrichment_results[host] = enrichment

    log_info(f"Enrichment phase completed: {len(enrichment_results)}/{len(live_hosts)} hosts successfully analyzed", logger)
    return enrichment_results


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze security headers"""
    security_headers = {}

    header_checks = {
        'content-security-policy': 'csp',
        'strict-transport-security': 'hsts',
        'x-frame-options': 'xfo',
        'x-content-type-options': 'xcto',
        'referrer-policy': 'referrer_policy',
        'x-xss-protection': 'xss_protection'
    }

    for header_name, key in header_checks.items():
        value = headers.get(header_name, headers.get(header_name.title(), ''))
        security_headers[key] = {
            'present': bool(value),
            'value': value if value else None
        }

    return security_headers


def analyze_cors_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze CORS headers"""
    cors_headers = {}

    cors_header_names = [
        'access-control-allow-origin',
        'access-control-allow-credentials',
        'access-control-allow-methods',
        'access-control-allow-headers'
    ]

    for header_name in cors_header_names:
        value = headers.get(header_name, headers.get(header_name.title(), ''))
        if value:
            cors_headers[header_name] = value

    return cors_headers


def analyze_cookies(set_cookie_header: str) -> Dict[str, Any]:
    """Analyze cookie security attributes"""
    cookie_analysis = {
        'total_cookies': 0,
        'secure_cookies': 0,
        'httponly_cookies': 0,
        'samesite_cookies': 0,
        'issues': []
    }

    # Simple parsing of Set-Cookie header(s)
    cookies = set_cookie_header.split(',') if ',' in set_cookie_header else [set_cookie_header]

    for cookie in cookies:
        cookie = cookie.strip()
        if not cookie:
            continue

        cookie_analysis['total_cookies'] += 1

        cookie_lower = cookie.lower()
        if 'secure' in cookie_lower:
            cookie_analysis['secure_cookies'] += 1
        else:
            cookie_analysis['issues'].append('Missing Secure flag')

        if 'httponly' in cookie_lower:
            cookie_analysis['httponly_cookies'] += 1
        else:
            cookie_analysis['issues'].append('Missing HttpOnly flag')

        if 'samesite=' in cookie_lower:
            cookie_analysis['samesite_cookies'] += 1

    return cookie_analysis


def discover_js_endpoints(base_url: str, session: requests.Session,
                         rate_limiter: RateLimiter, logger: logging.Logger,
                         max_js_files: int, max_bytes: int, timeout: int) -> List[str]:
    """Safely discover JavaScript endpoints from main page"""
    js_endpoints = []

    try:
        # Get main page
        rate_limiter.wait()
        response = session.get(base_url, timeout=timeout, stream=True)

        if response.status_code != 200:
            return js_endpoints

        # Read limited content
        content = response.content[:max_bytes]
        html_content = content.decode('utf-8', errors='ignore')

        # Simple regex to find JavaScript sources
        js_pattern = r'src=["\']([^"\']*\.js[^"\']*)["\']'
        matches = re.findall(js_pattern, html_content, re.IGNORECASE)

        js_files_found = 0
        for js_path in matches[:max_js_files]:
            if js_files_found >= max_js_files:
                break

            try:
                # Convert relative URLs to absolute
                if js_path.startswith('/'):
                    js_url = f"{base_url.rstrip('/')}{js_path}"
                elif js_path.startswith('http'):
                    # Skip external JS files for safety
                    continue
                else:
                    js_url = f"{base_url.rstrip('/')}/{js_path}"

                rate_limiter.wait()
                js_response = session.get(js_url, timeout=timeout, stream=True)

                if js_response.status_code == 200:
                    js_content = js_response.content[:max_bytes].decode('utf-8', errors='ignore')

                    # Extract potential API endpoints
                    api_patterns = [
                        r'["\']([^"\']*/?api/[^"\']*)["\']',
                        r'["\']([^"\']*/v[0-9]+/[^"\']*)["\']',
                        r'["\']([^"\']*/?graphql[^"\']*)["\']'
                    ]

                    for pattern in api_patterns:
                        endpoints = re.findall(pattern, js_content, re.IGNORECASE)
                        for endpoint in endpoints:
                            if endpoint not in js_endpoints:
                                js_endpoints.append(endpoint)

                js_files_found += 1

            except Exception as e:
                logger.debug(f"JS file processing error for {js_url}: {e}")
                continue

    except Exception as e:
        logger.debug(f"JS discovery error for {base_url}: {e}")

    return js_endpoints[:10]  # Limit results


def calculate_host_score(host_data: Dict[str, Any], enrichment_data: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Calculate practical ranking score for a host

    New approach:
    - Base score from responding endpoints
    - Bonus for high-value paths
    - Override signals for immediate attention
    - Penalties for low-signal indicators
    - Uniqueness/rarity boost
    """
    score = 0
    signals = []
    overrides = []
    high_value_hits = []

    http_results = host_data.get('http', [])
    if not http_results:
        return score, signals

    endpoint_checks = enrichment_data.get('endpoint_checks', {})

    # High-value paths that get significant bonuses
    high_value_paths = {
        '/admin': 4,
        '/wp-admin': 3,
        '/graphql': 3,
        '/api': 2,
        '/api/v1': 2,
        '/api/v2': 2,
        '/.env': 4,
        '/.git': 3,
        '/swagger.json': 3,
        '/openapi.json': 3,
        '/oauth/authorize': 3,
        '/metrics': 2,
        '/health': 1,
        '/status': 1
    }

    # Override signals that immediately flag for manual review
    override_indicators = {
        'auth_wall': [401, 403],  # Authentication required
        'server_error': range(500, 600),  # Server errors
        'admin_access': ['/admin', '/wp-admin'],
        'config_exposure': ['/.env', '/.git'],
        'api_discovery': ['/graphql', '/swagger.json', '/openapi.json']
    }

    # Base score: 1 point per meaningful response (not 404s)
    responding_endpoints = 0
    for path, result in endpoint_checks.items():
        status = result.get('status', 0)
        # Only count meaningful responses: success (2xx, 3xx) or security-relevant (401, 403, 5xx)
        if status in range(200, 400) or status in [401, 403] or status in range(500, 600):
            responding_endpoints += 1

            # High-value path bonuses (only for meaningful responses)
            if path in high_value_paths:
                bonus = high_value_paths[path]
                score += bonus
                high_value_hits.append(f"{path}(+{bonus})")
                signals.append(f"high_value_path_{path.replace('/', '_').replace('.', '_')}")

    score += responding_endpoints
    if responding_endpoints > 0:
        signals.append(f"responding_endpoints_{responding_endpoints}")

    # Override detection
    for indicator_type, criteria in override_indicators.items():
        triggered = False

        if indicator_type in ['auth_wall', 'server_error']:
            for result in endpoint_checks.values():
                status = result.get('status', 0)
                if (indicator_type == 'auth_wall' and status in criteria) or \
                   (indicator_type == 'server_error' and status in criteria):
                    overrides.append(indicator_type)
                    signals.append(f"override_{indicator_type}")
                    triggered = True
                    break

        elif indicator_type in ['admin_access', 'config_exposure', 'api_discovery']:
            for path in criteria:
                if path in endpoint_checks and endpoint_checks[path].get('status', 0) > 0:
                    overrides.append(indicator_type)
                    signals.append(f"override_{indicator_type}")
                    break

    # Authentication and technology detection bonuses
    auth_bonus = 0
    for http in http_results:
        title = http.get('title', '').lower()
        headers = http.get('headers', {})

        # OAuth/SSO detection
        if any(term in title for term in ['login', 'oauth', 'sso']):
            auth_bonus += 2
            signals.append("auth_interface_detected")

        # API indicators
        content_type = headers.get('content-type', '').lower()
        if 'application/json' in content_type:
            auth_bonus += 1
            signals.append("json_api_response")

        # Bearer token hints
        www_auth = headers.get('www-authenticate', '').lower()
        if 'bearer' in www_auth:
            auth_bonus += 2
            signals.append("bearer_auth_detected")

    score += auth_bonus

    # CORS and security headers
    if enrichment_data.get('cors'):
        score += 1
        signals.append("cors_headers_present")

    # Penalties for low-signal patterns
    penalties = 0
    for http in http_results:
        title = http.get('title', '').lower()

        # Generic error pages or placeholders
        if any(term in title for term in ['error', 'not found', 'coming soon', 'under construction', 'default page']):
            penalties += 1
            signals.append("generic_content_penalty")

        # CDN-only responses
        server = http.get('headers', {}).get('server', '').lower()
        if any(term in server for term in ['cloudflare-nginx', 'cloudfront']):
            penalties += 1
            signals.append("cdn_only_penalty")

    score = max(0, score - penalties)  # Don't go negative

    # Uniqueness boost for rare combinations
    unique_patterns = 0
    if len(high_value_hits) >= 3:  # Multiple high-value endpoints
        unique_patterns += 2
        signals.append("multiple_high_value_endpoints")

    if overrides and high_value_hits:  # Both overrides and high-value hits
        unique_patterns += 2
        signals.append("override_and_high_value_combo")

    score += unique_patterns

    # Store additional metadata
    if overrides:
        signals.append(f"overrides_triggered_{len(overrides)}")
    if high_value_hits:
        signals.append(f"high_value_hits_{len(high_value_hits)}")

    return score, signals, overrides, high_value_hits


def create_manual_review_outputs(consolidated_results: List[Dict[str, Any]],
                                run_dir: Path, logger: logging.Logger,
                                manual_threshold: int = 8):
    """Create manual review output files"""
    results_dir = run_dir / "results"

    # Filter manual review candidates
    manual_review_hosts = [
        host for host in consolidated_results
        if host.get('manual_review_candidate', False)
    ]

    log_info(f"Creating manual review outputs for {len(manual_review_hosts)} candidates (threshold: {manual_threshold})", logger)

    # Create manual_review_targets.json
    manual_review_file = results_dir / "manual_review_targets.json"
    with open(manual_review_file, 'w') as f:
        json.dump({
            'metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'total_candidates': len(manual_review_hosts),
                'threshold': manual_threshold,
                'version': VERSION
            },
            'candidates': manual_review_hosts
        }, f, indent=2)

    # Create manual_review_targets.md
    markdown_file = results_dir / "manual_review_targets.md"
    with open(markdown_file, 'w') as f:
        f.write("# Manual Review Targets\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total candidates: {len(manual_review_hosts)}\n")
        f.write(f"Score threshold: {manual_threshold}\n\n")

        if manual_review_hosts:
            f.write("## High-Priority Targets\n\n")
            f.write("| Host | Score | IP | Overrides | High-value | Status | HTTPS | Title |\n")
            f.write("|------|-------|----|-----------|-----------|---------|---------|---------|\n")

            for host_data in sorted(manual_review_hosts, key=lambda x: x.get('score', 0), reverse=True):
                host = host_data['host']
                score = host_data.get('score', 0)
                ip_addresses = ', '.join(host_data.get('ip_addresses', [])[:2])  # Show first 2 IPs
                if len(host_data.get('ip_addresses', [])) > 2:
                    ip_addresses += '...'
                overrides = ', '.join(host_data.get('overrides', []))
                high_value_hits = ', '.join(host_data.get('high_value_hits', []))

                http_results = host_data.get('http', [])
                if http_results:
                    status = http_results[0].get('status', 'N/A')
                    https = 'Yes' if any(h.get('scheme') == 'https' for h in http_results) else 'No'
                    title = http_results[0].get('title', 'N/A')[:30]
                else:
                    status = https = title = 'N/A'

                f.write(f"| {host} | {score} | {ip_addresses} | {overrides} | {high_value_hits} | {status} | {https} | {title} |\n")

            f.write("\n## Detailed Analysis\n\n")
            for host_data in manual_review_hosts:
                f.write(f"### {host_data['host']} (Score: {host_data.get('score', 0)})\n\n")

                # IP addresses
                if host_data.get('ip_addresses'):
                    f.write(f"**IP Addresses:** {', '.join(host_data.get('ip_addresses', []))}\n\n")

                # Override signals
                if host_data.get('overrides'):
                    f.write(f"**⚠️ Override Signals:** {', '.join(host_data.get('overrides', []))}\n\n")

                # High-value hits
                if host_data.get('high_value_hits'):
                    f.write(f"**🎯 High-value Hits:** {', '.join(host_data.get('high_value_hits', []))}\n\n")

                f.write(f"**All Signals:** {', '.join(host_data.get('signals', []))}\n\n")

                # HTTP details
                http_results = host_data.get('http', [])
                if http_results:
                    f.write("**HTTP Services:**\n")
                    for http in http_results:
                        f.write(f"- {http.get('scheme', '')}://{host_data['host']}:{http.get('port', '')} ")
                        f.write(f"(Status: {http.get('status', 'N/A')})\n")

                # Enrichment data
                enrichment = host_data.get('enrichment', {})
                if enrichment.get('security_headers'):
                    f.write("\n**Security Headers:**\n")
                    for header, info in enrichment['security_headers'].items():
                        status = "Present" if info.get('present') else "Missing"
                        f.write(f"- {header}: {status}\n")

                f.write("\n---\n\n")

        else:
            f.write("No hosts met the manual review threshold.\n")

    # Create host_scores.csv
    csv_file = results_dir / "host_scores.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Host', 'Score', 'Manual_Review', 'IP_Addresses', 'Overrides', 'High_Value_Hits', 'Signals', 'Top_Status', 'HTTPS', 'Title', 'Server'])

        for host_data in consolidated_results:
            host = host_data['host']
            score = host_data.get('score', 0)
            manual_review = host_data.get('manual_review_candidate', False)
            ip_addresses = '; '.join(host_data.get('ip_addresses', []))
            overrides = '; '.join(host_data.get('overrides', []))
            high_value_hits = '; '.join(host_data.get('high_value_hits', []))
            signals = '; '.join(host_data.get('signals', []))

            http_results = host_data.get('http', [])
            if http_results:
                top_status = http_results[0].get('status', '')
                https = any(h.get('scheme') == 'https' for h in http_results)
                title = http_results[0].get('title', '')
                server = http_results[0].get('headers', {}).get('server', '')
            else:
                top_status = https = title = server = ''

            writer.writerow([host, score, manual_review, ip_addresses, overrides, high_value_hits, signals, top_status, https, title, server])

    log_info(f"Manual review outputs created: {len(manual_review_hosts)} candidates", logger)
    log_info(f"- JSON targets: {manual_review_file}", logger)
    log_info(f"- Markdown report: {markdown_file}", logger)
    log_info(f"- CSV scores: {csv_file}", logger)


def consolidate_results(targets: List[str], all_hosts: Set[str], http_results: List[Dict],
                       in_scope_patterns: List[str], out_of_scope_patterns: List[str],
                       host_sources: Dict[str, Set[str]], host_notes: Dict[str, List[Dict]],
                       rate_limiter: RateLimiter, logger: logging.Logger,
                       dns_results: Dict[str, Dict[str, Any]] = None,
                       enrichment_results: Dict[str, Dict[str, Any]] = None,
                       enable_scoring: bool = True, manual_threshold: int = 8) -> List[Dict[str, Any]]:
    """Consolidate all results into structured format with scoring"""
    host_data = {}

    # Initialize all hosts
    for host in all_hosts:
        host_data[host] = {
            'input_domain': None,
            'host': host,
            'in_scope': is_in_scope(host, in_scope_patterns, out_of_scope_patterns),
            'source': sorted(list(host_sources.get(host, set()))),
            'dns': {},
            'http': [],
            'notes': host_notes.get(host, []),
            'enrichment': {},
            'score': 0,
            'signals': [],
            'manual_review_candidate': False,
            'ip_addresses': [],
            'overrides': [],
            'high_value_hits': []
        }

    # Map hosts to their input domains
    for host in all_hosts:
        for target in targets:
            if host == target or host.endswith(f".{target}"):
                host_data[host]['input_domain'] = target
                break

    # Add DNS information and IP addresses
    dns_results = dns_results or {}
    for host in all_hosts:
        if host in dns_results:
            # Use dnsx results
            host_data[host]['dns'] = dns_results[host]
        elif host_data[host]['in_scope']:
            # Fallback to dnspython for any missed hosts
            host_data[host]['dns'] = resolve_dns_records(host, rate_limiter, logger)

        # Extract IP addresses from DNS records
        dns_data = host_data[host]['dns']
        ip_addresses = []
        if isinstance(dns_data, dict):
            ip_addresses.extend(dns_data.get('a_records', []))
            ip_addresses.extend(dns_data.get('aaaa_records', []))
        host_data[host]['ip_addresses'] = ip_addresses

    # Add HTTP results
    for result in http_results:
        host = result['host']
        if host in host_data:
            host_data[host]['http'].append(result['http_result'])

    # Add enrichment data and calculate scores
    enrichment_results = enrichment_results or {}

    if enable_scoring:
        live_hosts_for_scoring = [host for host in host_data if host_data[host]['http']]
        log_info(f"Calculating security scores for {len(live_hosts_for_scoring)} live hosts", logger)

    scored_hosts = 0
    for host in host_data:
        if host in enrichment_results:
            host_data[host]['enrichment'] = enrichment_results[host]

        # Calculate score for hosts with HTTP results
        if enable_scoring and host_data[host]['http']:
            score, signals, overrides, high_value_hits = calculate_host_score(host_data[host], enrichment_results.get(host, {}))
            host_data[host]['score'] = score
            host_data[host]['signals'] = signals
            host_data[host]['overrides'] = overrides
            host_data[host]['high_value_hits'] = high_value_hits
            host_data[host]['manual_review_candidate'] = score >= manual_threshold or len(overrides) > 0
            scored_hosts += 1

    if enable_scoring and scored_hosts > 0:
        manual_review_count = len([h for h in host_data.values() if h.get('manual_review_candidate')])
        log_info(f"Scoring completed: {scored_hosts} hosts scored, {manual_review_count} manual review candidates (threshold: {manual_threshold})", logger)

    return list(host_data.values())


def write_results(consolidated_results: List[Dict], run_dir: Path,
                 run_metadata: Dict, logger: logging.Logger):
    """Write results to JSON Lines and Markdown files"""
    results_dir = run_dir / "results"

    log_info(f"Writing results for {len(consolidated_results)} hosts to {results_dir}", logger)

    # Write JSON Lines
    jsonl_file = results_dir / "hosts.jsonl"
    with open(jsonl_file, 'w') as f:
        for host_data in consolidated_results:
            f.write(json.dumps(host_data) + '\n')

    log_info(f"JSONL results written to {jsonl_file} ({len(consolidated_results)} hosts)", logger)

    # Write metadata
    metadata_file = results_dir / "metadata.json"
    with open(metadata_file, 'w') as f:
        json.dump(run_metadata, f, indent=2)

    log_info(f"Run metadata written to {metadata_file}", logger)

    # Generate summary report
    log_info("Generating summary reports...", logger)
    write_summary_report(consolidated_results, run_metadata, results_dir, logger)


def write_summary_report(results: List[Dict], metadata: Dict, results_dir: Path, logger: logging.Logger):
    """Generate a summary report in Markdown format"""
    output_file = results_dir / "summary.md"

    # Calculate statistics
    total_hosts = len(results)
    in_scope_hosts = [r for r in results if r['in_scope']]
    live_hosts = [r for r in results if r['http']]
    live_in_scope = [r for r in live_hosts if r['in_scope']]
    manual_review_candidates = [r for r in results if r.get('manual_review_candidate', False)]

    with open(output_file, 'w') as f:
        f.write(f"# Reconnaissance Summary Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Version:** {metadata.get('version', 'Unknown')}\n")
        f.write(f"**Run Directory:** {metadata.get('run_dir', 'Unknown')}\n\n")

        f.write(f"## Statistics\n\n")
        f.write(f"- **Total Hosts Discovered:** {total_hosts}\n")
        f.write(f"- **In-Scope Hosts:** {len(in_scope_hosts)}\n")
        f.write(f"- **Live Services:** {len(live_hosts)}\n")
        f.write(f"- **Live In-Scope:** {len(live_in_scope)}\n")
        f.write(f"- **Manual Review Candidates:** {len(manual_review_candidates)}\n\n")

        # Target domains
        f.write(f"## Target Domains\n\n")
        for domain in metadata.get('targets', []):
            domain_hosts = [r for r in results if r.get('input_domain') == domain]
            f.write(f"- **{domain}:** {len(domain_hosts)} hosts discovered\n")

        # Manual review summary
        if manual_review_candidates:
            f.write(f"\n## High-Priority Manual Review Candidates\n\n")
            for result in sorted(manual_review_candidates, key=lambda x: x.get('score', 0), reverse=True):
                score = result.get('score', 0)
                signals = ', '.join(result.get('signals', []))
                f.write(f"- **{result['host']}** (Score: {score}) - {signals}\n")

        # Live services summary
        if live_in_scope:
            f.write(f"\n## Live In-Scope Services\n\n")
            for result in sorted(live_in_scope, key=lambda x: x['host']):
                f.write(f"### {result['host']}\n")
                f.write(f"**Sources**: {', '.join(result['source'])}\n")
                if result['http']:
                    for http in result['http']:
                        f.write(f"- **{http['scheme']}://{result['host']}:{http['port']}** ")
                        f.write(f"(Status: {http['status']})")
                        if http.get('title'):
                            f.write(f" - {http['title']}")
                        if http.get('redirect_blocked_to'):
                            f.write(f" [Redirect blocked to: {http['redirect_blocked_to']}]")
                        f.write("\n")
                f.write("\n")

        f.write(f"## Run Configuration\n\n")
        f.write(f"- **Rate Limit**: {metadata.get('rate', 'N/A')} req/sec\n")
        f.write(f"- **Concurrency**: {metadata.get('concurrency', 'N/A')}\n")
        f.write(f"- **Timeout**: {metadata.get('timeout', 'N/A')}s\n")
        f.write(f"- **GET Requests**: {'Enabled' if metadata.get('enable_get') else 'Disabled (HEAD only)'}\n")
        f.write(f"- **Ports Scanned**: {', '.join(map(str, metadata.get('ports', [])))}\n")
        f.write(f"- **Cache Reuse**: {'Enabled' if metadata.get('reuse_cache') else 'Disabled'}\n")
        f.write(f"- **Scoring**: {'Enabled' if metadata.get('enable_scoring') else 'Disabled'}\n")
        f.write(f"- **DNS Resolution**: {'Skipped' if metadata.get('skip_dns') else 'Enabled'}\n")

    log_info(f"Summary report written to {output_file}", logger)


class ReconUIHandler(SimpleHTTPRequestHandler):
    """Simple HTTP handler for the recon UI"""

    def __init__(self, *args, results_data=None, **kwargs):
        self.results_data = results_data or {}
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.generate_ui_html().encode())
        elif self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.results_data).encode())
        else:
            self.send_error(404)

    def generate_ui_html(self) -> str:
        """Generate the HTML for the web UI"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconStarter Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
        .filters {{ margin: 20px 0; }}
        .filters input, .filters select {{ margin: 5px; padding: 5px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .live {{ background-color: #d4edda; }}
        .manual-review {{ background-color: #fff3cd; }}
        .out-of-scope {{ color: #6c757d; }}
        .score-high {{ font-weight: bold; color: #dc3545; }}
        .score-medium {{ font-weight: bold; color: #fd7e14; }}
        .score-low {{ color: #28a745; }}
        .overrides {{ background-color: #f8d7da; font-weight: bold; }}
        .high-value {{ background-color: #cce7ff; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ReconStarter Results</h1>
        <p>Version: {VERSION} | Generated: <span id="timestamp"></span></p>
        <p>Total Hosts: <span id="total-hosts"></span> | Live: <span id="live-hosts"></span> | Manual Review: <span id="manual-review-hosts"></span></p>
    </div>

    <div class="filters">
        <input type="text" id="search" placeholder="Search hosts..." />
        <select id="status-filter">
            <option value="all">All Hosts</option>
            <option value="live">Live Only</option>
            <option value="manual-review">Manual Review Only</option>
            <option value="in-scope">In-Scope Only</option>
        </select>
        <select id="source-filter">
            <option value="all">All Sources</option>
            <option value="subfinder">Subfinder</option>
            <option value="ct">CT Logs</option>
            <option value="dnsx">DNS Resolved</option>
            <option value="wordlist">Wordlist</option>
        </select>
        <select id="override-filter">
            <option value="all">All Overrides</option>
            <option value="overrides-only">Override Signals Only</option>
            <option value="high-value-only">High-value Hits Only</option>
        </select>
    </div>

    <table id="results-table">
        <thead>
            <tr>
                <th>Host</th>
                <th>Score</th>
                <th>Manual?</th>
                <th>IP</th>
                <th>Status</th>
                <th>Sources</th>
                <th>HTTP Services</th>
                <th>Overrides</th>
                <th>High-value hits</th>
                <th>Signals</th>
                <th>Notes</th>
            </tr>
        </thead>
        <tbody id="results-body">
        </tbody>
    </table>

    <script>
        let allResults = [];

        async function loadResults() {{
            try {{
                const response = await fetch('/api/data');
                const data = await response.json();

                allResults = data.results || [];
                document.getElementById('timestamp').textContent = new Date(data.metadata.timestamp).toLocaleString();
                updateStats();
                renderTable(allResults);
            }} catch (error) {{
                console.error('Failed to load results:', error);
            }}
        }}

        function updateStats() {{
            const total = allResults.length;
            const live = allResults.filter(r => r.http && r.http.length > 0).length;
            const manualReview = allResults.filter(r => r.manual_review_candidate).length;

            document.getElementById('total-hosts').textContent = total;
            document.getElementById('live-hosts').textContent = live;
            document.getElementById('manual-review-hosts').textContent = manualReview;
        }}

        function renderTable(results) {{
            const tbody = document.getElementById('results-body');
            tbody.innerHTML = '';

            results.forEach(result => {{
                const row = document.createElement('tr');
                if (result.http && result.http.length > 0) row.classList.add('live');
                if (result.manual_review_candidate) row.classList.add('manual-review');
                if (!result.in_scope) row.classList.add('out-of-scope');
                if (result.overrides && result.overrides.length > 0) row.classList.add('overrides');
                if (result.high_value_hits && result.high_value_hits.length > 0) row.classList.add('high-value');

                const scoreClass = result.score >= 8 ? 'score-high' :
                                 result.score >= 4 ? 'score-medium' : 'score-low';

                const httpServices = result.http ? result.http.map(h =>
                    `${{h.scheme}}://${{result.host}}:${{h.port}} (${{h.status}})`
                ).join('<br>') : 'None';

                const ipAddresses = result.ip_addresses ? result.ip_addresses.slice(0, 3).join(', ') +
                    (result.ip_addresses.length > 3 ? '...' : '') : 'None';
                const manualReview = result.manual_review_candidate ? '✓' : '';
                const overrides = result.overrides ? result.overrides.join(', ') : '';
                const highValueHits = result.high_value_hits ? result.high_value_hits.join(', ') : '';
                const signals = result.signals ? result.signals.join(', ') : '';
                const notes = result.notes ? result.notes.length : 0;

                row.innerHTML = `
                    <td>${{result.host}}</td>
                    <td class="${{scoreClass}}">${{result.score}}</td>
                    <td>${{manualReview}}</td>
                    <td title="${{result.ip_addresses ? result.ip_addresses.join(', ') : ''}}">${{ipAddresses}}</td>
                    <td>${{result.in_scope ? (result.http.length > 0 ? 'Live' : 'Down') : 'Out-of-scope'}}</td>
                    <td>${{result.source.join(', ')}}</td>
                    <td>${{httpServices}}</td>
                    <td>${{overrides}}</td>
                    <td>${{highValueHits}}</td>
                    <td>${{signals}}</td>
                    <td>${{notes}} notes</td>
                `;
                tbody.appendChild(row);
            }});
        }}

        function filterResults() {{
            const searchTerm = document.getElementById('search').value.toLowerCase();
            const statusFilter = document.getElementById('status-filter').value;
            const sourceFilter = document.getElementById('source-filter').value;
            const overrideFilter = document.getElementById('override-filter').value;

            let filtered = allResults.filter(result => {{
                const matchesSearch = result.host.toLowerCase().includes(searchTerm);

                let matchesStatus = true;
                if (statusFilter === 'live') matchesStatus = result.http && result.http.length > 0;
                else if (statusFilter === 'manual-review') matchesStatus = result.manual_review_candidate;
                else if (statusFilter === 'in-scope') matchesStatus = result.in_scope;

                let matchesSource = true;
                if (sourceFilter !== 'all') matchesSource = result.source.includes(sourceFilter);

                let matchesOverride = true;
                if (overrideFilter === 'overrides-only') matchesOverride = result.overrides && result.overrides.length > 0;
                else if (overrideFilter === 'high-value-only') matchesOverride = result.high_value_hits && result.high_value_hits.length > 0;

                return matchesSearch && matchesStatus && matchesSource && matchesOverride;
            }});

            renderTable(filtered);
        }}

        document.getElementById('search').addEventListener('input', filterResults);
        document.getElementById('status-filter').addEventListener('change', filterResults);
        document.getElementById('source-filter').addEventListener('change', filterResults);
        document.getElementById('override-filter').addEventListener('change', filterResults);

        loadResults();
    </script>
</body>
</html>'''


def serve_ui(run_dir: Path, port: int, logger: logging.Logger):
    """Serve the web UI for results"""
    try:
        # Load results data
        results_file = run_dir / "results" / "hosts.jsonl"
        metadata_file = run_dir / "results" / "metadata.json"

        results_data = {"results": [], "metadata": {}}

        if results_file.exists():
            with open(results_file, 'r') as f:
                for line in f:
                    if line.strip():
                        results_data["results"].append(json.loads(line))

        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                results_data["metadata"] = json.load(f)

        # Create handler with results data
        handler = lambda *args, **kwargs: ReconUIHandler(*args, results_data=results_data, **kwargs)

        # Start server
        server = HTTPServer(('localhost', port), handler)
        log_info(f"Starting web UI on http://localhost:{port}", logger)
        log_info("Press Ctrl+C to stop the server", logger)

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log_info("Shutting down web server", logger)
            server.shutdown()

    except Exception as e:
        log_error(f"Failed to start web UI: {e}", logger)


def main():
    parser = argparse.ArgumentParser(
        description="ReconStarter - Safe reconnaissance for authorized bug bounty testing",
        epilog="""
Examples:
  # Basic domain recon with scoring
  python recon_starter.py --domain example.com --out ./recon_example

  # Multiple domains from file with enrichment
  python recon_starter.py --domains-file targets.txt --enable-get --out ./recon_multi

  # Rate limiting examples:
  python recon_starter.py --domain example.com --rate 0.1 --out ./results    # 1 req every 10s (ultra-safe)
  python recon_starter.py --domain example.com --rate 0.2 --out ./results    # 1 req every 5s (default)
  python recon_starter.py --domain example.com --rate 1.0 --out ./results    # 1 req per second
  python recon_starter.py --domain example.com --rate 2.0 --out ./results    # 2 req per second (with permission)

  # Enrichment and scoring
  python recon_starter.py --domain example.com --enable-get --manual-threshold 8 --out ./results
  python recon_starter.py --domain example.com --disable-scoring --out ./results
  python recon_starter.py --domain example.com --enrichment-only --out ./results

  # Results management
  python recon_starter.py --serve-only --out ./results --ui-port 8080
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Target specification
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('--domain', help='Single target domain')
    target_group.add_argument('--domains-file', help='File containing target domains (one per line)')

    # Output
    parser.add_argument('--out', required=True, help='Base output directory for results')

    # Rate limiting and safety
    parser.add_argument('--rate', type=float, default=0.2,
                       help='Request rate limit in requests per second (default: 0.2 = 1 request every 5 seconds, 0 = no limit)')
    parser.add_argument('--concurrency', type=int, default=3,
                       help='Maximum concurrent operations (default: 3)')
    parser.add_argument('--timeout', type=int, default=6,
                       help='Timeout for network operations in seconds (default: 6)')
    parser.add_argument('--user-agent', default=USER_AGENT_DEFAULT,
                       help=f'Custom User-Agent string (default: {USER_AGENT_DEFAULT})')

    # Scope control
    parser.add_argument('--in-scope', action='append', default=[],
                       help='In-scope domain patterns (can be repeated, supports wildcards)')
    parser.add_argument('--out-of-scope', action='append', default=[],
                       help='Out-of-scope domain patterns (can be repeated, supports wildcards)')
    parser.add_argument('--allow-redirect-out-of-scope', action='store_true',
                       help='Allow HTTP redirects to out-of-scope domains (default: false)')

    # HTTP probing options
    parser.add_argument('--include-ports', default='80,443',
                       help='Comma-separated list of ports to probe (default: 80,443)')
    parser.add_argument('--enable-get', action='store_true',
                       help='Enable GET requests (default: HEAD only)')

    # Subdomain discovery
    parser.add_argument('--enable-wordlist-subdomains', action='store_true',
                       help='Enable wordlist-based subdomain generation')
    parser.add_argument('--wordlist', help='Wordlist file for subdomain generation (required with --enable-wordlist-subdomains)')
    parser.add_argument('--no-ct', action='store_true',
                       help='Disable Certificate Transparency log collection')
    parser.add_argument('--skip-dns', action='store_true',
                       help='Skip DNS resolution step (may result in httpx probing unresolvable domains)')

    # Scoring and enrichment options
    parser.add_argument('--enable-scoring', action='store_true', default=True,
                       help='Enable security scoring (default: true)')
    parser.add_argument('--disable-scoring', action='store_false', dest='enable_scoring',
                       help='Disable security scoring')
    parser.add_argument('--manual-threshold', type=int, default=8,
                       help='Minimum score for manual review candidacy (default: 8)')
    parser.add_argument('--max-js-per-host', type=int, default=10,
                       help='Maximum JavaScript files to analyze per host (default: 10)')
    parser.add_argument('--max-bytes', type=int, default=1048576,
                       help='Maximum bytes to download per response (default: 1MB)')
    parser.add_argument('--enrichment-only', action='store_true',
                       help='Run discovery+probe+enrichment+scoring but skip UI serve')

    # Archived URL discovery
    parser.add_argument('--enable-archived-urls', action='store_true',
                       help='Enable archived URL discovery with gau/waybackurls (default: false)')
    parser.add_argument('--max-archived-urls', type=int, default=200,
                       help='Maximum archived URLs to fetch per domain (default: 200)')

    # Caching and reruns
    parser.add_argument('--reuse-cache', action='store_true', default=True,
                       help='Reuse cached results from previous runs (default: true)')
    parser.add_argument('--no-reuse-cache', action='store_false', dest='reuse_cache',
                       help='Disable cache reuse, fetch fresh data')
    parser.add_argument('--dry-run', action='store_true',
                       help='Perform dry run without network requests')

    # UI and tool options
    parser.add_argument('--serve', action='store_true',
                       help='Start web UI after running reconnaissance')
    parser.add_argument('--serve-only', action='store_true',
                       help='Only serve web UI for existing results (no recon)')
    parser.add_argument('--run', help='Specific run directory to serve (for --serve-only, default: latest)')
    parser.add_argument('--ui-port', type=int, default=8765,
                       help='Port for web UI (default: 8765)')

    # Dependency management
    parser.add_argument('--check-deps', action='store_true',
                       help='Check dependency status and exit')
    parser.add_argument('--install-hints', action='store_true',
                       help='Show installation hints for missing dependencies')

    # Verbosity
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Handle dependency checks
    if args.check_deps or args.install_hints:
        print_dependency_status()
        return

    # Validate required dependencies
    if not HAS_DNSPYTHON:
        log_error("dnspython package is required. Install with: pip install dnspython")
        sys.exit(1)

    # Validate rate parameter
    if args.rate < 0:
        log_error("Rate must be >= 0 (0 = no rate limiting)")
        sys.exit(1)

    # Setup base output directory
    base_output_dir = Path(args.out).resolve()
    base_output_dir.mkdir(parents=True, exist_ok=True)

    # Handle serve-only mode
    if args.serve_only:
        if args.run:
            # Serve specific run
            run_dir = base_output_dir / args.run
            if not run_dir.exists():
                log_error(f"Run directory not found: {run_dir}")
                sys.exit(1)
        else:
            # Serve latest run
            run_dir = get_latest_run_directory(base_output_dir)
            if not run_dir:
                log_error(f"No run directories found in {base_output_dir}")
                sys.exit(1)

        serve_ui(run_dir, args.ui_port, logging.getLogger())
        return

    # Create new run directory
    run_dir = create_run_directory(base_output_dir)

    # Setup logging
    logger = setup_logging(run_dir, args.verbose)

    # Validate target specification
    if not args.domain and not args.domains_file:
        log_error("Must specify either --domain or --domains-file", logger)
        sys.exit(1)

    # Validate wordlist subdomain options
    if args.enable_wordlist_subdomains and not args.wordlist:
        log_error("--wordlist is required when --enable-wordlist-subdomains is used", logger)
        sys.exit(1)

    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.include_ports.split(',')]
        if not all(1 <= p <= 65535 for p in ports):
            raise ValueError("Ports must be between 1 and 65535")
    except ValueError as e:
        log_error(f"Invalid port specification: {e}", logger)
        sys.exit(1)

    # Load targets first
    targets = load_targets(args.domain, args.domains_file, logger)

    # Setup run metadata
    run_metadata = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': VERSION,
        'platform': f"{platform.system()} {platform.release()}",
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'run_dir': str(run_dir.relative_to(base_output_dir)),
        'targets': targets,
        'rate': args.rate,
        'concurrency': args.concurrency,
        'timeout': args.timeout,
        'enable_get': args.enable_get,
        'ports': ports,
        'reuse_cache': args.reuse_cache,
        'dry_run': args.dry_run,
        'no_ct': args.no_ct,
        'skip_dns': args.skip_dns,
        'enable_scoring': args.enable_scoring,
        'manual_threshold': args.manual_threshold,
        'max_js_per_host': args.max_js_per_host,
        'max_bytes': args.max_bytes,
        'enable_archived_urls': args.enable_archived_urls,
        'tools': check_tool_availability()
    }

    # Add tool versions
    run_metadata['tool_versions'] = {}
    for tool in ['subfinder', 'httpx', 'dnsx', 'tlsx', 'gau', 'waybackurls']:
        version = get_tool_version(tool)
        if version:
            run_metadata['tool_versions'][tool] = version

    log_info(f"Starting ReconStarter v{VERSION}", logger)
    log_info(f"Run directory: {run_dir}", logger)

    if args.dry_run:
        log_info("DRY RUN MODE - No network requests will be made", logger)

    # Validate archived URL options
    if args.enable_archived_urls:
        tools_available = check_tool_availability()
        if not tools_available['gau'] and not tools_available['waybackurls']:
            log_warning("--enable-archived-urls specified but neither gau nor waybackurls available", logger)

    # Setup scope patterns
    in_scope_patterns = args.in_scope.copy()
    if not in_scope_patterns:
        # Default: all target domains and their subdomains are in scope
        for target in targets:
            in_scope_patterns.extend([target, f"*.{target}"])

    out_of_scope_patterns = args.out_of_scope

    log_info(f"In-scope patterns: {in_scope_patterns}", logger)
    if out_of_scope_patterns:
        log_info(f"Out-of-scope patterns: {out_of_scope_patterns}", logger)

    # Initialize rate limiter and tracking structures
    rate_limiter = RateLimiter(args.rate)
    host_sources = defaultdict(set)  # Track source for each host
    host_notes = defaultdict(list)   # Track notes for each host

    # Collect all hosts
    all_hosts = set()

    # Add target domains themselves
    for target in targets:
        all_hosts.add(target)
        host_sources[target].add("target")

    # Run subfinder for each target
    for target in targets:
        subdomains = run_subfinder(target, run_dir / "raw", rate_limiter, logger,
                                 host_sources, args.reuse_cache, args.dry_run)
        all_hosts.update(subdomains)

    # Collect from Certificate Transparency logs
    if not args.no_ct:
        for target in targets:
            ct_domains = collect_ct_logs(target, run_dir / "raw", rate_limiter, logger,
                                       host_sources, args.user_agent, args.timeout,
                                       args.reuse_cache, args.dry_run)
            all_hosts.update(ct_domains)

    # Wordlist subdomain generation
    if args.enable_wordlist_subdomains and args.wordlist:
        for target in targets:
            wordlist_domains = generate_wordlist_subdomains(target, args.wordlist, logger, host_sources)
            all_hosts.update(wordlist_domains)

    # Archived URL discovery (optional)
    if args.enable_archived_urls:
        log_warning("Archived URL discovery enabled - limited to small number of URLs for safety", logger)
        for target in targets:
            archived_hosts = fetch_archived_urls(target, run_dir / "raw", rate_limiter,
                                               logger, host_sources, args.max_archived_urls,
                                               args.reuse_cache, args.dry_run)
            all_hosts.update(archived_hosts)

    # Filter to in-scope hosts only for active probing
    in_scope_hosts = {host for host in all_hosts if is_in_scope(host, in_scope_patterns, out_of_scope_patterns)}

    log_info(f"Total unique hosts discovered: {len(all_hosts)}", logger)
    log_info(f"In-scope hosts for probing: {len(in_scope_hosts)}", logger)

    # DNS resolution to filter out hosts without valid IPs
    if args.skip_dns:
        log_info("DNS resolution skipped (--skip-dns flag)", logger)
        dns_results = {}
        hosts_with_ips = in_scope_hosts
    else:
        dns_results = run_dnsx_resolve(
            in_scope_hosts, run_dir / "raw", rate_limiter, logger,
            host_sources, host_notes, args.timeout, args.reuse_cache, args.dry_run
        )

        # Filter to only hosts with valid IP addresses for HTTP probing
        hosts_with_ips = set(dns_results.keys())

        log_info(f"DNS resolution: {len(hosts_with_ips)}/{len(in_scope_hosts)} hosts resolved to IPs", logger)

        if len(hosts_with_ips) == 0 and len(in_scope_hosts) > 0:
            log_warning("No hosts resolved to IP addresses - no HTTP probing will be performed", logger)

    # HTTP probing
    http_results = run_httpx_probe(
        hosts_with_ips, run_dir / "raw", in_scope_patterns, out_of_scope_patterns,
        ports, args.enable_get, args.rate, args.concurrency, args.timeout,
        args.allow_redirect_out_of_scope, args.user_agent, logger,
        host_sources, host_notes, args.reuse_cache, args.dry_run
    )

    if not args.dry_run:
        # Enrichment phase for live hosts
        enrichment_results = {}
        if args.enable_scoring:
            # Filter to live hosts for enrichment
            live_hosts = []
            for result in http_results:
                host = result['host']
                # Find consolidated host data
                for host_name in all_hosts:
                    if host_name == host:
                        host_data = {
                            'host': host,
                            'http': [r['http_result'] for r in http_results if r['host'] == host]
                        }
                        if host_data['http']:  # Only if has HTTP results
                            live_hosts.append(host_data)
                        break

            if live_hosts:
                log_info(f"Running enrichment checks on {len(live_hosts)} live hosts", logger)
                enrichment_results = run_enrichment_checks(
                    live_hosts, run_dir / "raw", rate_limiter, logger,
                    args.user_agent, args.timeout, args.enable_get,
                    args.max_js_per_host, args.max_bytes, args.dry_run
                )

        # Consolidate results with scoring
        consolidated_results = consolidate_results(
            targets, all_hosts, http_results, in_scope_patterns, out_of_scope_patterns,
            host_sources, host_notes, rate_limiter, logger, dns_results,
            enrichment_results, args.enable_scoring, args.manual_threshold
        )

        # Write main results
        write_results(consolidated_results, run_dir, run_metadata, logger)

        # Create manual review outputs if scoring is enabled
        if args.enable_scoring:
            create_manual_review_outputs(consolidated_results, run_dir, logger, args.manual_threshold)

        log_info("Reconnaissance completed successfully", logger)
        log_info(f"Results available in: {run_dir}", logger)

        # Statistics
        live_count = len([r for r in consolidated_results if r.get('http')])
        manual_review_count = len([r for r in consolidated_results if r.get('manual_review_candidate')])
        if args.enable_scoring:
            log_info(f"Live services: {live_count}, Manual review candidates: {manual_review_count}", logger)

        # Start web UI if requested (but not in enrichment-only mode)
        if args.serve and not args.enrichment_only:
            serve_ui(run_dir, args.ui_port, logger)
    else:
        log_info("Dry run completed - no results written", logger)


if __name__ == "__main__":
    main()