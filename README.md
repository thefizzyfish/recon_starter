# ReconStarter - Authorized Bug Bounty Reconnaissance Tool

ReconStarter is a safety-focused reconnaissance tool for authorized bug bounty testing. It combines subdomain discovery, DNS resolution, HTTP probing, and automated scoring to identify high-value targets for manual review.

## Safety Notice

**This tool is for authorized testing only.** Conservative defaults with strict rate limiting and scope enforcement. Never use against targets without explicit written authorization.

## Key Features

- **Multi-source subdomain discovery**: subfinder, Certificate Transparency, wordlists, archived URLs
- **DNS resolution**: Efficient filtering using dnsx (only probe domains with valid records)
- **HTTP probing**: Smart service discovery using httpx with manual fallback
- **Automated scoring**: 15-point security scoring system for target prioritization
- **Smart enrichment**: Safe endpoint enumeration, JavaScript discovery, CORS analysis
- **Conservative defaults**: 0.2 RPS, concurrency 3, 6s timeout, HEAD-only requests
- **Comprehensive output**: JSON Lines, CSV, Markdown reports with web UI

## Installation

### External Tools
```bash
# Core tools (recommended)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Optional archived URL discovery
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

### Quick Setup
```bash
git clone <repository-url>
cd recon_starter
pip install dnspython requests
python3 recon_starter.py --check-deps
```

## Usage Examples

### Basic Usage
```bash
# Single domain with default settings
python3 recon_starter.py --domain example.com --out ./results

# Multiple domains from file
python3 recon_starter.py --domains-file targets.txt --out ./results

# Enable GET requests and serve web UI
python3 recon_starter.py --domain example.com --enable-get --serve --out ./results
```

### Rate Limiting (Critical for Safety)
```bash
# Ultra-conservative (1 request every 10 seconds)
python3 recon_starter.py --domain example.com --rate 0.1 --out ./results

# Default safe rate (1 request every 5 seconds)
python3 recon_starter.py --domain example.com --rate 0.2 --out ./results

# Moderate rate (with authorization - 1 request per second)
python3 recon_starter.py --domain example.com --rate 1.0 --out ./results

# Aggressive rate (explicit permission required - 2 requests per second)
python3 recon_starter.py --domain example.com --rate 2.0 --concurrency 5 --out ./results
```

### Advanced Options
```bash
# Custom scope patterns
python3 recon_starter.py --domain example.com --in-scope "*.example.com" --out-of-scope "cdn.example.com" --out ./results

# Enable archived URL discovery
python3 recon_starter.py --domain example.com --enable-archived-urls --max-archived-urls 300 --out ./results

# Serve existing results only
python3 recon_starter.py --serve-only --out ./results --ui-port 8080

# Disable scoring and enrichment
python3 recon_starter.py --domain example.com --disable-scoring --out ./results
```

## Security Scoring System

15-point scoring system to identify high-value targets:

### Scoring Categories
1. **Accessibility (0-3)**: DNS resolution, HTTP responses, HTTPS availability
2. **Status Code Signals (0-3)**: Authentication required (401/403), server errors (5xx)
3. **Authentication & Trust (0-4)**: Login pages, OAuth/SSO, API authentication, permissions
4. **API & Data Interfaces (0-3)**: API endpoints (/api, /graphql), JSON responses, CORS
5. **Application Complexity (0-2)**: Custom applications, legacy technology stacks

### Manual Review Threshold
- **Default**: 8 points (use `--manual-threshold N` to customize)
- **High-priority targets**: Automatically flagged for manual review

## Enrichment Features

### Safe Endpoint Enumeration
Fixed list of common endpoints (no brute forcing):
- `/robots.txt`, `/.well-known/security.txt`, `/.well-known/openid-configuration`
- `/api`, `/api/v1`, `/api/v2`, `/graphql`, `/.git`, `/admin`

### Analysis Capabilities
- **Cookie security**: Secure, HttpOnly, SameSite flags
- **CORS configuration**: Access-Control headers
- **JavaScript discovery**: Extract API endpoints from JS files (with `--enable-get`)
- **TLS information**: Certificate details for HTTPS services

### Output Structure
```
results/
├── hosts.jsonl                    # Complete host data (JSON Lines)
├── metadata.json                  # Run configuration and statistics
├── summary.md                     # Human-readable summary report
├── manual_review_targets.json     # High-scoring hosts for manual review
├── manual_review_targets.md       # Manual review targets (Markdown)
└── host_scores.csv               # Scoring data (CSV)
```

## Safety Features

### Rate Limiting
- **Global enforcement**: Applied to all network operations
- **Conservative defaults**: Safe for most target environments
- **Tool-specific limits**: Respects individual tool capabilities

### Scope Control
- **Pattern matching**: Wildcard support for flexible scope definition
- **Redirect protection**: Blocks out-of-scope redirects by default
- **Source tracking**: Complete audit trail of host discovery

### Additional Safety
- **Dry run mode**: `--dry-run` for zero network activity testing
- **HEAD-only requests**: Default behavior (use `--enable-get` when authorized)
- **Content limits**: 1MB download limit per response

## Important Options

```bash
--rate RATE              # Requests per second (default: 0.2)
--concurrency N          # Max concurrent operations (default: 3)
--timeout N              # Network timeout in seconds (default: 6)
--enable-get            # Enable GET requests (default: HEAD only)
--manual-threshold N     # Minimum score for manual review (default: 8)
--in-scope PATTERN      # In-scope domain patterns (wildcards supported)
--out-of-scope PATTERN  # Out-of-scope exclusions
--skip-dns              # Skip DNS resolution step
--no-ct                 # Disable Certificate Transparency logs
--reuse-cache           # Reuse cached results (default: true)
```


## License & Disclaimer

This tool is for authorized security testing only. Users are responsible for proper authorization and legal compliance. Developers are not responsible for misuse.