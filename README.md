# ReconStarter - Authorized Bug Bounty Reconnaissance Tool

ReconStarter is a comprehensive, safety-focused reconnaissance tool designed specifically for authorized bug bounty testing and responsible security research. It combines subdomain discovery, DNS resolution, HTTP probing, security analysis, and automated scoring to identify high-value targets for manual review.

## SAFETY NOTICE

**This tool is designed for authorized testing only.** It implements conservative defaults with strict rate limiting and scope enforcement. Never use this tool against targets without explicit written authorization.

## Key Features

### Core Reconnaissance
- **Multi-source subdomain discovery**: subfinder, Certificate Transparency logs, wordlists, archived URLs (gau/waybackurls)
- **DNS resolution**: Efficient DNS filtering using dnsx (only probe domains with valid A/AAAA records)
- **HTTP probing**: Smart HTTP service discovery using httpx with manual fallback
- **Scope enforcement**: Strict in-scope/out-of-scope filtering with redirect protection

### Advanced Security Analysis
- **Automated scoring**: 15-point security scoring system across 5 categories
- **Smart enrichment**: Safe endpoint enumeration, header analysis, JavaScript discovery
- **Manual review targeting**: Automated identification of high-value targets requiring manual analysis
- **Comprehensive output**: JSON Lines, CSV, Markdown reports with detailed analysis

### Safety & Reliability
- **Conservative defaults**: 0.2 RPS, concurrency 3, 6s timeout, HEAD-only requests
- **Scope protection**: Never follow out-of-scope redirects, strict pattern matching
- **Comprehensive caching**: Intelligent caching system with cache reuse across runs
- **Dry-run support**: Zero network activity mode for testing and validation

## Installation

### Prerequisites

**Required:**
- Python 3.11+
- `dnspython`: `pip install dnspython`

**Recommended:**
- `rich`: `pip install rich` (enhanced output)
- `requests`: `pip install requests` (CT log collection, enrichment)

**External Tools:**
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
# Clone and install
git clone <repository-url>
cd recon_starter
pip install -r requirements.txt

# Check dependencies
python recon_starter.py --check-deps
```

## Usage Examples

### Basic Reconnaissance
```bash
# Single domain with default settings
python recon_starter.py --domain example.com --out ./results

# Multiple domains from file
python recon_starter.py --domains-file targets.txt --out ./results

# Enable GET requests and custom scoring threshold
python recon_starter.py --domain example.com --enable-get --manual-threshold 8 --out ./results
```

### Advanced Configuration
```bash
# Conservative scan with custom rate limiting
python recon_starter.py --domain example.com --rate 0.1 --timeout 10 --concurrency 1 --out ./results

# Full enrichment with JavaScript analysis
python recon_starter.py --domain example.com --enable-get --max-js-per-host 15 --out ./results

# Skip DNS resolution (faster but less efficient)
python recon_starter.py --domain example.com --skip-dns --out ./results
```

### Rate Limiting Examples
```bash
# Ultra-conservative (production systems)
python recon_starter.py --domain example.com --rate 0.1 --out ./results   # 1 request every 10 seconds

# Default safe rate
python recon_starter.py --domain example.com --rate 0.2 --out ./results   # 1 request every 5 seconds

# Moderate rate (with authorization)
python recon_starter.py --domain example.com --rate 1.0 --out ./results   # 1 request per second

# Aggressive rate (only with explicit permission)
python recon_starter.py --domain example.com --rate 2.0 --concurrency 5 --out ./results   # 2 requests/second, 5 concurrent

# No rate limiting (extreme caution required)
python recon_starter.py --domain example.com --rate 0 --out ./results     # No delays between requests
```

### Scope Control
```bash
# Custom scope patterns
python recon_starter.py --domain example.com --in-scope "*.example.com" --out-of-scope "cdn.example.com" --out ./results

# Allow out-of-scope redirects (use cautiously)
python recon_starter.py --domain example.com --allow-redirect-out-of-scope --out ./results
```

### Archived URL Discovery
```bash
# Enable archived URL discovery (requires gau/waybackurls)
python recon_starter.py --domain example.com --enable-archived-urls --max-archived-urls 300 --out ./results
```

### Results Management
```bash
# Serve existing results
python recon_starter.py --serve-only --out ./results --ui-port 8080

# Enrichment only (no UI)
python recon_starter.py --domain example.com --enrichment-only --out ./results

# Disable scoring and enrichment
python recon_starter.py --domain example.com --disable-scoring --out ./results
```

## Security Scoring System

ReconStarter implements a comprehensive 15-point scoring system to automatically identify high-value targets:

### Scoring Categories (0-15 total)

1. **Accessibility (0-3 points)**
   - +1: DNS resolves
   - +1: HTTP service responds
   - +1: HTTPS available with valid TLS

2. **Status Code Signals (0-3 points)**
   - +2: Authentication required (401/403)
   - +2: Server errors (5xx)
   - +1: Redirects to authentication endpoints

3. **Authentication & Trust Boundaries (0-4 points)**
   - +1: Login pages detected
   - +2: OAuth/SSO endpoints found
   - +2: API token/key authentication hints
   - +1: Multi-role/permission system indicators

4. **API & Data Interfaces (0-3 points)**
   - +2: Multiple API endpoints respond (/api, /v1, /v2, /graphql)
   - +1: JSON API responses
   - +1: CORS headers present

5. **Application Complexity/Age (0-2 points)**
   - +1: Custom application (not static/CDN error)
   - +1: Legacy technology stack detected

### Manual Review Threshold
- **Default threshold**: 10 points
- **Customizable**: Use `--manual-threshold N` to adjust
- **High-priority targets**: Score ≥ threshold automatically flagged for manual review

## Output Structure

ReconStarter generates comprehensive outputs in multiple formats:

### Primary Output Files
```
results/
├── hosts.jsonl              # Complete host data (JSON Lines)
├── metadata.json            # Run configuration and statistics
├── summary.md               # Human-readable summary report
├── manual_review_targets.json # High-scoring hosts (JSON)
├── manual_review_targets.md   # Manual review targets (Markdown)
└── host_scores.csv           # Scoring data (CSV)
```

### Host Data Structure
Each host entry includes:
```json
{
  "host": "api.example.com",
  "score": 12,
  "signals": ["dns_resolves", "https_available", "auth_required_401", "api_endpoint_detected"],
  "manual_review_candidate": true,
  "in_scope": true,
  "source": ["subfinder", "dnsx"],
  "dns": {
    "a_records": ["1.2.3.4"],
    "aaaa_records": [],
    "timestamp": "2024-01-01T12:00:00Z"
  },
  "http": [{
    "scheme": "https",
    "port": 443,
    "status": 401,
    "title": "API Login Required",
    "headers": {"server": "nginx/1.20.1"}
  }],
  "enrichment": {
    "security_headers": {...},
    "endpoint_checks": {...},
    "js_endpoints": [...]
  },
  "notes": [...]
}
```

## Enrichment Features

### Safe Endpoint Enumeration
ReconStarter checks a fixed list of common endpoints (no brute forcing):
- `/robots.txt`
- `/.well-known/security.txt`
- `/.well-known/openid-configuration`
- `/api`, `/v1`, `/v2`, `/graphql`

### Security Analysis
- **Header analysis**: CSP, HSTS, X-Frame-Options, etc.
- **Cookie security**: Secure, HttpOnly, SameSite flags
- **CORS configuration**: Access-Control headers
- **TLS information**: Certificate details for HTTPS services

### JavaScript Discovery
When `--enable-get` is used:
- Parse main page for JavaScript file references
- Extract API endpoints from JavaScript code
- Strict limits: max 10 JS files, 1MB download limit per response

## Web UI

ReconStarter includes a localhost-only web interface for interactive result analysis:

### Features
- **Real-time filtering**: Search hosts, filter by status/source
- **Scoring visualization**: Color-coded scores with signal details
- **Live service overview**: HTTP status codes, titles, technologies
- **Manual review focus**: Highlight high-priority targets

### Access
- **Auto-launch**: Use `--serve` flag
- **Serve existing**: `--serve-only` for previous runs
- **Custom port**: `--ui-port 8080`
- **Localhost only**: Secure by design

## Configuration Options

### Rate Limiting & Safety

**Rate Limiting Details:**
```bash
--rate 0.2                    # Requests per second (default: 0.2 = 1 request every 5 seconds)
--rate 1.0                    # 1 request per second
--rate 2.5                    # 2.5 requests per second (1 request every 400ms)
--rate 0                      # No rate limiting (use with extreme caution)
```

**Rate Limiting Examples:**
- `--rate 0.1` = 1 request every 10 seconds (ultra-conservative)
- `--rate 0.2` = 1 request every 5 seconds (default, very safe)
- `--rate 0.5` = 1 request every 2 seconds (conservative)
- `--rate 1.0` = 1 request per second (moderate)
- `--rate 2.0` = 2 requests per second (aggressive, use only if authorized)

**How Rate Limiting Works:**
- **Global enforcement**: Applied to ALL network operations (DNS, HTTP, CT logs, enrichment)
- **Thread-safe**: Safe for concurrent operations across multiple hosts
- **Minimum interval**: Calculated as `1.0 / rate` seconds between requests
- **Automatic delays**: Script automatically waits between requests to respect limits

**Additional Safety Controls:**
```bash
--concurrency 3               # Max concurrent operations (default: 3)
--timeout 6                   # Network timeout in seconds (default: 6)
--enable-get                  # Enable GET requests (default: HEAD only)
```

**Choosing the Right Rate Limit:**

| Rate | Interval | Use Case |
|------|----------|----------|
| `0.1` | 10 seconds | Production systems, shared hosting, strict SLAs |
| `0.2` | 5 seconds | **Default** - safe for most authorized testing |
| `0.5` | 2 seconds | Well-established targets, robust infrastructure |
| `1.0` | 1 second | Internal testing, dedicated test environments |
| `2.0` | 500ms | Bug bounty programs with explicit permission |
| `5.0` | 200ms | Internal red team exercises (with approval) |

**Important Notes:**
- Always start with the **default (0.2)** and increase only if needed
- Higher rates require **explicit authorization** from target owners
- Monitor target systems for any signs of impact
- Some tools (dnsx, httpx) have their own internal rate limiting that may apply

### Discovery Options
```bash
--no-ct                       # Disable Certificate Transparency logs
--skip-dns                    # Skip DNS resolution step
--enable-wordlist-subdomains  # Enable wordlist-based discovery
--wordlist SecLists/common.txt # Wordlist file path
--enable-archived-urls        # Enable gau/waybackurls discovery
```

### Scoring & Analysis
```bash
--enable-scoring              # Enable scoring (default: true)
--disable-scoring             # Disable scoring and enrichment
--manual-threshold 10         # Manual review score threshold
--max-js-per-host 10         # Max JavaScript files to analyze
--max-bytes 1048576          # Max bytes per response (1MB)
```

### Scope Control
```bash
--in-scope "*.example.com"           # In-scope patterns (wildcards supported)
--out-of-scope "cdn.example.com"     # Out-of-scope exclusions
--allow-redirect-out-of-scope        # Allow redirects outside scope
```

## Best Practices

### Responsible Usage
1. **Always obtain written authorization** before scanning any targets
2. **Use conservative settings** in production environments
3. **Monitor rate limits** and respect target infrastructure
4. **Review scope carefully** to avoid unintended scanning

### Effective Reconnaissance
1. **Start with default settings** for initial reconnaissance
2. **Enable GET requests** for comprehensive analysis when authorized
3. **Use manual review outputs** to focus security testing efforts
4. **Cache results** for iterative testing and analysis

### Performance Optimization
1. **Use DNS resolution** (default) to improve HTTP probing efficiency
2. **Adjust rate limits** based on target infrastructure and authorization
3. **Enable caching** for repeated scans of the same targets
4. **Use dry-run mode** for testing configurations

## Safety Features

### Scope Enforcement
- **Pattern matching**: Wildcard support for flexible scope definition
- **Redirect protection**: Blocks out-of-scope redirects by default
- **Source tracking**: Complete audit trail of how each host was discovered

### Rate Limiting
- **Global rate limiting**: Applied across all network operations
- **Tool-specific limits**: Respects individual tool rate limiting capabilities
- **Conservative defaults**: Safe for most target environments

### Dry Run Mode
- **Zero network activity**: Complete simulation without network requests
- **Configuration testing**: Validate settings before actual scanning
- **Scope verification**: Preview target lists and scope patterns

## Troubleshooting

### Common Issues

**"dnspython package is required"**
```bash
pip install dnspython
```

**"httpx not found in PATH"**
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**"No hosts resolved to IP addresses"**
- Check DNS connectivity and domain validity
- Verify in-scope patterns include target domains
- Consider using `--skip-dns` for testing

**"CT service temporarily unavailable"**
- Certificate Transparency API may be rate limited
- Use `--no-ct` to skip CT log collection
- Results will be cached for subsequent runs

### Performance Issues

**Slow scanning**
- Increase `--rate` (e.g., `--rate 1.0`) if authorized
- Increase `--concurrency` for more parallel operations
- Use `--skip-dns` to bypass DNS resolution

**Memory usage**
- Reduce `--max-bytes` limit for content sampling
- Disable enrichment with `--disable-scoring`
- Process smaller target lists

## Security Considerations

### Authorization
- Only use against targets you are explicitly authorized to test
- Respect scope limitations defined in bug bounty programs
- Document authorization and scope in your testing records

### Data Handling
- Results contain potentially sensitive information
- Secure storage of reconnaissance data
- Follow data retention policies for your testing program

### Network Impact
- Conservative defaults minimize target impact
- Monitor for any service disruption during testing
- Adjust rate limits based on target infrastructure capacity

## Version History

- **v1.3.0**: Added comprehensive security scoring, enrichment pipeline, manual review targeting
- **v1.2.0**: Added dnsx DNS resolution integration, improved filtering efficiency
- **v1.1.0**: Enhanced error handling, caching improvements, logging fixes
- **v1.0.0**: Initial release with core reconnaissance features

## Contributing

This tool is designed for authorized security testing only. Contributions should maintain the safety-first approach and conservative defaults that protect both testers and target infrastructure.

## License

See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing only. Users are responsible for ensuring proper authorization and compliance with applicable laws and regulations. The developers are not responsible for misuse of this tool.