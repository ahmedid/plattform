# CTF Challenge Analysis - BountyScanner

## Target
- URL: `https://u8p0uags08m1.ctfhub.io`
- Application: Flask/Werkzeug 3.1.3 on Python 3.14.0
- Reverse Proxy: nginx/1.28.0 (external) + nginx/1.18.0 (internal ACL)

## Challenge Structure

1. **Frontend**: BountyScanner dashboard at `/`
2. **SSRF Endpoint**: `/api/fetch` - accepts `{"endpoint": "url"}` and fetches internal URLs
3. **Protected Endpoints**:
   - `/api/fetch` - blocked by nginx with 403 Forbidden
   - `/api/systems` - blocked by nginx with 403 Forbidden

## Attack Flow (Intended)

1. Access `/api/fetch` (currently blocked)
2. Use SSRF to reach internal `httpd` server
3. Upload nuclei template via HTTP request smuggling
4. Execute template to run `/readflag`
5. Read flag from output file

## Nginx ACL Bypass Attempts

### Techniques That Bypass Nginx (but return 404 from Flask)

| Path | Result |
|------|--------|
| `/api/fetch/` | 404 - trailing slash |
| `/api/fetch/.` | 404 - trailing dot |
| `/api/fetch/..` | 404 - traversal |
| `/api/fetch/x` | 404 - subpath |
| `/API/FETCH` | 404 - uppercase |
| `/Api/Fetch` | 404 - title case |
| `/api/fetch;` | 404 - semicolon |
| `/api/..;/fetch` | 404 - semicolon traversal |
| `/api/fetch%20` | 404 - trailing space |
| `/api/fetch%09` | 404 - trailing tab |

### Techniques Blocked by Nginx

| Path | Result |
|------|--------|
| `/api/fetch` | 403 - exact match |
| `/api/fetch?x` | 403 - with query |
| `/api/fetch#x` | 403 - with fragment |
| `/api/x/../fetch` | 403 - normalized traversal |
| `//api/fetch` | 403 - double slash |
| `/./api/fetch` | 403 - dot prefix |

## The Problem

The nginx ACL uses **exact path matching** for `/api/fetch`:
- Any modification to bypass nginx also changes the Flask route
- Flask routes are case-sensitive and don't normalize paths
- Result: Can't reach `/api/fetch` endpoint from external

## Potential Solutions

### 1. HTTP Request Smuggling
If there's a discrepancy between nginx and Flask in parsing:
- CL.TE / TE.CL attacks
- Header injection
- Connection reuse

**Result**: Tested, nginx properly rejects malformed requests.

### 2. Header-Based Bypass
Try headers like:
- `X-Original-URL: /api/fetch`
- `X-Rewrite-URL: /api/fetch`

**Result**: Flask doesn't process these headers for routing.

### 3. WebSocket Upgrade
Bypass ACL via WebSocket upgrade.

**Result**: nginx still applies ACL to WebSocket paths.

### 4. Find Alternative Endpoints
Look for other SSRF-capable endpoints.

**Status**: Not found yet.

### 5. Exploit nginx/Flask Version Vulnerabilities
Check for CVEs in:
- nginx 1.28.0 / 1.18.0
- Werkzeug 3.1.3
- Python 3.14.0

## Scripts Created

1. `bypass_nginx.py` - Tests 30+ path-based bypass techniques
2. `smuggle_exploit.py` - Tests HTTP smuggling attacks
3. `ctf_exploit.py` - Original nuclei template bypass
4. `nuclei_signer.py` - Signs templates if key is leaked

## Next Steps to Try

1. **Check for HTTP/2-specific bypasses** (h2c smuggling)
2. **Look for race conditions** in ACL checks
3. **Try CONNECT method** for tunneling
4. **DNS rebinding** if internal resolution is used
5. **Check for backup/debug endpoints** that might not have ACL
6. **Review nginx version-specific vulnerabilities**

## Running the Exploits

```bash
# Test nginx bypass techniques
python3 bypass_nginx.py

# Test HTTP smuggling
python3 smuggle_exploit.py

# If you find a bypass, use the original exploit:
python3 ctf_final_exploit.py u8p0uags08m1.ctfhub.io
```
