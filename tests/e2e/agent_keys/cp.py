#!/usr/bin/env python3
"""Tiny dashboard client for the E2E: signs a GoTrue-style HS256 JWT and calls
the control plane. Usage: cp.py <method> <path> [json-body]"""
import base64, hashlib, hmac, json, sys, time, urllib.request, urllib.error

SECRET = b"e2e-secret-e2e-secret-e2e-secret-e2e-secret"
BASE = "http://127.0.0.1:18091"
SUB = "e2e-user-0001"

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def jwt():
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64(json.dumps({"sub": SUB, "email": "e2e@faultwall.test", "exp": int(time.time()) + 3600, "iat": int(time.time())}).encode())
    sig = b64(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"

def call(method, path, body=None, bearer=None):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + (bearer or jwt()), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

if __name__ == "__main__":
    method, path = sys.argv[1], sys.argv[2]
    body = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
    st, out = call(method, path, body)
    print(st)
    print(out)
