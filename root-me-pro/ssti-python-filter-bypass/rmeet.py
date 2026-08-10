import re, sys, requests, urllib3
urllib3.disable_warnings()

BASE = "https://instance-019fe9d3-100d-72b5-b0ee-ffec6b5fe300.challenges.root-me.pro"
USER, PASS = "pauk9x", "Passw0rd!123"

s = requests.Session()
s.verify = False

def csrf(path):
    r = s.get(BASE + path, timeout=20)
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text)
    return m.group(1) if m else None

def register():
    t = csrf("/register")
    r = s.post(BASE + "/register", data={"csrf_token": t, "username": USER, "email": USER+"@x.com",
              "password": PASS, "confirm_password": PASS, "submit": "Sign Up"}, timeout=20)
    return r

def login():
    t = csrf("/login")
    r = s.post(BASE + "/login", data={"csrf_token": t, "username": USER, "password": PASS,
              "submit": "Login"}, timeout=20)
    return r

if __name__ == "__main__":
    r = register()
    print("register", r.status_code, r.url)
    r = login()
    print("login", r.status_code, r.url)
    open("files/after_login.html","w").write(r.text)
    print(sorted(set(re.findall(r'href="(/[^"]*)"', r.text))))
