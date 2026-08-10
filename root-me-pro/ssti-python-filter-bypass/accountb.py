import re, requests, urllib3
urllib3.disable_warnings()
from rmeet import BASE
B_USER, B_PASS = "bobtester", "Passw0rd!123"

def sessionB():
    s = requests.Session(); s.verify=False
    r = s.get(BASE+"/login", timeout=20)
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text).group(1)
    r = s.post(BASE+"/login", data={"csrf_token":t,"username":B_USER,"password":B_PASS,"submit":"Login"}, timeout=20)
    return s

def registerB():
    s = requests.Session(); s.verify=False
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', s.get(BASE+"/register",timeout=20).text).group(1)
    s.post(BASE+"/register", data={"csrf_token":t,"username":B_USER,"email":"bob@x.com",
        "password":B_PASS,"confirm_password":B_PASS,"submit":"Sign Up"}, timeout=20)
    return s

def setB(s, **kw):
    path = "/profile/"+B_USER
    r = s.get(BASE+path, timeout=20)
    if "csrf_token" not in r.text:
        path = "/start"; r = s.get(BASE+path, timeout=20)
    t = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text).group(1)
    d = {"csrf_token":t,"full_name":"Bob","age":"30","gender":"Male","location":"Paris",
         "bio":"just a normal bio here","interests":"music"}
    d.update(kw)
    return s.post(BASE+path, data=d, timeout=20)
