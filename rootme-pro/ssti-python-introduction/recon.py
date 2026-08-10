import requests, re, sys
U="https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro"
s=requests.Session()
def tok(path):
    r=s.get(U+path)
    m=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text)
    return m.group(1) if m else None
t=tok("/register")
r=s.post(U+"/register",data={"csrf_token":t,"username":"pauk01","email":"pauk01@x.com","password":"Passw0rd!23","confirm_password":"Passw0rd!23","submit":"Sign Up"},allow_redirects=True)
print("register:",r.status_code,r.url)
t=tok("/login")
r=s.post(U+"/login",data={"csrf_token":t,"username":"pauk01","password":"Passw0rd!23","submit":"Sign In"},allow_redirects=True)
print("login:",r.status_code,r.url)
print("cookies:",s.cookies.get_dict())
r=s.get(U+"/")
links=sorted(set(re.findall(r'href="(/[^"]*)"',r.text)))
print("links:",links)
open("home_auth.html","w").write(r.text)
