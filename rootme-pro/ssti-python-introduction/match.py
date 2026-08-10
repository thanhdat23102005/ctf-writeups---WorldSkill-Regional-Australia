import requests, re, json
U="https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro"
s=requests.Session()
def tok(p):
    r=s.get(U+p); m=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text); return m.group(1) if m else None
s.post(U+"/login",data={"csrf_token":tok("/login"),"username":"pauk01","password":"Passw0rd!23","submit":"Sign In"})
for _ in range(12):
    r=s.get(U+"/swipe")
    m=re.search(r'data-user-id="(\d+)"',r.text)
    if not m: print("no more profiles"); break
    uid=m.group(1)
    j=s.post(U+"/api/swipe",json={"user_id":int(uid),"direction":"right"}).json()
    print("swiped",uid,j)
r=s.get(U+"/matches")
print("matches links:",sorted(set(re.findall(r'href="(/messages/[^"]+)"',r.text))))
open("matches.html","w").write(r.text)
