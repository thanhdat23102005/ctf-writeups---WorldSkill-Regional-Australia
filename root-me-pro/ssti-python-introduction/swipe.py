import requests, re
U="https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro"
s=requests.Session()
def tok(p):
    r=s.get(U+p); m=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text); return m.group(1) if m else None
s.post(U+"/login",data={"csrf_token":tok("/login"),"username":"pauk01","password":"Passw0rd!23","submit":"Sign In"})
r=s.get(U+"/swipe"); open("swipe.html","w").write(r.text)
body=r.text
print(re.sub(r'\n\s*\n','\n', body[body.find('<div class="container'):][:3500]))
