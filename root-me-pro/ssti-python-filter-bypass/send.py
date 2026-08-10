import sys,re,os; os.chdir(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0,'.')
from rmeet import *
login()
def send(msg):
    r=s.post(BASE+"/messages/bobtester",data={"message":msg},timeout=30)
    b=re.sub(r'\s+',' ',s.get(BASE+"/messages/bobtester",timeout=30).text)
    i=b.find('id="messagesContainer"'); j=b.find('<div class="message-input-container">')
    msgs=re.findall(r'message-content">(.*?)</div>', b[i:j], re.S)
    return msgs[-1] if msgs else None
