#!/usr/bin/env python3
"""
ShieldNet — pre-network fraud, spam and AML defence engine.   (zero dependencies: Python 3.9+ stdlib only)

Run:   python server.py            -> http://localhost:8000   (serves index.html + JSON API)
Eval:  python server.py --eval     -> prints the full metrics report and exits

Two shields in front of the UPI / bank network:
  1. MESSAGE SHIELD  - reads incoming messages/links BEFORE they reach the user's device. Spam is detected by
     structure (pressure + ask + impersonation + hidden payloads + URL forensics), not only by old keywords.
     PRIVACY: only confirmed spam is remembered (redacted + simhash). Normal messages are analysed in RAM and
     discarded; nothing but a counter survives.
  2. TRANSACTION SHIELD - live scoring of every payment with 3 independent signals fused by LEARNED weights:
        supervised model (+ interaction features)  |  isolation-forest anomaly  |  rolling 24h transaction graph
     -> Allow / Verify / Hold / Block, exact linear-SHAP reason codes, merged case management, analyst feedback
        retraining.  Time-based splits, thresholds tuned on validation only, honest held-out + ablation tests.
"""
import os, re, sys, json, math, time, random, sqlite3, hashlib, threading, unicodedata, base64, urllib.parse
from collections import defaultdict, deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from time import perf_counter

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SHIELDNET_DB", os.path.join(HERE, "shieldnet.db"))
SEED = 42
# cost model used to tune thresholds on VALIDATION only (INR-ish units, per transaction)
COST = dict(fn=100.0, fn_verified=30.0, hold_friction=8.0, verify_friction=1.2)

# ====================================================================================================
# PART 1 - MESSAGE SHIELD
# ====================================================================================================
BRANDS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"],
    "axis": ["axisbank.com"], "kotak": ["kotak.com"], "paytm": ["paytm.com"], "phonepe": ["phonepe.com"],
    "gpay": ["pay.google.com"], "npci": ["npci.org.in"], "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"], "irctc": ["irctc.co.in"], "uidai": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"], "fedex": ["fedex.com"], "dhl": ["dhl.com"], "netflix": ["netflix.com"],
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com"], "apple": ["apple.com"], "google": ["google.com"],
    "whatsapp": ["whatsapp.com"], "pnb": ["pnbindia.in"], "indiapost": ["indiapost.gov.in"], "rbi": ["rbi.org.in"],
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly", "s.id", "t.ly"}
BAD_TLDS = {"xyz", "top", "click", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "work", "loan", "icu", "buzz", "cyou", "rest", "monster", "support", "pw", "cn", "ru", "vip", "club", "sbs", "cfd", "bond"}
ALL_TLDS = BAD_TLDS | {"com", "in", "net", "org", "co", "io", "info", "biz", "me", "ly", "gl", "to", "cc", "site", "online", "shop", "link", "app", "live", "store", "tech", "gov", "edu", "bank", "uk", "us", "ai", "sh", "ws"}
SLD = {"co", "com", "org", "net", "gov", "ac", "edu", "nic"}
DANGEROUS_EXT = r"apk|exe|scr|bat|cmd|vbs|jar|msi|lnk|ps1|hta|docm|xlsm|pptm|dll|jse|wsf|dmg|pkg"
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})

LEX = {  # family -> (points, regex).  Each family fires ONCE; scam = combination, not any single keyword.
    "ask_secret": (30, r"\b(share|send|tell|provide|enter|confirm|verify|update|reply with|give)\b[^.\n]{0,45}\b(otp|pin|cvv|password|passcode|card (number|details)|aadhaar|pan (card|number)|upi pin|mpin|net ?banking|login details)\b|\breceive\b[^.\n]{0,40}\b(enter|input|type)\b[^.\n]{0,25}\bpin\b"),
    "ask_money": (22, r"\b(send|transfer|pay|deposit|remit)\b[^.\n]{0,30}(\brs\.?|\binr\b|₹|\busd\b|\$|\bfee\b|\bcharges?\b|\bfunds?\b|\bbitcoin\b|\busdt\b)|\b(processing|registration|release|clearance|customs|delivery|insurance) (fee|charge)s?\b|\bcollect request\b|\bapprove (the |this )?(request|payment|collect)\b|\bscan (this |the )?qr\b|\brefundable (deposit|fee)\b"),
    "urgency": (14, r"\b(urgent(ly)?|immediately|right now|asap|within \d+ ?(hours?|hrs?|minutes?|mins?)|expires? (today|soon|in|at)|last (chance|warning|notice)|act now|today only|final (notice|reminder)|before midnight|do not delay)\b"),
    "fear": (16, r"\b(blocked|suspended|deactivated|frozen|terminated|disconnected|will be closed|arrest(ed)?|warrant|legal action|fir\b|court|penalty|seized|unauthori[sz]ed (login|transaction|access)|illegal)\b"),
    "authority": (8, r"\b(rbi|npci|sbi|hdfc|icici|axis bank|bank|customs|income tax|cbi|trai|police|uidai|aadhaar|courier|fedex|dhl|amazon|paytm|phonepe|google pay|kyc|cyber ?crime|support team|customer care)\b"),
    "reward": (16, r"\b(lottery|jackpot|winner|you (have )?won|prize|congratulations|lucky draw|cashback|reward points?|gift (card|voucher)|free (gift|iphone|recharge)|claim (your|now|reward))\b"),
    "remote": (34, r"\b(anydesk|teamviewer|quick ?support|ammyy|rustdesk|screen ?shar(e|ing)|remote (access|support|control)|install (this |the |our )?(app|apk|software))\b"),
    "shift": (10, r"\b(whats ?app|telegram|signal|call|contact|message|dm)\b[^.\n]{0,25}(\+?\d[\d ]{8,}|@\w{3,}|t\.me/)|\bt\.me/\w+"),
    "advance_fee": (28, r"\b(inheritance|beneficiary|barrister|next of kin|unclaimed (funds|deposit)|million (usd|dollars)|diplomat|transfer of (the )?funds?|late client)\b"),
    "job_task": (22, r"\b(part[- ]time job|work from home|earn (up to |rs\.? ?|₹ ?)?\d[\d,]*|daily (income|payout|salary)|like (and|&) subscribe|task[- ]based|data entry job|per (day|task))\b"),
    "invest": (22, r"\b(guaranteed returns?|double your money|risk[- ]free|insider (tip|information)|crypto|usdt|bitcoin|trading group|vip signals?|100% (profit|returns?)|doubl(e|ing) (profit|capital))\b"),
    "kyc": (16, r"\bkyc\b[^.\n]{0,40}\b(expire[sd]?|update|pending|verify|incomplete|suspend)\w*|\b(update|verify|complete)\b[^.\n]{0,20}\bkyc\b"),
}
LEX_RX = {k: (w, re.compile(rx, re.I)) for k, (w, rx) in LEX.items()}
PROTECT_OTP = re.compile(r"\b(otp|code|pin)\b[^.\n]{0,60}\b(do not|don't|never|dont)\b[^.\n]{0,20}\b(share|disclose|tell)\b|\b(do not|don't|never)\b[^.\n]{0,15}\b(share|disclose)\b[^.\n]{0,25}\b(otp|code|pin)\b", re.I)
TXN_ALERT = re.compile(r"\b(debited|credited|a/c|acct|account)\b[^.\n]{0,50}\b(rs\.?|inr|₹)\s?[\d,]+|\b(rs\.?|inr|₹)\s?[\d,]+\b[^.\n]{0,40}\b(debited|credited|spent|received)\b", re.I)
URL_RX = re.compile(r"(?i)\b(?:(?:https?|hxxps?|ftp)://[^\s<>\"']+|www\.[^\s<>\"']+|\d{1,3}(?:\.\d{1,3}){3}(?:/[^\s<>\"']*)?|[a-z0-9][a-z0-9\-\.]{1,60}\.(?:%s)(?:/[^\s<>\"']*)?)" % "|".join(sorted(ALL_TLDS)))
UPI_RX = re.compile(r"(?i)upi://[a-z]+\?[^\s<>\"']+")
ZW = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"), None)
BIDI = re.compile("[‪-‮⁦-⁩]")


def host_of(u):
    u = u.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
    try: return (urllib.parse.urlparse(u if "://" in u else "http://" + u).hostname or "").lower()
    except ValueError: return re.sub(r"^[a-z]+://", "", u.lower()).split("/")[0].strip("[]")


def lev(a, b):
    if abs(len(a) - len(b)) > 2: return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable(host):
    p = host.split(".")
    if len(p) >= 3 and p[-2] in SLD and len(p[-1]) == 2: return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else host


def entropy(s):
    if not s: return 0
    c = defaultdict(int)
    for ch in s: c[ch] += 1
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def analyze_url(u):
    """Static forensics of one URL.  Returns {url, host, score 0-100, flags[], decisive}."""
    raw = u
    u = u.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".").rstrip(".,;:!?)]}'\"")
    flags, pts, decisive = [], 0, False
    def add(p, t, dec=False):
        nonlocal pts, decisive
        pts += p; flags.append(t); decisive = decisive or dec
    if re.match(r"(?i)(javascript|data|vbscript):", u):
        return dict(url=raw[:90], host="", score=95, flags=["executable URL scheme"], decisive=True)
    um = UPI_RX.match(u)
    if um:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
        return dict(url=raw[:90], host="upi://", score=55, flags=["UPI deep-link inside a message (payee %s%s) - payment/collect request, not information" % ((q.get("pa") or ["?"])[0], (", amount " + q["am"][0]) if "am" in q else "")], decisive=False)
    host = host_of(u)
    try: pu = urllib.parse.urlparse(u if "://" in u else "http://" + u)
    except ValueError: pu = urllib.parse.urlparse("http://" + host)
    if pu.username: add(30, "credentials/@ in URL hides the real host", True)
    if not host: return dict(url=raw[:90], host="", score=pts, flags=flags, decisive=decisive)
    reg = registrable(host); labels = host.split("."); tld = labels[-1]
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host): add(34, "raw IP address instead of a domain", True)
    if host in SHORTENERS or reg in SHORTENERS: add(18, "link shortener hides the destination")
    if any(l.startswith("xn--") for l in labels): add(28, "punycode (look-alike unicode) domain", True)
    if tld in BAD_TLDS: add(14, "high-abuse TLD .%s" % tld)
    if len(labels) >= 5: add(10, "deeply nested subdomains")
    if pu.scheme == "http": add(6, "no HTTPS")
    if len(u) > 90: add(6, "very long URL")
    if u.count("%") >= 4: add(8, "heavy percent-encoding (obfuscation)")
    body = host[: -len(tld) - 1] if "." in host else host
    deleet = body.translate(LEET).replace("rn", "m").replace("vv", "w")
    toks = [t for t in re.split(r"[-_.\d]+", deleet) if t]
    brand_hit = None
    for b, offs in BRANDS.items():
        if reg in offs: brand_hit = None; break
        for t in toks:
            if t == b or (len(b) >= 5 and len(t) >= 5 and lev(t, b) <= 1) or (len(b) >= 6 and b in t):
                brand_hit = b
    if brand_hit: add(42, "impersonates '%s' but is not its official domain (%s)" % (brand_hit, reg), True)
    lab = labels[-2] if len(labels) > 1 else host
    if len(lab) >= 12 and entropy(lab) > 3.4 and not brand_hit: add(10, "random-looking (DGA-style) domain")
    path = (pu.path + "?" + pu.query).lower()
    if re.search(r"\.(%s)(\?|$)" % DANGEROUS_EXT, path): add(40, "link downloads an executable/installer file", True)
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(%s)" % DANGEROUS_EXT, path): add(20, "double-extension disguise")
    if re.search(r"(login|signin|verify|kyc|secure|update|otp|claim|refund|wallet|reward|account)", path + host): add(8, "credential-harvest keywords in URL")
    if reg in MEM.bad_domains: add(45, "domain previously seen in confirmed spam", True)
    return dict(url=raw[:90], host=host, score=min(100, pts), flags=flags, decisive=decisive)


def sanitize(text):
    hidden = []
    nz = len(re.findall("[​‌‍⁠﻿­]", text))
    if nz: hidden.append(("hidden", 12 + min(nz, 6) * 2, "%d invisible characters used to slice keywords past filters" % nz, False))
    if BIDI.search(text): hidden.append(("hidden", 30, "bidirectional-override characters (text/extension spoofing)", True))
    t = BIDI.sub("", text.translate(ZW))
    # mixed-script (homoglyph) words: latin letters mixed with cyrillic/greek
    for w in re.findall(r"\w{3,}", t):
        sc = {unicodedata.name(c, "?").split()[0] for c in w if c.isalpha()}
        if len(sc & {"LATIN", "CYRILLIC", "GREEK"}) >= 2:
            hidden.append(("hidden", 28, "homoglyph word '%s' mixes alphabets to fake a brand/keyword" % w[:20], True)); break
    t = unicodedata.normalize("NFKC", t)
    if re.search(r"(?i)<\s*(script|iframe|object|embed|form)\b|\bon(error|load|click)\s*=|display\s*:\s*none|font-size\s*:\s*0", t):
        hidden.append(("hidden", 40, "active/hidden HTML content (script, iframe, hidden text)", True))
    for m in re.finditer(r"(?is)<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", t):
        sh = re.search(URL_RX, m.group(2) or "")
        if sh:
            h1 = host_of(m.group(1))
            h2 = host_of(sh.group(0))
            if registrable(h1) != registrable(h2): hidden.append(("hidden", 38, "link text shows %s but opens %s" % (h2, h1), True)); break
    for b in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", t):
        try:
            d = base64.b64decode(b + "=" * (-len(b) % 4), validate=False)
            if d[:2] == b"MZ" or re.search(rb"(?i)https?://|powershell|cmd\.exe|/bin/(ba)?sh|<script", d):
                hidden.append(("hidden", 42, "base64 blob decodes to executable code or a hidden link", True)); break
        except Exception: pass
    for m in re.finditer(r"(?i)\b[\w\-]+\.(?:%s)\b" % DANGEROUS_EXT, t):
        hidden.append(("hidden", 36, "attachment/file name '%s' is an installable or executable type" % m.group(0)[:30], True)); break
    if re.search(r"(?i)\.(pdf|docx?|xlsx?|jpg|png)\.(%s)\b" % DANGEROUS_EXT, t):
        hidden.append(("hidden", 30, "double-extension file (looks like a document, runs as a program)", True))
    return t, hidden


class SpamMemory:
    """Privacy-preserving memory. Stores ONLY confirmed spam (redacted skeleton + simhash + domains)."""
    def __init__(self):
        self.lock = threading.Lock(); self.items = []; self.bad_domains = {}
        self.counters = dict(processed=0, discarded_normal=0, stored_spam=0, known_variant_hits=0)
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS spam_memory(id INTEGER PRIMARY KEY, ts REAL, simhash TEXT, redacted TEXT, domains TEXT, typology TEXT, hits INTEGER DEFAULT 1)")
        for r in self.db.execute("SELECT id,simhash,redacted,domains,typology,hits FROM spam_memory"):
            self.items.append(dict(id=r[0], sh=int(r[1]), redacted=r[2], domains=json.loads(r[3]), typology=r[4], hits=r[5]))
            for d in json.loads(r[3]): self.bad_domains[d] = 1
    @staticmethod
    def canon(text):
        t = URL_RX.sub(lambda m: " url_" + registrable(host_of(m.group(0)) or "x").replace(".", "_") + " ", text.lower())
        return re.sub(r"\d", "#", t)
    @classmethod
    def simhash(cls, text):
        w = re.findall(r"[a-z_#]{2,}", cls.canon(text)); toks = w + [a + "_" + b for a, b in zip(w, w[1:])]
        v = [0] * 64
        for tk in toks:
            h = int.from_bytes(hashlib.md5(tk.encode()).digest()[:8], "big")
            for i in range(64): v[i] += 1 if (h >> i) & 1 else -1
        return sum(1 << i for i in range(64) if v[i] > 0)
    @staticmethod
    def redact(text):
        t = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "[email]", text)
        t = URL_RX.sub(lambda m: "[link:" + registrable(host_of(m.group(0)) or "?") + "]", t)
        t = re.sub(r"\+?\d[\d\s\-]{7,}\d", "[number]", t)
        t = re.sub(r"\d{3,}", "###", t)
        return t[:220]
    def match(self, sh):
        best = None
        for it in self.items:
            d = bin(it["sh"] ^ sh).count("1")
            if d <= 9 and (best is None or d < best[0]): best = (d, it)
        return best
    def store(self, text, typology, domains):
        sh = self.simhash(text)
        with self.lock:
            m = self.match(sh)
            if m and m[0] <= 3:
                m[1]["hits"] += 1; self.db.execute("UPDATE spam_memory SET hits=hits+1 WHERE id=?", (m[1]["id"],)); self.db.commit(); return m[1]["id"], False
            cur = self.db.execute("INSERT INTO spam_memory(ts,simhash,redacted,domains,typology) VALUES(?,?,?,?,?)", (time.time(), str(sh), self.redact(text), json.dumps(domains), typology))
            self.db.commit()
            it = dict(id=cur.lastrowid, sh=sh, redacted=self.redact(text), domains=domains, typology=typology, hits=1)
            self.items.append(it); self.counters["stored_spam"] += 1
            for d in domains: self.bad_domains[d] = 1
            return it["id"], True

MEM = SpamMemory()


def shield(text, store=True):
    t0 = perf_counter()
    MEM.counters["processed"] += 1
    clean, hidden = sanitize(text)
    sig = []  # (family, points, text, decisive)
    for fam, pts, txt, dec in hidden: sig.append((fam, pts, txt, dec))
    # --- scam structure (typology) ---
    fired = {}
    for fam, (w, rx) in LEX_RX.items():
        m = rx.search(clean)
        if m: fired[fam] = (w, m.group(0)[:50])
    protective = bool(PROTECT_OTP.search(clean))
    if protective: fired.pop("ask_secret", None)
    core = [f for f in fired if f != "authority"]
    if "authority" in fired and not core: fired.pop("authority")
    labels = dict(ask_secret="asks for a secret (OTP/PIN/password/card)", ask_money="asks you to pay / send money / approve a request", urgency="manufactured urgency", fear="threat or fear of account loss / legal action", authority="impersonates a bank/agency/courier", reward="unexpected prize / reward bait", remote="pushes remote-access / app install", shift="moves you to a private channel / unknown number", advance_fee="advance-fee / inheritance pattern", job_task="task / easy-income job lure", invest="guaranteed-return / crypto lure", kyc="KYC-expiry pretext")
    lex_pts = 0
    for fam, (w, frag) in fired.items():
        sig.append(("lexical", w, "%s  [\"%s\"]" % (labels[fam], frag.strip()), False)); lex_pts += w
    pressure = {"urgency", "fear"} & set(fired); ask = {"ask_secret", "ask_money", "remote"} & set(fired)
    if pressure and ask: sig.append(("lexical", 16, "pressure + ask combination (classic social-engineering structure)", False)); lex_pts += 16
    if "authority" in fired and ask and pressure: sig.append(("lexical", 8, "unverified authority + ask + pressure", False)); lex_pts += 8
    if len(core) >= 3 and not ask: sig.append(("lexical", 10, "stacked lure types without a legitimate purpose", False)); lex_pts += 10
    if TXN_ALERT.search(clean) and not URL_RX.search(clean) and not ask: lex_pts -= 25; sig.append(("trust", -25, "looks like a plain transaction alert (no link, no ask)", False))
    if protective and not ask and not URL_RX.search(clean): lex_pts -= 30; sig.append(("trust", -30, "OTP notice with 'do not share' warning, no link", False))
    lex_pts = max(-40, min(78, lex_pts))
    # --- URLs ---
    urls = [analyze_url(m.group(0)) for m in URL_RX.finditer(clean)][:8] + [analyze_url(m.group(0)) for m in UPI_RX.finditer(clean)][:3]
    uscore = max([u["score"] for u in urls], default=0)
    for u in urls:
        for f in u["flags"]: sig.append(("url", round(u["score"] * 0.6), "%s: %s" % (u["host"] or "link", f), u["decisive"]))
    # --- hidden ---
    hid_pts = min(60, sum(p for fam, p, *_ in sig if fam == "hidden"))
    families = {s[0] for s in sig if s[1] > 0 and s[0] != "trust"}
    total = lex_pts + 0.75 * uscore + hid_pts
    if uscore >= 40 and lex_pts >= 14: total += 10; sig.append(("synergy", 10, "suspicious link AND persuasion language together", False))
    decisive = any(s[3] for s in sig)
    # --- memory (old spam) ---
    sh = MEM.simhash(clean); mm = MEM.match(sh); memory = None
    if mm and (total >= 15 or mm[0] <= 4):
        memory = dict(distance=mm[0], seen=mm[1]["hits"], typology=mm[1]["typology"])
        total = max(total, 88 if mm[0] <= 6 else total + 25); families.add("memory"); MEM.counters["known_variant_hits"] += 1
        sig.append(("memory", 40, "near-duplicate of known spam (distance %d) - old spam recognised instantly" % mm[0], True))
    total = int(max(0, min(100, round(total))))
    # single weak signal never blocks: need 2 independent families, or one decisive finding
    if total >= 60 and (len(families) >= 2 or decisive): verdict, action = "SPAM", "BLOCK"
    elif total >= 30: verdict, action = "SUSPICIOUS", "WARN"
    else: verdict, action = "SAFE", "ALLOW"
    if verdict == "SPAM" and len(families) < 2 and not decisive: verdict, action = "SUSPICIOUS", "WARN"
    typ = "/".join(sorted(f for f in fired if f != "authority"))[:60] or ("url" if uscore else "hidden")
    stored, mem_id = False, None
    if verdict == "SPAM" and store:
        doms = sorted({registrable(u["host"]) for u in urls if u["host"] and u["score"] >= 40 and "." in u["host"]})
        mem_id, new = MEM.store(clean, typ, doms); stored = True
    elif store:
        MEM.counters["discarded_normal"] += 1  # normal / unconfirmed: analysed in RAM, then dropped. Nothing kept.
    return dict(verdict=verdict, action=action, score=total, families=sorted(families),
                signals=[dict(family=a, points=b, text=c) for a, b, c, _ in sorted(sig, key=lambda s: -abs(s[1]))][:10],
                urls=urls, memory=memory, stored_in_memory=stored, memory_id=mem_id,
                privacy=("redacted fingerprint of this SPAM kept for future matching" if stored else "message analysed in RAM and discarded - nothing stored"),
                latency_ms=round((perf_counter() - t0) * 1000, 2))


# labelled self-test sets (dev = used while writing rules, held = written afterwards, never tuned on)
MSG_DEV = [
 ("Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login and share OTP", 1),
 ("Congratulations! You have won Rs 25,00,000 in the lucky draw. Pay Rs 4999 processing fee to claim your prize", 1),
 ("URGENT: install AnyDesk and share the code so our support team can refund your payment", 1),
 ("Your courier is held at customs. Pay delivery charge Rs 49 at bit.ly/3xYz12 within 24 hours or it will be returned", 1),
 ("Part time job! Earn Rs 5000 daily by liking videos. WhatsApp +91 98765 43210 now", 1),
 ("To receive money enter your UPI PIN in the collect request and approve", 1),
 ("I am Barrister James, beneficiary of unclaimed funds 12 million USD. Send fee to release the transfer of funds", 1),
 ("Income tax refund pending. Verify at http://incometax-refund.top/claim immediately or legal action will follow", 1),
 ("Your Netflix account is suspended. Update payment at http://netfIix-billing.com/verify", 1),
 ("Download your invoice: http://files-secure.click/Invoice_2024.pdf.exe", 1),
 ("HDFC: unauthorized login detected. Call +91 99999 11111 on telegram @hdfc_support and confirm your card number", 1),
 ("Guaranteed returns 40% weekly, risk free, join our VIP signals trading group on t.me/cryptogain", 1),
 ("Your Aadhaar will be deactivated, verify at 192.168.4.7/uidai/login now", 1),
 ("Dear user, your electricity will be disconnected tonight 9:30pm. Call 9876543210 immediately to update bill", 1),
 ("Hi, I'm from Amazon customer care. Please install this app to cancel the wrong order and share the OTP", 1),
 ("Your PAN card is blocked. Click http://pan-update-india.xyz and enter net banking password", 1),
 ("Hello Mom, I lost my phone, new number. Please send Rs 18000 urgently to this UPI", 1),
 ("Your OTP for HDFC transaction is 482913. Do not share this with anyone. Never share OTP.", 0),
 ("Rs 2,450.00 debited from a/c XX1234 on 12-Oct. Avl bal Rs 10,200. If not you call bank helpline", 0),
 ("Hey are we still on for dinner at 8 tomorrow?", 0),
 ("Your Amazon order #402-1234 has shipped. Track at https://www.amazon.in/orders", 0),
 ("Meeting moved to 3pm, please bring the signed documents.", 0),
 ("Happy birthday! Wishing you a great year ahead :)", 0),
 ("Your salary of Rs 54,000 has been credited to a/c XX5521.", 0),
 ("Reminder: electricity bill due on 20th. Pay through the official app or at https://www.tatapower.com", 0),
 ("Can you send me the notes from yesterday's class? Thanks", 0),
 ("IRCTC: your ticket PNR 4521896 is confirmed for 14 Nov. Have a safe journey. https://www.irctc.co.in", 0),
 ("The cashback of Rs 50 has been added to your Paytm wallet after your recharge.", 0),
 ("Please share the project report by evening. The client call is at 6.", 0),
 ("Your Uber ride receipt: Rs 312. Thanks for riding.", 0),
 ("Bank holiday on Monday, branches will remain closed.", 0),
 ("Dad, I reached the station. Will call you in 10 minutes.", 0),
 ("We have received your KYC documents and your account is active. No action required.", 0),
]
MSG_HELD = [
 ("Sir your SIM will be disconnected in 2 hours as per TRAI. Press 9 or call 8800123456 now to avoid police action", 1),
 ("Bro easy money, just complete 3 tasks and get Rs 800 each. Telegram me @fast_cash_job", 1),
 ("We found unpaid customs on your parcel. Transfer Rs 3200 within 12 hours to avoid seizure, pay at hxxp://parcel-release[.]buzz", 1),
 ("Your Google Pay reward Rs 5000 is waiting! Scan the QR and enter PIN to receive. Expires today.", 1),
 ("Final warning: your bank account is frozen. Share your card number and OTP to unfreeze immediately", 1),
 ("Dear sir, our client died leaving 8 million dollars, you are the next of kin. Send processing fee for transfer", 1),
 ("PayPal security alert: login from new device. Confirm at http://paypal-secure-login.xyz or account will be closed", 1),
 ("Download 'KYC_Update.apk' from http://kyc-india-fast.top/KYC_Update.apk to keep your account active", 1),
 ("Doubling your crypto in 24h, guaranteed returns, deposit USDT now before the window closes", 1),
 ("Pаyment received! Cl​aim your refund at http://refund-npci.click/verify now", 1),
 ("Hi, this is the cyber crime branch. Your Aadhaar is linked to illegal activity. Stay on the video call and do not tell anyone", 1),
 ("Your son has been arrested. Send Rs 40000 immediately to settle with the officer, do not call anyone", 1),
 ("Your bank statement for September is ready. Download it from the HDFC app.", 0),
 ("Lunch at 1? The new place near office has good reviews.", 0),
 ("Your OTP is 7712. It is valid for 5 minutes. Do not share it with anyone.", 0),
 ("Delivery: your parcel will arrive today between 2-5pm. Track at https://www.flipkart.com/track", 0),
 ("Rs 1,200 credited to a/c XX3321 by UPI from Rahul.", 0),
 ("Appointment confirmed for Tuesday 10am with Dr. Rao.", 0),
 ("Please verify the attendance sheet and send it to the principal today.", 0),
 ("Your mutual fund SIP of Rs 5000 was processed successfully.", 0),
 ("Congrats on the new job! Let's celebrate this weekend.", 0),
 ("Mom: don't forget to pay the school fee before the 15th.", 0),
 ("Your Swiggy order is out for delivery. Pay Rs 340 on delivery.", 0),
 ("Please call me when you are free, urgent but not an emergency.", 0),
]

MSG_HELD2 = [  # third set, written AFTER the rules were frozen; reported exactly as scored, never patched
 ("Your DHL parcel is on hold: address incomplete. Update details and pay 1.5 USD at http://dhl-redeliver.top/track", 1),
 ("Hi dear, I saw your profile. I'm a doctor in UK, let's chat on telegram @lily_uk88, I want to send you a gift", 1),
 ("Your electricity bill is overdue. Pay Rs 1,250 now via this link or power will be cut: bit.ly/ebill-pay-9", 1),
 ("Alert: Your Netflix payment failed. Update your card at https://netflix-account-help.xyz/login to avoid suspension", 1),
 ("You are selected for a work from home job, earn Rs 3000 per day. Send your Aadhaar and PAN to confirm registration", 1),
 ("SBI YONO: your account is locked, tap here to unlock http://yono-sbi-unlock.click and enter your net banking password", 1),
 ("Congratulations winner! You got a free iPhone 15. Pay Rs 99 shipping fee to claim", 1),
 ("Please install the attached SecureBank.apk to complete your KYC update", 1),
 ("Dear customer, your credit card reward points of Rs 8,540 will expire today. Redeem now at http://hdfc-rewardz.buzz", 1),
 ("Send me 20000 on this UPI right now, I'm in an accident, don't tell anyone, will return tonight", 1),
 ("Official notice: your GST registration will be cancelled. Pay penalty immediately at 45.33.21.8/gst/pay", 1),
 ("Hello, I'm calling from Microsoft support. Your computer has a virus. Download AnyDesk and give us the 9 digit code", 1),
 ("Earn 40% returns weekly with our crypto signals. Guaranteed. Message +44 7700 900123 on whatsapp", 1),
 ("Your account has been compromised. Verify your identity within 2 hours by entering your card number and CVV at secure-axisbank-verify.xyz", 1),
 ("Your Zomato order is arriving in 10 mins. Delivery partner: Ramesh.", 0),
 ("Your Airtel recharge of Rs 299 is successful. Validity 28 days. Visit https://www.airtel.in for more.", 0),
 ("OTP 551203 is for your Flipkart login. Do not share this OTP with anyone.", 0),
 ("Reminder: your dentist appointment is tomorrow at 11am. Reply C to confirm.", 0),
 ("Hi team, urgent: please review the Q3 report before the 4pm meeting.", 0),
 ("Your SBI statement for September is ready. Login to the official app to view.", 0),
 ("Congratulations on your promotion! Dinner is on me.", 0),
 ("UPI: Rs 450.00 sent to Anita via a/c XX9981 on 12-10. Ref 2845123.", 0),
 ("Payment of Rs 1,499 received for your Amazon order. Track it at https://www.amazon.in/gp/your-orders", 0),
 ("Mom: Send me the photos from the trip when you get time.", 0),
 ("Your electricity bill of Rs 1,120 is due on 18 Oct. Pay at https://www.bescom.karnataka.gov.in", 0),
 ("Heads up, the bank will be closed on Saturday for the festival. Plan your cash needs.", 0),
 ("The package will be delivered tomorrow. Please keep Rs 350 ready for cash on delivery.", 0),
 ("Hey, can you transfer me the Rs 500 for lunch when you're free? Thanks!", 0),
]


def eval_messages():
    out = {}
    for name, ds in (("dev", MSG_DEV), ("held_out", MSG_HELD), ("fresh_set_3", MSG_HELD2)):
        tp = fp = tn = fn = 0
        wrong = []
        for t, y in ds:
            r = shield(t, store=False); p = 1 if r["action"] in ("BLOCK", "WARN") else 0
            if y and p: tp += 1
            elif y: fn += 1; wrong.append(t[:60])
            elif p: fp += 1; wrong.append(t[:60])
            else: tn += 1
        out[name] = dict(n=len(ds), precision=round(tp / max(1, tp + fp), 3), recall=round(tp / max(1, tp + fn), 3), false_positive_rate=round(fp / max(1, fp + tn), 3), accuracy=round((tp + tn) / len(ds), 3), misses=wrong)
    MEM.counters["processed"] = 0; MEM.counters["discarded_normal"] = 0; MEM.counters["known_variant_hits"] = 0
    return out

# ====================================================================================================
# PART 2 - TRANSACTION SHIELD
# ====================================================================================================
CITIES = ["Mumbai", "Delhi", "Bengaluru", "Chennai", "Hyderabad", "Pune", "Kolkata", "Jaipur"]
DAY = 86400.0
FEATS = ["amt_logz", "amt_log", "new_device", "new_city", "new_recv", "c10m", "c1h", "c24h", "dist_recv_1h", "since_credit",
         "inout", "odd_hour", "dev_shared", "recv_age", "send_age", "prior_int", "under_thr", "fanin_6h",
         "x_dev_city", "x_dev_amt", "x_young_new", "x_burst_thr"]
FORBIDDEN = {"label", "pattern", "variant", "decoy"}
assert not (FORBIDDEN & set(FEATS)), "label leakage guard"
PHRASE = {"amt_logz": "amount far above this account's normal", "amt_log": "large absolute amount", "new_device": "payment from a new device",
          "new_city": "new city", "new_recv": "first-time payee", "c10m": "burst of payments in 10 min", "c1h": "many payments within 1 hour",
          "c24h": "unusually many payments today", "dist_recv_1h": "paying many different people in an hour", "since_credit": "money received only moments ago",
          "inout": "inflow/outflow imbalance", "odd_hour": "odd-hour activity", "dev_shared": "device shared with other accounts", "recv_age": "payee account is brand new",
          "send_age": "sender account is brand new", "prior_int": "no history with payee", "under_thr": "amount just under reporting limit", "fanin_6h": "payee is receiving from many senders",
          "x_dev_city": "new device AND new city together", "x_dev_amt": "new device with a large amount", "x_young_new": "new payee that is a young account", "x_burst_thr": "repeated just-under-limit transfers"}


def gen_data(seed=SEED, days=30, n_acc=500):
    R = random.Random(seed); H = days * DAY
    ids = ["AC%04d" % i for i in range(n_acc)]
    acc = {}
    for a in ids:
        acc[a] = dict(age=R.randint(120, 1500), city=R.choice(CITIES), dev=["D" + a[2:] + "A"] + (["D" + a[2:] + "B"] if R.random() < .3 else []),
                      mu=R.uniform(6.2, 8.2), sig=R.uniform(.45, .9), rate=R.uniform(.6, 1.8), pay=[])
    for _ in range(25):
        a, b = R.sample(ids, 2); acc[b]["dev"][0] = acc[a]["dev"][0]  # families sharing a device (benign decoy)
    for a in ids: acc[a]["pay"] = [x for x in R.sample(ids, R.randint(4, 8)) if x != a]
    EMP = ["EMP%d" % i for i in range(8)]; MER = ["MR%d" % i for i in range(10)]
    for e in EMP + MER: acc[e] = dict(age=2000, city="Mumbai", dev=["D" + e], mu=9, sig=.5, rate=0, pay=[])
    NC = ["NC%d" % i for i in range(70)]   # legitimate NEW customers (young accounts) - blur the "young payee" signal
    for e in NC: acc[e] = dict(age=R.randint(3, 40), city=R.choice(CITIES), dev=["D" + e], mu=7, sig=.6, rate=0, pay=[])
    tx = []
    def add(t, s, r, amt, dev, city, label=0, pat="", var="", decoy=0):
        tx.append(dict(t=round(t, 1), s=s, r=r, amt=round(amt, 2), dev=dev, city=city, label=label, pat=pat, var=var, decoy=decoy))
    hour_w = [1, 1, 1, 1, 1, 2, 4, 6, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 9, 7, 4, 2]
    for d in range(days):
        for a in ids:
            P = acc[a]
            for _ in range(int(P["rate"] + R.random())):
                t = d * DAY + R.choices(range(24), hour_w)[0] * 3600 + R.random() * 3600
                r = R.choice(P["pay"]) if R.random() < .84 else (R.choice(NC) if R.random() < .35 else R.choice(ids))
                if r == a: continue
                add(t, a, r, max(10, R.lognormvariate(P["mu"], P["sig"])), R.choice(P["dev"]), P["city"] if R.random() < .95 else R.choice(CITIES))
    for a in ids:  # monthly salary, a normal flow
        for d in (1, 28):
            if d < days: add(d * DAY + 9 * 3600 + R.random() * 600, R.choice(EMP), a, R.uniform(25000, 70000), "D" + "EMP", "Mumbai")
    m_of = lambda a: math.exp(acc[a]["mu"] + acc[a]["sig"] ** 2 / 2)
    nm = [0]
    def mule(age=None):
        nm[0] += 1; m = "MU%04d" % nm[0]; acc[m] = dict(age=age or (R.randint(60, 800) if R.random() < .3 else R.randint(1, 6)), city=R.choice(CITIES), dev=["DM%04d" % nm[0]], mu=7, sig=.5, rate=0, pay=[]); return m
    st = lambda lo=.08, hi=.96: R.uniform(lo, hi) * H
    st2 = lambda k, n, lo=.08, hi=.96: (lo + (hi - lo) * (k + R.random()) / n) * H   # stratified: every pattern appears in every period
    ma = lambda sub: R.randint(5, 45) if sub else None
    # ---- DECOYS (label 0) ----
    for a in R.sample(ids, 10): add(st(.1, .9), R.choice(EMP), a, R.uniform(150000, 300000), "DEMP", "Mumbai", pat="salary_bonus", decoy=1)
    for a in R.sample(ids, 14):
        t = st(.1, .9); c = R.choice([x for x in CITIES if x != acc[a]["city"]])
        for k in range(R.randint(2, 4)): add(t + k * 3000, a, R.choice(acc[a]["pay"]), max(10, R.lognormvariate(acc[a]["mu"], acc[a]["sig"])), acc[a]["dev"][0], c, pat="traveller", decoy=1)
    for a in R.sample(ids, 14): add(st(.1, .9), a, R.choice(MER), m_of(a) * R.uniform(8, 16), acc[a]["dev"][0], acc[a]["city"], pat="big_purchase", decoy=1)
    for a in R.sample(ids, 10):
        t = st(.55, .8)
        for k in range(R.randint(8, 14)): add(t + k * R.uniform(600, 2400), a, R.choice(ids), m_of(a) * R.uniform(.6, 1.8), acc[a]["dev"][0], acc[a]["city"], pat="festival_spike", decoy=1)
    for b in R.sample(ids, 5):
        for k in range(R.randint(35, 55)):
            s2 = R.choice(ids)
            if s2 != b: add(st(.05, .98), s2, b, R.uniform(80, 900), acc[s2]["dev"][0], acc[s2]["city"], pat="business_owner", decoy=1)
    for a in R.sample(ids, 16): add(st(.1, .9), a, R.choice(acc[a]["pay"]), m_of(a) * R.uniform(.5, 1.5), "DNEWPHONE" + a, acc[a]["city"], pat="new_phone", decoy=1)
    for a in R.sample(ids, 16): add(st(.1, .9), a, mule(R.randint(8, 25)), m_of(a) * R.uniform(4, 9), acc[a]["dev"][0], acc[a]["city"], pat="new_business_payee", decoy=1)
    # ---- FRAUD ----
    for k in range(30):  # structuring
        sub = k % 2; s = R.choice(ids); rcv = [mule(ma(sub)), mule(ma(sub))]; t = st2(k, 30); n = R.randint(6, 8) if sub else R.randint(8, 10); span = (4 * 3600 + R.random() * 7200) if sub else 3000
        for i in range(n): add(t + i * span / n + R.random() * 60, s, rcv[i % 2], R.uniform(5500, 9900) if sub else R.uniform(9000, 9900), acc[s]["dev"][0], acc[s]["city"], 1, "structuring", "subtle" if sub else "obvious")
    for k in range(30):  # circular
        sub = k % 2; n = R.choice([3, 4, 5]); ms = [mule(ma(sub)) for _ in range(n)]; t = st2(k, 30, .08, .9); amt = R.uniform(20000, 90000)
        for i in range(n):
            add(t, ms[i], ms[(i + 1) % n], amt, acc[ms[i]]["dev"][0], acc[ms[i]]["city"], 1, "circular", "subtle" if sub else "obvious")
            t += R.uniform(1800, 6600) if sub else R.uniform(60, 300); amt *= .95 if sub else .99
    for k in range(40):  # pass-through
        sub = k % 2; v = R.choice(ids); m1, m2 = mule(ma(sub)), mule(ma(sub)); t = st2(k, 40, .08, .9); x = R.uniform(15000, 80000)
        add(t, v, m1, x, acc[v]["dev"][0], acc[v]["city"], 1, "pass_through", "subtle" if sub else "obvious")
        add(t + (R.uniform(1200, 3600) if sub else R.uniform(120, 600)), m1, m2, x * .97, acc[m1]["dev"][0], acc[m1]["city"], 1, "pass_through", "subtle" if sub else "obvious")
    for k in range(16):  # mule rings paying one hub
        sub = k % 2; hub = mule(ma(sub)); n = R.randint(6, 10); shared = ["DR%dA" % k, "DR%dB" % k]; t0 = st2(k, 16, .08, .85)
        for i in range(n):
            m = mule(ma(sub)); acc[m]["dev"] = [R.choice(shared)] if (not sub or i % 2 == 0) else acc[m]["dev"]
            for j in range(R.randint(1, 3)): add(t0 + R.uniform(0, 20 * 3600) * (1 if sub else .3), m, hub, R.uniform(2000, 8000), acc[m]["dev"][0], acc[m]["city"], 1, "mule_ring", "subtle" if sub else "obvious")
    for k in range(100):  # account takeover
        sub = k % 2; v = R.choice(ids); m = mule(R.randint(1, 10) if not sub else R.randint(5, 40))
        c = acc[v]["city"] if sub else R.choice([x for x in CITIES if x != acc[v]["city"]])
        add(st2(k, 100), v, m, m_of(v) * (R.uniform(2, 3.5) if sub else R.uniform(5, 12)), (acc[v]["dev"][0] if (sub and R.random() < .4) else "ATK%04d" % k), c, 1, "takeover", "subtle" if sub else "obvious")
    for x in tx:
        if x["label"] == 1 and R.random() < .01: x["label"] = 0  # label noise
    tx.sort(key=lambda x: x["t"])
    for i, x in enumerate(tx): x["id"] = i
    return tx, acc


class FState:
    """Streaming feature store. Same code path for training replay and live scoring; features use PAST only."""
    def __init__(self, acc):
        self.acc = acc; self.out = defaultdict(deque); self.inn = defaultdict(deque)
        self.devs = defaultdict(set); self.cit = defaultdict(set); self.rcv = defaultdict(set)
        self.n = defaultdict(float); self.mean = {}; self.m2 = {}; self.lastcred = {}; self.inter = defaultdict(int); self.dev_acc = defaultdict(set)
        for a, P in acc.items():
            if a.startswith("AC"):
                self.devs[a] |= set(P["dev"]); self.cit[a].add(P["city"]); self.rcv[a] |= set(P["pay"])
                self.mean[a] = P["mu"]; self.m2[a] = P["sig"] ** 2 * 12; self.n[a] = 13
                for d in P["dev"]: self.dev_acc[d].add(a)
                for p in P["pay"]: self.inter[(a, p)] = 3

    def featurize(self, x):
        s, r, t, amt = x["s"], x["r"], x["t"], x["amt"]
        o = self.out[s]
        while o and o[0][0] < t - DAY: o.popleft()
        ib = self.inn[s]
        while ib and ib[0][0] < t - DAY: ib.popleft()
        rin = self.inn[r]
        while rin and rin[0][0] < t - DAY: rin.popleft()
        la = math.log(max(amt, 1)); n = self.n[s]
        mean = self.mean.get(s, 7.0); sd = math.sqrt(self.m2.get(s, .5) / max(1, n - 1)) if n > 1 else .7
        z = max(-4, min(9, (la - mean) / (sd + .3)))
        nd = 1.0 if (self.devs[s] and x["dev"] not in self.devs[s]) or (not self.devs[s]) else 0.0
        nc = 1.0 if (self.cit[s] and x["city"] not in self.cit[s]) or (not self.cit[s]) else 0.0
        nr = 0.0 if r in self.rcv[s] else 1.0
        c10 = sum(1 for e in o if e[0] >= t - 600); c1 = sum(1 for e in o if e[0] >= t - 3600)
        dr = len({e[1] for e in o if e[0] >= t - 3600})
        sc = min(72.0, (t - self.lastcred[s]) / 3600) if s in self.lastcred else 72.0
        io = math.log1p(sum(e[2] for e in ib)) - math.log1p(sum(e[2] for e in o))
        hr = (t % DAY) / 3600
        ds = len(self.dev_acc[x["dev"]]) if x["dev"] in self.dev_acc else 0
        ra = math.log1p(self.acc.get(r, {"age": 30})["age"]) / 7; sa = math.log1p(self.acc.get(s, {"age": 30})["age"]) / 7
        pi = math.log1p(self.inter[(s, r)]); ut = 1.0 if 5500 <= amt < 10000 else 0.0
        fin = len({e[1] for e in rin if e[0] >= t - 6 * 3600})
        young_new = nr * (1.0 if self.acc.get(r, {"age": 30})["age"] < 14 else 0.0)
        u5 = sum(1 for e in o if 5500 <= e[2] < 10000 and e[0] >= t - 6 * 3600)
        v = [z, la / 10, nd, nc, nr, c10, c1, len(o), dr, sc / 24, io, 1.0 if (hr < 5) else 0.0, ds, ra, sa, pi, ut, fin,
             nd * nc, nd * max(0, z), young_new, ut * min(u5, 6)]
        return v

    def update(self, x):
        s, r, t, amt = x["s"], x["r"], x["t"], x["amt"]
        self.out[s].append((t, r, amt)); self.inn[r].append((t, s, amt)); self.lastcred[r] = t
        la = math.log(max(amt, 1)); n = self.n[s] + 1; m = self.mean.get(s, la); d = la - m
        self.mean[s] = m + d / n; self.m2[s] = self.m2.get(s, 0) + d * (la - self.mean[s]); self.n[s] = n
        self.devs[s].add(x["dev"]); self.cit[s].add(x["city"]); self.rcv[s].add(r); self.inter[(s, r)] += 1; self.dev_acc[x["dev"]].add(s)


class Graph:
    """Incremental rolling 24h directed transaction graph. Edges evicted lazily, searches are bounded."""
    def __init__(self, acc):
        self.acc = acc; self.out = defaultdict(deque); self.inn = defaultdict(deque)
        self.uf = {}; self.members = defaultdict(set); self.dev_members = defaultdict(set)
    def age(self, a): return self.acc.get(a, {"age": 30})["age"]
    def find(self, a):
        self.uf.setdefault(a, a)
        while self.uf[a] != a: self.uf[a] = self.uf[self.uf[a]]; a = self.uf[a]
        return a
    def cluster(self, a):
        root = self.find(a); return [m for m in self.members_of(root)]
    def members_of(self, root):
        return [m for m in self.uf if self.find(m) == root] if len(self.uf) < 4000 else []
    def analyze(self, x):
        t, u, v, amt, dev = x["t"], x["s"], x["r"], x["amt"], x["dev"]
        sc, fd, linked = {}, [], {u, v}
        for dq in (self.out[u], self.inn[u], self.inn[v], self.out[v]):
            while dq and dq[0][0] < t - DAY: dq.popleft()
        # 1 circular flow:  v ->...-> u   (<=4 existing hops, amounts within 40%, last 6h)
        def dfs(node, path, depth):
            if depth > 4: return None
            for (tt, w, a2) in list(self.out[node])[-10:]:
                if tt < t - 6 * 3600 or not (.6 * amt <= a2 <= 1.4 * amt): continue
                if w == u: return path + [w]
                if w not in path:
                    r = dfs(w, path + [w], depth + 1)
                    if r: return r
            return None
        cyc = dfs(v, [v], 1)
        if cyc: sc["cycle"] = .9; fd.append("Circular money flow %s > %s (%d hops)" % (u, " > ".join(cyc), len(cyc))); linked |= set(cyc)
        # 2 structuring
        if 5500 <= amt < 10000:
            n = sum(1 for e in self.out[u] if 5500 <= e[2] < 10000 and e[0] >= t - 6 * 3600) + 1
            if n >= 3: sc["structuring"] = min(1, .2 + .2 * n); fd.append("%d transfers just under the Rs 10,000 limit within 6h" % n)
        # 3 pass-through
        for (tt, w, a2) in self.inn[u]:
            if t - tt <= 3600 and .75 <= amt / max(a2, 1) <= 1.05:
                s2 = .85 if self.age(u) < 30 else .25; sc["pass_through"] = s2 * (1 - .25 * (t - tt) / 3600)
                fd.append("Pass-through: Rs %d in, Rs %d out after %d min" % (a2, amt, (t - tt) / 60)); linked.add(w); break
        # 4 hub / fan-in
        snd = {e[1] for e in self.inn[v]} | {u}
        young = [a for a in snd if self.age(a) < 30]
        if len(snd) >= 4 and self.age(v) < 30 or len(young) >= 3:
            sc["hub"] = min(1, (len(young) - 1) / 4) * .9 if young else 0
            if sc["hub"] > 0: fd.append("Payee is a hub: %d senders in 24h (%d new accounts)" % (len(snd), len(young))); linked |= set(list(snd)[:10])
        # 5 mule cluster via shared devices (union-find; incremental)
        for a in (u, v):
            c = self.find(a)
        if dev:
            self.dev_members[dev].add(u)
            for m in list(self.dev_members[dev])[1:]:
                ra, rb = self.find(list(self.dev_members[dev])[0]), self.find(m)
                if ra != rb: self.uf[rb] = ra
        best = 0
        for a in (u, v):
            ms = self.members_of(self.find(a)) if a in self.uf else []
            if len(ms) >= 4:
                fy = sum(1 for m in ms if self.age(m) < 30) / len(ms)
                s5 = min(1, (len(ms) - 2) / 5) * (1 if fy >= .5 else .25)
                if s5 > best: best = s5; bm = ms
        if best > 0: sc["cluster"] = best; fd.append("Mule cluster: %d accounts share devices" % len(bm)); linked |= set(bm[:12])
        # 6 fan-out
        dr = {e[1] for e in self.out[u] if e[0] >= t - 3600}
        if len(dr) >= 6 and self.age(u) < 60: sc["fanout"] = .6; fd.append("Fan-out to %d payees in 1h" % len(dr))
        self.out[u].append((t, v, amt)); self.inn[v].append((t, u, amt))
        g = max(sc.values(), default=0) + .08 * max(0, sum(1 for s in sc.values() if s >= .3) - 1)
        return min(1.0, g), fd, sorted(linked)[:16], sc


class IForest:
    def __init__(self, X, trees=30, psi=128, seed=SEED):
        R = random.Random(seed); self.psi = psi; self.h = int(math.ceil(math.log2(psi))); self.c = self.cfun(psi); self.trees = []
        for _ in range(trees):
            S = R.sample(X, psi); self.trees.append(self.build(S, 0, R))
    @staticmethod
    def cfun(n): return 0 if n <= 1 else 2 * (math.log(n - 1) + .5772) - 2 * (n - 1) / n
    def build(self, S, d, R):
        if d >= self.h or len(S) <= 1: return ("L", len(S))
        q = R.randrange(len(S[0])); lo = min(s[q] for s in S); hi = max(s[q] for s in S)
        if lo == hi: return ("L", len(S))
        p = R.uniform(lo, hi); return ("N", q, p, self.build([s for s in S if s[q] < p], d + 1, R), self.build([s for s in S if s[q] >= p], d + 1, R))
    def path(self, nd, x, d):
        while nd[0] == "N": nd = nd[3] if x[nd[1]] < nd[2] else nd[4]; d += 1
        return d + self.cfun(nd[1])
    def score(self, x): return 2 ** (-(sum(self.path(t, x, 0) for t in self.trees) / len(self.trees)) / self.c)


def sig(z): return 1 / (1 + math.exp(-max(-30, min(30, z))))


def train_lr(X, y, w, iters, lr, l2=1e-3, mom=.8):
    n = len(X[0]); W = [0.0] * n; b = 0.0; vW = [0.0] * n; vb = 0.0; N = sum(w)
    for _ in range(iters):
        gW = [0.0] * n; gb = 0.0
        for xi, yi, wi in zip(X, y, w):
            e = (sig(b + sum(map(float.__mul__, W, xi))) - yi) * wi
            gb += e
            for j in range(n): gW[j] += e * xi[j]
        for j in range(n): vW[j] = mom * vW[j] - lr * (gW[j] / N + l2 * W[j]); W[j] += vW[j]
        vb = mom * vb - lr * gb / N; b += vb
    return W, b


class Bundle:
    """Everything learned from data: standardiser, supervised model, isolation forest, stacker weights, thresholds."""
    pass


def fit_bundle(D, tr, va, extra=(), seed=SEED, drop_val_pattern=None, drop_train_pattern=None):
    """D: dict(X,y,pat,graph,...).  tr/va: index lists (chronological). extra: (vec,label,weight) feedback rows."""
    R = random.Random(seed); B = Bundle(); X = D["X"]; nf = len(FEATS)
    trn = [i for i in tr if not (drop_train_pattern and D["pat"][i] == drop_train_pattern)]
    mu = [sum(X[i][j] for i in trn) / len(trn) for j in range(nf)]
    sd = [math.sqrt(sum((X[i][j] - mu[j]) ** 2 for i in trn) / len(trn)) + 1e-6 for j in range(nf)]
    B.mu, B.sd = mu, sd; std = lambda v: [(v[j] - mu[j]) / sd[j] for j in range(nf)]
    pos = [i for i in trn if D["y"][i] == 1]; neg = [i for i in trn if D["y"][i] == 0]; negs = R.sample(neg, min(len(neg), 2400))
    Xs = [std(X[i]) for i in pos + negs] + [std(v) for v, _, _ in extra]
    ys = [1] * len(pos) + [0] * len(negs) + [l for _, l, _ in extra]
    ws = [3.0] * len(pos) + [1.0] * len(negs) + [w for _, _, w in extra]
    B.W, B.b = train_lr(Xs, ys, ws, iters=55, lr=.9)
    normal = [std(X[i]) for i in trn if D["y"][i] == 0]; B.iso = IForest(R.sample(normal, 3000), seed=seed)
    vv = [i for i in va if not (drop_val_pattern and D["pat"][i] == drop_val_pattern)]
    B.std = std
    mp = {i: B.model_p(X[i]) for i in vv}; an_raw = sorted(B.iso.score(std(X[i])) for i in vv if D["y"][i] == 0)
    B.an_ref = an_raw; B.val_idx = vv
    B.fit_stack(D, mp); return B


def _bundle_methods():
    def model_p(self, v): return sig(self.b + sum(map(float.__mul__, self.W, self.std(v))))
    def anomaly(self, v):
        s = self.iso.score(self.std(v)); import bisect
        return bisect.bisect_left(self.an_ref, s) / max(1, len(self.an_ref))
    def contrib(self, v):
        z = self.std(v); return [self.W[j] * z[j] for j in range(len(z))]  # exact linear SHAP (baseline = training mean)
    def inputs(self, p, a, g, cols): return [{"m": math.log(max(p, 1e-4) / max(1 - p, 1e-4)) / 6, "a": a, "g": g}[c] for c in cols]
    def fit_stack(self, D, mp, cols_list=None):
        self.stacks = {}
        for name, cols in (cols_list or {"all": ["m", "a", "g"]}).items():
            Xv = [self.inputs(mp[i], D["an"][i] if "an" in D and i in D["an"] else self.anomaly(D["X"][i]), D["g"][i], cols) for i in self.val_idx]
            yv = [D["y"][i] for i in self.val_idx]
            W, b = train_lr(Xv, yv, [4.0 if y else 1.0 for y in yv], iters=250, lr=2.0, mom=.7)
            self.stacks[name] = (cols, W, b)
    def risk(self, p, a, g, name="all"):
        cols, W, b = self.stacks[name]; return sig(b + sum(w * x for w, x in zip(W, self.inputs(p, a, g, cols))))
    for f in (model_p, anomaly, contrib, inputs, fit_stack, risk): setattr(Bundle, f.__name__, f)
_bundle_methods()


def tune_thresholds(risks, ys):
    """cost-based tuning on VALIDATION only. t1: allow/verify, t2: verify/hold, t3: hold/block (precision>=.9)."""
    NB = 400; F = [0] * NB; L = [0] * NB
    for r, y in zip(risks, ys): (F if y else L)[min(NB - 1, int((max(r, 0) ** .3) * NB))] += 1
    cF = [0]; cL = [0]
    for i in range(NB): cF.append(cF[-1] + F[i]); cL.append(cL[-1] + L[i])
    tF, tL = cF[-1], cL[-1]; best = None
    for a in range(1, NB - 1, 2):
        for b in range(a + 1, NB, 2):
            fa = cF[a]; fv = cF[b] - cF[a]; lv = cL[b] - cL[a]; lh = tL - cL[b]
            c = COST["fn"] * fa + COST["fn_verified"] * fv + COST["hold_friction"] * lh + COST["verify_friction"] * lv
            if best is None or c < best[0]: best = (c, a, b)
    _, a, b = best; t3 = b
    for c3 in range(b, NB):
        tp = tF - cF[c3]; fp = tL - cL[c3]
        if tp + fp > 0 and tp / (tp + fp) >= .9: t3 = c3; break
    else: t3 = min(NB - 1, b + 20)
    return tuple((v / NB) ** (1 / .3) for v in (a, b, min(NB, max(t3, b + 1))))


def disp(r, th):
    """map raw fused risk to a human 0-1 scale where the tuned thresholds sit at .30 / .60 / .85"""
    t1, t2, t3 = th
    if r < t1: return .30 * r / t1
    if r < t2: return .30 + .30 * (r - t1) / (t2 - t1)
    if r < t3: return .60 + .25 * (r - t2) / (t3 - t2)
    return min(1.0, .85 + .15 * (r - t3) / max(1e-9, 1 - t3) * 4)


def action_for(r, th): return "ALLOW" if r < th[0] else "VERIFY" if r < th[1] else "HOLD" if r < th[2] else "BLOCK"


def guard(action, p, a, g):
    """single weak signal can never hold/block: need >=2 independent signals above floors, or one decisive."""
    if action in ("HOLD", "BLOCK"):
        n = (p >= .25) + (a >= .6) + (g >= .3)
        if n < 2 and p < .9 and g < .8: return "VERIFY"
    return action


def trust_adj(r, age): return max(0, min(1, r - .03 if age >= 180 else r + .04 if age < 14 else r))


def metrics(pred, truth, decoy=None, actions=None):
    tp = sum(1 for p, y in zip(pred, truth) if p and y); fp = sum(1 for p, y in zip(pred, truth) if p and not y)
    fn = sum(1 for p, y in zip(pred, truth) if not p and y); tn = sum(1 for p, y in zip(pred, truth) if not p and not y)
    pr = tp / max(1, tp + fp); rc = tp / max(1, tp + fn)
    return dict(precision=round(pr, 3), recall=round(rc, 3), fpr=round(fp / max(1, fp + tn), 4), f1=round(2 * pr * rc / max(1e-9, pr + rc), 3), tp=tp, fp=fp, fn=fn, tn=tn)


def pr_auc(scores, ys):
    o = sorted(zip(scores, ys), key=lambda z: -z[0]); P = sum(ys); tp = fp = 0; auc = 0; prev_r = 0
    for s, y in o:
        tp += y; fp += 1 - y; r = tp / P; auc += (r - prev_r) * tp / (tp + fp); prev_r = r
    return round(auc, 3)


def pct(a, q):
    a = sorted(a); return round(a[min(len(a) - 1, int(len(a) * q))], 3) if a else 0

# ----------------------------------------------------------------------------------------------------
ENG = None
LOG = []


class Engine:
    def __init__(self):
        self.ready = False; self.phase = "starting"; self.report = {}; self.lock = threading.RLock(); self.sim_t = 0; self.scn = 0
        self.cdb = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cdb.execute("CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, ts REAL, status TEXT, risk REAL, action TEXT, accounts TEXT, txns TEXT, reasons TEXT, findings TEXT, feedback INTEGER, vec TEXT)")
        self.open_by_acc = {}; self.cases = {}; self.feedback = []

    # ---------------- build / train / evaluate ----------------
    def build(self):
        t0 = perf_counter(); self.phase = "generating synthetic data"
        tx, acc = gen_data(); self.tx = tx; self.acc = acc; N = len(tx)
        self.phase = "streaming features + graph"
        fs = FState(acc); gr = Graph(acc); X = []; G = []; GF = []; GS = []; tl = []
        for x in tx:
            a = perf_counter(); v = fs.featurize(x); b = perf_counter(); g, fd, lk, scs = gr.analyze(x); c = perf_counter(); fs.update(x)
            X.append(v); G.append(g); GF.append((fd, lk)); GS.append(scs); tl.append((b - a, c - b))
        self.fs, self.gr = fs, gr
        # no-future-leakage proof: re-featurize a few txns from a fresh store fed ONLY with their past
        ok = True
        for i in random.Random(1).sample(range(500, N), 6):
            f2 = FState(acc)
            for x in tx[:i]: f2.featurize(x); f2.update(x)
            ok &= all(abs(p - q) < 1e-9 for p, q in zip(f2.featurize(tx[i]), X[i]))
        self.no_leak_test = bool(ok)
        i1, i2 = int(N * .6), int(N * .8); tr, va, te = list(range(i1)), list(range(i1, i2)), list(range(i2, N))
        D = dict(X=X, y=[x["label"] for x in tx], pat=[x["pat"] if x["label"] else "" for x in tx], g=G)
        self.D, self.split = D, (tr, va, te)
        self.phase = "training supervised model + isolation forest"
        B = fit_bundle(D, tr, va); self.B = B
        self.phase = "evaluating"
        rep = self.evaluate(D, B, tr, va, te, tl)
        rep["data"] = dict(transactions=N, accounts=len(acc), fraud_rate=round(sum(D["y"]) / N, 4), decoys=sum(x["decoy"] for x in tx),
                           split=dict(train=len(tr), validation=len(va), test=len(te)), no_future_leak_test=self.no_leak_test,
                           forbidden_features_guard=sorted(FORBIDDEN), feature_count=len(FEATS))
        # held-out pattern: never train/tune on takeover, test on it
        B2 = fit_bundle(D, tr, va, drop_train_pattern="takeover", drop_val_pattern="takeover")
        anB2 = {i: B2.anomaly(X[i]) for i in te}; mpB2 = {i: B2.model_p(X[i]) for i in te}
        vv = B2.val_idx; vr = [trust_adj(B2.risk(B2.model_p(X[i]), B2.anomaly(X[i]), G[i]), self.acc.get(tx[i]["s"], {"age": 30})["age"]) for i in vv]
        th2 = tune_thresholds(vr, [D["y"][i] for i in vv]); hit = n = 0
        for i in te:
            if D["y"][i] and D["pat"][i] == "takeover":
                n += 1; r = trust_adj(B2.risk(mpB2[i], anB2[i], G[i]), self.acc.get(tx[i]["s"], {"age": 30})["age"])
                hit += guard(action_for(r, th2), mpB2[i], anB2[i], G[i]) in ("HOLD", "BLOCK")
        rep["held_out_pattern"] = dict(pattern="account takeover (removed from training AND validation)", test_cases=n, recall=round(hit / max(1, n), 3),
                                       note="supervised model never saw this fraud type; recall comes from generalising features + anomaly detector")
        rep["adaptive"] = self.adaptive_experiment(D, B, tr, va, te)
        rep["messages"] = eval_messages(); rep["build_seconds"] = round(perf_counter() - t0, 1)
        self.report = rep; self.sim_t = tx[-1]["t"] + 7200; self.ready = True; self.phase = "ready"
        # prepare replay stream from test split (precomputed decisions)
        self.stream = []; th = self.th
        for i in te:
            self.stream.append(self.decide_row(i, th))

    def decide_row(self, i, th):
        D, B, tx = self.D, self.B, self.tx; x = tx[i]; p = B.model_p(D["X"][i]); a = B.anomaly(D["X"][i]); g = D["g"][i]
        r = trust_adj(B.risk(p, a, g), self.acc.get(x["s"], {"age": 30})["age"]); act = guard(action_for(r, th), p, a, g)
        return dict(id=i, t=x["t"], s=x["s"], r=x["r"], amt=x["amt"], city=x["city"], risk=round(disp(r, th), 3), action=act, truth=x["label"], pattern=x["pat"], decoy=x["decoy"], variant=x["var"])

    def evaluate(self, D, B, tr, va, te, tl):
        X, y, G, tx = D["X"], D["y"], D["g"], self.tx
        P = {}; A = {}; lat = []
        for i in va + te:
            a0 = perf_counter(); P[i] = B.model_p(X[i]); a1 = perf_counter(); A[i] = B.anomaly(X[i]); a2 = perf_counter()
            if i >= te[0]: lat.append((tl[i][0], P[i] and a1 - a0, a2 - a1, tl[i][1]))
        D["an"] = A
        cfg = {"model only": ["m"], "anomaly only": ["a"], "graph only": ["g"], "model + anomaly": ["m", "a"], "model + graph": ["m", "g"], "all three (fused)": ["m", "a", "g"]}
        B.fit_stack(D, P, cfg); abl = {}
        for name, cols in cfg.items():
            vr = [B.risk(P[i], A[i], G[i], name) for i in va]; th = tune_thresholds(vr, [y[i] for i in va])
            m = metrics([action_for(B.risk(P[i], A[i], G[i], name), th) in ("HOLD", "BLOCK") for i in te], [y[i] for i in te]); m["pr_auc"] = pr_auc([B.risk(P[i], A[i], G[i], name) for i in te], [y[i] for i in te]); abl[name] = m
        cols, W, b = B.stacks["all three (fused)"]; B.stacks["all"] = B.stacks["all three (fused)"]
        vr = [trust_adj(B.risk(P[i], A[i], G[i]), self.acc.get(tx[i]["s"], {"age": 30})["age"]) for i in va]; th = tune_thresholds(vr, [y[i] for i in va]); self.th = th
        acts = []; rs = []
        for i in te:
            r = trust_adj(B.risk(P[i], A[i], G[i]), self.acc.get(tx[i]["s"], {"age": 30})["age"]); rs.append(r); acts.append(guard(action_for(r, th), P[i], A[i], G[i]))
        ty = [y[i] for i in te]; m = metrics([a in ("HOLD", "BLOCK") for a in acts], ty); m["pr_auc"] = pr_auc(rs, ty)
        legit = [k for k, i in enumerate(te) if not y[i]]; dec = [k for k, i in enumerate(te) if tx[i]["decoy"]]
        fr = dict(verify=round(sum(acts[k] == "VERIFY" for k in legit) / len(legit), 4), hold_block=round(sum(acts[k] in ("HOLD", "BLOCK") for k in legit) / len(legit), 4),
                  allowed_untouched=round(sum(acts[k] == "ALLOW" for k in legit) / len(legit), 4))
        pat = defaultdict(lambda: [0, 0])
        for k, i in enumerate(te):
            if y[i]: key = "%s (%s)" % (tx[i]["pat"], tx[i]["var"]); pat[key][1] += 1; pat[key][0] += acts[k] in ("HOLD", "BLOCK")
        thr_acts = {a: sum(1 for z in acts if z == a) for a in ("ALLOW", "VERIFY", "HOLD", "BLOCK")}
        r1 = [tx[i]["amt"] > 50000 for i in te]
        r3 = [tx[i]["amt"] > 30000 or X[i][6] >= 6 or (X[i][2] and tx[i]["amt"] > 15000) for i in te]
        e2e = [sum(z) * 1000 for z in lat if z[1] is not None]
        comp = {n: pct([z[k] * 1000 for z in lat], .95) for k, n in enumerate(["features", "model", "isolation_forest", "graph"])}
        by_dec = {}
        for k in dec: by_dec[tx[te[k]]["pat"]] = by_dec.get(tx[te[k]]["pat"], [0, 0]); by_dec[tx[te[k]]["pat"]][1] += 1; by_dec[tx[te[k]]["pat"]][0] += acts[k] == "ALLOW"
        W_named = {"model": round(W[cols.index("m")], 2), "anomaly": round(W[cols.index("a")], 2), "graph": round(W[cols.index("g")], 2), "bias": round(b, 2)}
        return dict(test=dict(**m, test_txns=len(te), friction_on_legit=fr, actions=thr_acts,
                              decoy_pass_rate=round(sum(acts[k] == "ALLOW" for k in dec) / max(1, len(dec)), 3), decoys=len(dec), decoy_breakdown={k: "%d/%d allowed" % tuple(v) for k, v in by_dec.items()}),
                    thresholds=dict(verify_from=round(th[0], 3), hold_from=round(th[1], 3), block_from=round(th[2], 3), tuned_on="validation only"),
                    fusion_weights_learned=W_named, per_pattern_recall={k: dict(recall=round(v[0] / v[1], 3), n=v[1]) for k, v in sorted(pat.items())},
                    baseline_rule_amount_gt_50k=metrics(r1, ty), baseline_3_rule_engine=metrics(r3, ty), ablation=abl,
                    latency_ms=dict(p50=pct(e2e, .5), p95=pct(e2e, .95), p99=pct(e2e, .99), p95_by_component=comp, note="end-to-end, no SHAP (SHAP only computed for Verify/Hold/Block)"))

    def adaptive_experiment(self, D, B, tr, va, te):
        tx, X, y, G = self.tx, D["X"], D["y"], D["g"]; half = len(te) // 2; A, Bw = te[:half], te[half:]
        def run(bundle, th):
            acts = [guard(action_for(trust_adj(bundle.risk(bundle.model_p(X[i]), bundle.anomaly(X[i]), G[i]), self.acc.get(tx[i]["s"], {"age": 30})["age"]), th), bundle.model_p(X[i]), bundle.anomaly(X[i]), G[i]) in ("HOLD", "BLOCK") for i in Bw]
            return metrics(acts, [y[i] for i in Bw])
        before = run(B, self.th)
        fb = []
        for i in A:
            r = trust_adj(B.risk(B.model_p(X[i]), B.anomaly(X[i]), G[i]), 100)
            if action_for(r, self.th) != "ALLOW": fb.append((X[i], y[i], 6.0))   # analysts review everything that was flagged
        B2 = fit_bundle(D, tr, va, extra=fb); B2.stacks["all"] = B2.stacks["all"]
        vr = [trust_adj(B2.risk(B2.model_p(X[i]), B2.anomaly(X[i]), G[i]), self.acc.get(tx[i]["s"], {"age": 30})["age"]) for i in B2.val_idx]
        th2 = tune_thresholds(vr, [y[i] for i in B2.val_idx]); after = run(B2, th2)
        return dict(feedback_rows=len(fb), window="analyst labels from the first half of the test period; scored on the second half", before=before, after=after,
                    honest_note="the learned supervised layer improves only if feedback contains patterns the model had under-weighted; report is raw, not cherry-picked")

    # ---------------- live scoring ----------------
    def score(self, x, with_case=True):
        with self.lock:
            tm = {}; t0 = perf_counter(); fs, gr, B = self.fs, self.gr, self.B
            x = dict(x); x.setdefault("t", self.sim_t); x.setdefault("dev", "D?"); x.setdefault("city", "Mumbai")
            for k in ("s", "r"): self.acc.setdefault(x[k], dict(age=x.get("age_" + k, 400), city=x["city"], dev=[x["dev"]], mu=7, sig=.6, rate=0, pay=[]))
            v = fs.featurize(x); tm["features"] = perf_counter() - t0; t1 = perf_counter()
            g, fd, lk, scs = gr.analyze(x); tm["graph"] = perf_counter() - t1; t1 = perf_counter()
            p = B.model_p(v); tm["model"] = perf_counter() - t1; t1 = perf_counter(); a = B.anomaly(v); tm["isolation_forest"] = perf_counter() - t1
            fs.update(x); self.sim_t = max(self.sim_t, x["t"])
            r = trust_adj(B.risk(p, a, g), self.acc[x["s"]]["age"]); act = guard(action_for(r, self.th), p, a, g)
            reasons = []
            if act != "ALLOW":
                cn = B.contrib(v); order = sorted(range(len(cn)), key=lambda j: -cn[j]); pos = [(j, cn[j]) for j in order if cn[j] > .05][:4]; tot = sum(c for _, c in pos) or 1
                mshare = max(0, p - .1)
                rd = disp(r, self.th); reasons = [dict(feature=FEATS[j], text=PHRASE[FEATS[j]], points=round(100 * rd * c / tot * .55)) for j, c in pos]
                for f in fd: reasons.append(dict(feature="graph", text=f, points=round(100 * rd * g * .45 / max(1, len(fd)))))
                if a > .8: reasons.append(dict(feature="anomaly", text="behaviour is statistically unusual vs normal traffic (top %d%%)" % round((1 - a) * 100 + 1), points=round(a * 12)))
            res = dict(id=x.get("id"), s=x["s"], r=x["r"], amt=x["amt"], risk=round(disp(r, self.th), 3), action=act, signals=dict(model=round(p, 3), anomaly=round(a, 3), graph=round(g, 3)),
                       reasons=reasons, findings=fd, linked=lk, latency_ms=round((perf_counter() - t0) * 1000, 2), component_ms={k: round(v2 * 1000, 2) for k, v2 in tm.items()},
                       intervention=dict(ALLOW="none - silent approval", VERIFY="step-up verification (OTP / in-app confirmation)", HOLD="hold payment, open case, contact customer", BLOCK="block, freeze payee, escalate to fraud ops")[act])
            if with_case and act in ("HOLD", "BLOCK"): res["case_id"] = self.add_case(x, res, v)
            return res

    def add_case(self, x, res, vec):
        accs = set([x["s"], x["r"]] + res["linked"]); cid = None
        for a in accs:
            if a in self.open_by_acc: cid = self.open_by_acc[a]; break
        edge = [x["s"], x["r"], x["amt"], res["action"], round(res["risk"], 2)]
        if cid and cid in self.cases:
            c = self.cases[cid]; c["accounts"] = sorted(set(c["accounts"]) | accs)[:40]; c["txns"].append(edge); c["alerts_merged"] += 1
            c["risk"] = max(c["risk"], res["risk"]); c["findings"] = sorted(set(c["findings"]) | set(res["findings"]))[:6]
            if res["risk"] >= c["risk"]: c["reasons"] = res["reasons"]
            c["action"] = "BLOCK" if "BLOCK" in (c["action"], res["action"]) else "HOLD"; c["vec"] = vec
        else:
            cid = self.cdb.execute("INSERT INTO cases(ts,status,risk,action,accounts,txns,reasons,findings,feedback,vec) VALUES(?,?,?,?,?,?,?,?,?,?)", (time.time(), "open", res["risk"], res["action"], "[]", "[]", "[]", "[]", None, "[]")).lastrowid
            self.cases[cid] = dict(id=cid, status="open", risk=res["risk"], action=res["action"], accounts=sorted(accs)[:40], txns=[edge], reasons=res["reasons"], findings=res["findings"], alerts_merged=1, ts=time.time(), vec=vec, truth=None)
        for a in accs: self.open_by_acc[a] = cid
        c = self.cases[cid]
        self.cdb.execute("UPDATE cases SET risk=?,action=?,accounts=?,txns=?,reasons=?,findings=? WHERE id=?", (c["risk"], c["action"], json.dumps(c["accounts"]), json.dumps(c["txns"]), json.dumps(c["reasons"]), json.dumps(c["findings"]), cid)); self.cdb.commit()
        return cid

    def resolve(self, cid, fraud):
        with self.lock:
            c = self.cases.get(cid)
            if not c: return None
            c["status"] = "confirmed_fraud" if fraud else "false_alarm"; self.feedback.append((c["vec"], 1 if fraud else 0, 6.0))
            for a in c["accounts"]:
                if self.open_by_acc.get(a) == cid: del self.open_by_acc[a]
            self.cdb.execute("UPDATE cases SET status=?,feedback=? WHERE id=?", (c["status"], int(fraud), cid)); self.cdb.commit()
            return dict(id=cid, status=c["status"], pending_feedback_rows=len(self.feedback))

    def retrain(self):
        with self.lock:
            tr, va, te = self.split; t0 = perf_counter(); n = len(self.feedback)
            B2 = fit_bundle(self.D, tr, va, extra=self.feedback); B2.stacks["all"] = B2.stacks["all"]
            vr = [trust_adj(B2.risk(B2.model_p(self.D["X"][i]), B2.anomaly(self.D["X"][i]), self.D["g"][i]), 100) for i in B2.val_idx]
            self.th = tune_thresholds(vr, [self.D["y"][i] for i in B2.val_idx]); self.B = B2
            return dict(retrained_with_feedback_rows=n, new_thresholds=[round(t, 3) for t in self.th], seconds=round(perf_counter() - t0, 1))

    # ---------------- scenarios through the LIVE engine ----------------
    def scenario(self, name):
        with self.lock:
            self.scn += 1; k = self.scn; R = random.Random(k * 7 + 1); t = self.sim_t + 600; out = []; accs = [a for a in self.acc if a.startswith("AC")]
            def mk(s, r, amt, dev, city, dt, **kw):
                nonlocal t
                t += dt; out.append(dict(s=s, r=r, amt=round(amt, 2), dev=dev, city=city, t=t, **kw))
            def newacc(pfx, age): a = "%s%d_%d" % (pfx, k, len(self.acc)); self.acc[a] = dict(age=age, city=R.choice(CITIES), dev=["DN" + a], mu=7, sig=.6, rate=0, pay=[]); return a
            v = R.choice(accs); P = self.acc[v]; m = math.exp(P["mu"] + P["sig"] ** 2 / 2); pay = P["pay"][0] if P["pay"] else R.choice(accs)
            if name == "normal": mk(v, pay, m * .9, P["dev"][0], P["city"], 5); lab = "Everyday payment to a known payee"
            elif name == "salary": mk("EMP1", v, 95000, "DEMP", "Mumbai", 5); lab = "Large salary bonus credited (decoy - must be allowed)"
            elif name == "traveller": c = R.choice([c for c in CITIES if c != P["city"]]); mk(v, pay, m, P["dev"][0], c, 5); lab = "Genuine customer paying from a new city (decoy)"
            elif name == "structuring":
                rc = [newacc("MU", 2), newacc("MU", 3)]
                for i in range(8): mk(v, rc[i % 2], R.uniform(9000, 9900), P["dev"][0], P["city"], 330)
                lab = "8 transfers just under the Rs 10,000 limit"
            elif name == "circular":
                ms = [newacc("MU", 2) for _ in range(4)]; amt = 48000
                for i in range(4): mk(ms[i], ms[(i + 1) % 4], amt, "DX" + ms[i], "Delhi", 140); amt *= .99
                lab = "A > B > C > D > A circular laundering"
            elif name == "ring":
                hub = newacc("MU", 2); dv = ["DRING%d_A" % k, "DRING%d_B" % k]
                for i in range(9): mk(newacc("MU", 2), hub, R.uniform(2500, 7500), R.choice(dv), "Pune", 240)
                lab = "9 young accounts sharing 2 devices pay one hub"
            elif name == "takeover":
                mu = newacc("MU", 2); c = R.choice([c for c in CITIES if c != P["city"]]); mk(v, mu, m * 9, "ATKNEW%d" % k, c, 5); lab = "New device + new city + huge transfer to a brand-new payee"
            elif name == "passthrough":
                m1, m2 = newacc("MU", 2), newacc("MU", 3); x = 52000; mk(v, m1, x, P["dev"][0], P["city"], 5); mk(m1, m2, x * .97, "DX" + m1, "Jaipur", 240); lab = "Money in, almost the same out within 4 minutes"
            else: return None
            return dict(scenario=name, label=lab, results=[dict(tx=o, **self.score(o)) for o in out])

    def graph_view(self):
        nodes = {}; edges = []
        for c in self.cases.values():
            if c["status"] != "open": continue
            for a in c["accounts"][:30]: nodes[a] = dict(id=a, case=c["id"], young=self.acc.get(a, {"age": 999})["age"] < 30)
            for s, r, amt, act, rk in c["txns"][-40:]: edges.append(dict(s=s, r=r, amt=amt, action=act))
        return dict(nodes=list(nodes.values()), edges=edges)

# ====================================================================================================
# HTTP API
# ====================================================================================================
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # never log message content
    def _send(self, code, obj, ctype="application/json"):
        b = obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Access-Control-Allow-Headers", "Content-Type"); self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers(); self.wfile.write(b)
    def do_OPTIONS(self): self._send(204, b"")
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); p = u.path; q = urllib.parse.parse_qs(u.query)
        try:
            if p in ("/", "/index.html"):
                f = os.path.join(HERE, "index.html")
                return self._send(200, open(f, "rb").read(), "text/html; charset=utf-8") if os.path.exists(f) else self._send(404, {"error": "index.html missing"})
            if p == "/api/health": return self._send(200, dict(ok=True, ready=ENG.ready, phase=ENG.phase, version="shieldnet-1"))
            if p == "/api/privacy": return self._send(200, dict(counters=MEM.counters, stored=[dict(id=i["id"], typology=i["typology"], hits=i["hits"], redacted=i["redacted"], domains=i["domains"]) for i in MEM.items[-8:][::-1]],
                                                               policy="Normal messages are analysed in RAM and discarded. Only confirmed spam is kept as a redacted fingerprint."))
            if not ENG.ready and p != "/api/health" and not p.startswith("/api/message"): return self._send(503, dict(ready=False, phase=ENG.phase))
            if p == "/api/metrics": return self._send(200, ENG.report)
            if p == "/api/cases": return self._send(200, [{k: v for k, v in c.items() if k != "vec"} for c in sorted(ENG.cases.values(), key=lambda c: -c["risk"])][:60])
            if p == "/api/graph": return self._send(200, ENG.graph_view())
            if p == "/api/stream":
                a = int(q.get("from", ["0"])[0]); n = min(60, int(q.get("n", ["10"])[0])); return self._send(200, dict(items=ENG.stream[a:a + n], next=(a + n) % max(1, len(ENG.stream)), total=len(ENG.stream)))
            return self._send(404, {"error": "not found"})
        except Exception as e: return self._send(500, {"error": str(e)})
    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path; b = self.body()
        try:
            if p == "/api/message": return self._send(200, shield(str(b.get("text", ""))[:6000], store=bool(b.get("store", True))))
            if p == "/api/message/report":
                t = str(b.get("text", ""))[:6000]; r = shield(t, store=False); doms = sorted({registrable(u["host"]) for u in r["urls"] if u["host"] and "." in u["host"]})
                mid, new = MEM.store(t, "user_reported", doms); return self._send(200, dict(stored=True, id=mid, new=new, privacy="only a redacted fingerprint was kept"))
            if p == "/api/url": return self._send(200, analyze_url(str(b.get("url", ""))[:500]))
            if not ENG.ready: return self._send(503, dict(ready=False, phase=ENG.phase))
            if p == "/api/score":
                x = dict(s=str(b["s"]), r=str(b["r"]), amt=float(b["amt"]), dev=str(b.get("dev", "D?")), city=str(b.get("city", "Mumbai")))
                if b.get("t") is not None: x["t"] = float(b["t"])
                return self._send(200, ENG.score(x))
            if p == "/api/scenario":
                r = ENG.scenario(str(b.get("name", ""))); return self._send(200 if r else 400, r or {"error": "unknown scenario"})
            if p.startswith("/api/cases/") and p.endswith("/resolve"):
                r = ENG.resolve(int(p.split("/")[3]), bool(b.get("fraud"))); return self._send(200 if r else 404, r or {"error": "no such case"})
            if p == "/api/retrain": return self._send(200, ENG.retrain())
            return self._send(404, {"error": "not found"})
        except Exception as e: return self._send(500, {"error": str(e)})


def selftest():
    """python server.py --selftest : proves the claims (privacy, no leakage, blocking behaviour, API round-trip)."""
    global ENG
    ENG = Engine(); ENG.build(); res = []
    def check(name, ok): res.append((name, bool(ok))); print(("PASS  " if ok else "FAIL  ") + name, flush=True)
    check("features use the past only (re-featurised from a fresh store fed only earlier txns)", ENG.no_leak_test)
    check("label/pattern/decoy can never be features", not (FORBIDDEN & set(FEATS)))
    n0, c0 = len(MEM.items), MEM.db.execute("SELECT COUNT(*) FROM spam_memory").fetchone()[0]
    for t in ["Hey are we still on for dinner at 8 tomorrow?", "Your OTP is 4821. Do not share it with anyone.", "Lunch at 1?"]: shield(t)
    check("normal messages leave NOTHING in memory or database", len(MEM.items) == n0 and MEM.db.execute("SELECT COUNT(*) FROM spam_memory").fetchone()[0] == c0)
    r = shield("URGENT: Your SBI account will be blocked. Verify KYC at http://sbi-kyc-update.xyz/login and share OTP now")
    check("phishing message is blocked and only a masked fingerprint is kept", r["action"] == "BLOCK" and r["stored_in_memory"] and "sbi-kyc-update.xyz" in MEM.items[-1]["redacted"] and "xyz/login" not in MEM.items[-1]["redacted"])
    r2 = shield("urgent!! your SBI a/c will be blocked. verify KYC at http://sbi-kyc-update.xyz/login and share OTP now 99")
    check("reworded copy of known spam is recognised from memory", r2["action"] == "BLOCK")
    check("zero-width obfuscation does not hide a scam", shield("Cl\u200baim your pr\u200bize: pay Rs 500 fee at http://win-big.top now")["action"] in ("BLOCK", "WARN"))
    for nm, want in (("normal", ("ALLOW",)), ("salary", ("ALLOW", "VERIFY")), ("traveller", ("ALLOW", "VERIFY")), ("structuring", ("BLOCK", "HOLD")), ("circular", ("BLOCK", "HOLD")), ("ring", ("BLOCK", "HOLD")), ("takeover", ("BLOCK", "HOLD")), ("passthrough", ("BLOCK", "HOLD"))):
        out = ENG.scenario(nm); check("scenario %-11s -> %s" % (nm, out["results"][-1]["action"]), out["results"][-1]["action"] in want)
    check("a ring of alerts merges into few cases", max(c["alerts_merged"] for c in ENG.cases.values()) >= 5)
    check("single weak signal never blocks (guard)", guard("BLOCK", .1, .1, .1) == "VERIFY" and guard("BLOCK", .95, .0, .0) == "BLOCK")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    import urllib.request
    def post(path, o): return json.loads(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d%s" % (srv.server_port, path), json.dumps(o).encode(), {"Content-Type": "application/json"}), timeout=20).read())
    check("HTTP API round-trip /api/message", post("/api/message", {"text": "Congratulations! You won a lottery. Pay Rs 4999 fee to claim your prize"})["action"] in ("BLOCK", "WARN"))
    P = ENG.acc["AC0001"]
    check("HTTP API round-trip /api/score (usual device, city, payee -> Allow)", post("/api/score", {"s": "AC0001", "r": P["pay"][0], "amt": 500, "dev": P["dev"][0], "city": P["city"]})["action"] == "ALLOW")
    check("same account, unknown device + new city -> not silently allowed", post("/api/score", {"s": "AC0001", "r": "AC0002", "amt": 500, "dev": "UNKNOWN", "city": "Kochi"})["action"] != "ALLOW")
    bad = [n for n, ok in res if not ok]; print("\n%d/%d checks passed" % (len(res) - len(bad), len(res))); sys.exit(1 if bad else 0)


def main():
    global ENG
    ENG = Engine()
    if "--selftest" in sys.argv: selftest(); return
    if "--eval" in sys.argv:
        ENG.build(); print(json.dumps(ENG.report, indent=1)); return
    port = int(os.environ.get("PORT", 8000))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), H)   # bind the port FIRST so hosts (Render) see it open immediately
    print("ShieldNet listening on 0.0.0.0:%d  (engine trains in the background; message shield is live immediately)" % port, flush=True)
    def _train():
        try: ENG.build(); print("engine ready", flush=True)
        except Exception as e: ENG.phase = "failed: %s" % e; print("engine build failed:", e, flush=True)
    sys.setswitchinterval(0.002)  # keep the web thread responsive while training runs
    threading.Thread(target=_train, daemon=True).start()
    httpd.serve_forever()


if __name__ == "__main__":
    main()
