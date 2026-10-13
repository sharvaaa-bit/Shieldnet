# ShieldNet — stop spam, phishing and fraud *before* they reach the network or the device

Three files, zero dependencies on the backend:

| File | What it is |
|---|---|
| `index.html` | Front end: HTML + CSS + vanilla JS + Three.js (3D "shield" around the UPI/bank network). Works alone (in-browser demo engine) or connected to the backend. |
| `server.py` | Back end: Python 3.9+ **standard library only** (HTTP API, SQLite, trained models, graph engine, message shield). `python server.py` |
| `README.md` | This file. |

## What it does

**1. Message shield — before it hits the phone.** Reads every incoming SMS / chat / email / link and decides Allow / Warn / Block.
Old spam is recognised instantly (simhash memory); **new spam is caught by structure, not by an old keyword list**:
pressure + ask + impersonation + private-channel shift, URL forensics (look-alike brands, IP hosts, punycode, shorteners,
executable downloads, credential-harvest paths), and hidden payloads (zero-width characters, bidi overrides, homoglyph words,
hidden HTML, base64 blobs that decode to code, double-extension files). A single weak signal never blocks.

**Privacy by design.** Normal messages are analysed in RAM and discarded: only a counter survives. Only *confirmed spam* is kept,
as a redacted fingerprint (numbers/emails/phones masked, links reduced to their domain). See the *Privacy ledger* panel.

**2. Transaction shield — before it hits the UPI / bank rails.** Every payment gets three independent signals:
supervised model (22 point-in-time features incl. interactions) · isolation-forest anomaly · rolling 24 h transaction graph
(cycles, hubs, mule clusters via shared devices, pass-through, structuring). A stacking layer **learns** the fusion weights on a
validation split; action thresholds are **cost-tuned on validation only**. Results: Allow / Verify / Hold / Block, exact linear-SHAP
reason codes (only computed for non-Allow), merged cases (a ring is ONE case), and analyst feedback → retrain.

## Run it

```bash
python server.py            # http://localhost:8000  (serves index.html too). First boot trains in ~15 s.
python server.py --eval     # prints the full evaluation report as JSON
```
`PORT` env var is respected. No `pip install` needed.

## Put it on GitHub and host it

1. Create a repo, upload the three files (drag & drop in the GitHub web UI works).
2. **Front end (free):** Settings → Pages → *Deploy from a branch* → `main` / root. URL: `https://<you>.github.io/<repo>/`.
   With no backend it runs the **DEMO engine** (clearly labelled; metrics shown are a snapshot of a reference run).
3. **Real engine (free tier):** render.com → New → Web Service → connect the repo → Runtime *Python* → Build command *(empty)* →
   Start command `python server.py`. Render gives you `https://<name>.onrender.com` which serves the *whole* app with the live engine.
4. To use that backend from the GitHub Pages site, open `https://<you>.github.io/<repo>/?api=https://<name>.onrender.com`
   (or click **⚙ API** and paste it once). CORS is enabled.

Tip: free hosts sleep when idle, so open the URL a minute before you present.

## Measured results (synthetic data, unseen last 20 % of time, thresholds tuned on validation only)

| | precision | recall | false-positive rate |
|---|---|---|---|
| **ShieldNet (fused + guard)** | **0.78** | **0.97** | **0.68 %** |
| rule: amount > ₹50,000 | 0.03 | 0.07 | 5.5 % |
| 3-rule engine | 0.06 | 0.30 | 12.6 % |

- 20,379 transactions, 4 % fraud, 409 legitimate-but-unusual decoys; chronological 60/20/20 split.
- Legitimate customers never touched: **97.8 %**; asked to verify 1.5 %; held/blocked 0.7 %. Decoys allowed: 90.3 %.
- Latency per transaction: p50 0.28 ms · p95 0.48 ms (pure Python, no SHAP on the Allow path).
- Weakest spot, reported not hidden: **subtle account takeover** (known device, moderate amount) recall 0.63; takeover removed
  from training and validation entirely still reaches recall 0.75 on the test period.
- Ablation (model / anomaly / graph / combinations), per-pattern obvious-vs-subtle recall, adaptive before/after and the message
  self-test are in the **Proof & metrics** drawer of the UI (and in `python server.py --eval`).
- Guards: labels/pattern/decoy can never be features (asserted at import); a test proves features use past data only.

## Honest limits
- Data is synthetic and self-generated, so absolute numbers flatter reality; the baselines and ablations are the meaningful part.
- Supervised layer is a transparent logistic model + interactions (so SHAP is exact); swap LightGBM/XGBoost in behind `fit_bundle`.
- Message self-test sets are tiny hand-written lists (33 dev, 24 held-out); held-out recall is 0.83 and its two misses are shown, not patched.
- OTP step-up is simulated; the message shield cannot read encrypted end-to-end chats, only what a gateway/app hands it.
- Adaptive learning on this data shows little before/after change; it is real but small.

## 3-minute demo script
1. Paste *Bank KYC phish* → Spam, red burst on the shield, "stored: redacted fingerprint". Paste a reworded copy → recognised as known spam.
2. Paste *Normal chat* → delivered, **nothing stored** (privacy ledger: discarded +1).
3. *Novel (no old keywords)* → Suspicious/warn from structure alone. *Hidden payload* → invisible characters + `.pdf.exe`.
4. Scenarios: *Normal*, *Big salary* and *Traveller* pass untouched → *Structuring*, *Circular*, *Mule ring* (watch 9 alerts merge into one case) → *Takeover*.
5. Open **Proof & metrics**: baselines, ablation, held-out pattern, latency. Close with the 30-second pitch:
   *"Every message and payment is screened before it reaches the device or the network, by three independent signals fused with learned
   weights, explained in plain reasons, and we keep nothing about normal users."*
