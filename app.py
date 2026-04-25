#!/usr/bin/env python3
"""
AI Network Security Defense Dashboard
Flask web application — AEU Classroom Demo
Run:   python app.py
Open:  http://localhost:8888
"""

from flask import Flask, request, jsonify, render_template_string
import json, time, random, threading, os

import webbrowser

from datetime import datetime
from collections import deque

# ── Anthropic AI (optional) ──────────────────────────────────
try:
    from anthropic import Anthropic
    ai_client = Anthropic()
    AI_AVAILABLE = True
except Exception:
    ai_client = None
    AI_AVAILABLE = False

app = Flask(__name__)

# ── Attack Scenarios ─────────────────────────────────────────
ATTACKS = {
    'brute': {
        'label': 'Brute Force Login',
        'icon': 'BF',
        'src_ips': ['103.45.12.88', '198.71.33.201', '45.33.99.12', '176.10.55.23'],
        'events': [
            ('warning', 'Failed login — user: admin (attempt 1/5)'),
            ('warning', 'Failed login — user: root (attempt 2/5)'),
            ('warning', 'Failed login — user: administrator (attempt 3/5)'),
            ('info',    'AI: Analyzing login frequency pattern...'),
            ('warning', 'Login from new geolocation: CN — suspicious'),
            ('blocked', 'Rate limit exceeded — IP 103.45.12.88 blocked'),
            ('blocked', 'Credential stuffing pattern detected and blocked'),
            ('blocked', 'Account locked after 5 failed attempts'),
            ('info',    'Auth log saved. Incident report sent to SOC.'),
        ],
        'threat': 72, 'confidence': 92, 'anomaly': 68,
        'context': 'Simulated brute force: 47 failed login attempts in 12 seconds from 103.45.12.88 targeting admin/root/administrator. Sequential credential stuffing from known botnet range.'
    },
    'portscan': {
        'label': 'Port Scan',
        'icon': 'PS',
        'src_ips': ['185.220.101.45', '162.247.74.200', '185.100.87.33'],
        'events': [
            ('info',    'SYN packet to port 22 (SSH)'),
            ('info',    'SYN packet to port 80 (HTTP)'),
            ('info',    'SYN packet to port 443 (HTTPS)'),
            ('warning', 'Rapid sequential port probe detected'),
            ('info',    'SYN packet to port 3306 (MySQL)'),
            ('info',    'SYN packet to port 6379 (Redis)'),
            ('warning', 'SYN flood — 1,240 packets in 3 seconds'),
            ('blocked', 'Stealth scan fingerprint matched — IP blocked'),
            ('blocked', 'Nmap OS detection signatures blocked'),
        ],
        'threat': 65, 'confidence': 88, 'anomaly': 75,
        'context': 'Simulated port scan: 1,240 SYN packets in 3s across ports 1-65535 from 185.220.101.45. Nmap-style fingerprinting targeting DB ports 3306,5432,6379 and admin ports 22,8080.'
    },
    'ddos': {
        'label': 'DDoS Flood',
        'icon': 'DD',
        'src_ips': ['Botnet-C2', 'TOR-Exit', 'AS13335', 'AWS-Compromised'],
        'events': [
            ('warning', 'Traffic spike: 8,200 req/s (baseline: 120/s)'),
            ('warning', 'UDP flood from 1,400+ unique IPs detected'),
            ('blocked', 'SYN flood mitigated at edge firewall'),
            ('warning', 'BGP blackhole route engaged'),
            ('blocked', 'DNS amplification vector neutralized'),
            ('blocked', '2,100 botnet IPs rate-limited'),
            ('warning', 'CDN scrubbing center activated'),
            ('blocked', 'ICMP flood dropped at perimeter'),
            ('allowed', 'Legitimate traffic passed through (1.4%)'),
        ],
        'threat': 94, 'confidence': 89, 'anomaly': 85,
        'context': 'Simulated volumetric DDoS: 8,200 req/s from 1,400+ IPs. Mix of UDP flood, SYN flood and DNS amplification from botnet C2 networks. Legitimate traffic is 1.4% of total volume.'
    },
    'sqli': {
        'label': 'SQL Injection',
        'icon': 'SQ',
        'src_ips': ['91.234.99.12', '45.79.12.200'],
        'events': [
            ('warning', "Payload: GET /search?q=1' OR '1'='1'--"),
            ('blocked', 'SQL injection blocked: UNION SELECT payload'),
            ('warning', 'Time-based blind SQLi attempt detected'),
            ('blocked', 'Error-based SQLi payload neutralized'),
            ('warning', "Payload: '; DROP TABLE users; --"),
            ('blocked', 'WAF rule: sqlmap user-agent matched'),
            ('warning', 'Database error disclosure attempt'),
            ('blocked', 'Stacked query injection neutralized'),
            ('info',    'Incident report generated for SOC team'),
        ],
        'threat': 87, 'confidence': 96, 'anomaly': 79,
        'context': 'Simulated SQL injection: 34 malicious HTTP requests with UNION SELECT, OR 1=1--, time-based blind probes, and sqlmap targeting /search, /login, /api/data endpoints.'
    },
    'adversarial': {
        'label': 'Adversarial Attack',
        'icon': 'AD',
        'src_ips': ['172.33.45.11', '104.21.88.200'],
        'events': [
            ('warning', 'Evasion: fragmented packet stream detected'),
            ('warning', 'AI model probing with crafted inputs'),
            ('blocked', 'Adversarial payload fingerprint matched'),
            ('warning', 'Obfuscated shellcode in HTTP body'),
            ('blocked', 'Base64+ROT13 double-encoded payload blocked'),
            ('warning', 'Model poisoning attempt: /api/predict'),
            ('blocked', 'Anomalous request header manipulation blocked'),
            ('warning', 'GAN-generated traffic pattern identified'),
            ('info',    'Adversarial sample sent to sandbox'),
        ],
        'threat': 78, 'confidence': 83, 'anomaly': 91,
        'context': 'Simulated adversarial attack: crafted inputs to evade ML detection, fragmented packets to bypass DPI, multi-layer obfuscation, and probes to map AI model decision boundaries.'
    }
}

FALLBACK_AI = {
    'brute':       ('47 consecutive failed logins in 12 seconds from a single IP is statistically impossible for human behavior, matching known credential-stuffing botnet signatures. This attack directly threatens account integrity and could lead to unauthorized administrative access. Key indicators: 4 login attempts/sec, sequential username enumeration, identical password entropy, IP flagged in threat intelligence. Decision: Block source IP immediately and enforce MFA on all administrative accounts.', 'block'),
    'portscan':    ('The burst of 1,240 SYN packets in 3 seconds with no completed TCP handshakes is a classic stealth scan prioritizing database and admin ports, indicating pre-attack reconnaissance. If unchecked, the attacker gains a full map of exposed services for a follow-up exploit. Key indicators: SYN-only packets, sequential port ordering, low TTL values, Nmap OS fingerprint headers. Decision: Block source IP, alert SOC, and audit all exposed service banners immediately.', 'block'),
    'ddos':        ('Traffic at 68x the normal baseline from 1,400+ IPs with mixed UDP/SYN/ICMP vectors confirms a coordinated volumetric DDoS from botnet infrastructure. This can cause complete service unavailability for all legitimate users if not mitigated at the network edge. Key indicators: packet rate 8,200 req/s, DNS amplification factor ~40x, spoofed source IPs, BGP prefix anomaly. Decision: Block at upstream provider level and maintain scrubbing center activation until traffic normalizes.', 'block'),
    'sqli':        ('HTTP requests contain UNION SELECT for data exfiltration and DROP TABLE for destruction combined with sqlmap tooling fingerprints targeting three critical endpoints. A successful injection could expose the entire user database and enable persistent backdoor access. Key indicators: malicious GET/POST parameters, 34 injection vectors, WAF evasion patterns, automated sqlmap tooling. Decision: Block source IP, patch all input validation, and audit database access logs for prior compromise.', 'block'),
    'adversarial': ('Fragmented packets and multi-layer encoded payloads indicate an attacker mapping AI detection boundaries through adversarial probing, suggesting advanced threat actor tradecraft. This reconnaissance could enable future attacks that completely bypass the ML detection engine. Key indicators: unusual inter-packet timing, entropy anomalies in HTTP body, model confidence oscillation, GAN-generated traffic signatures. Decision: Monitor and feed all captured samples into the adversarial retraining pipeline to harden the model.', 'monitor'),
}

# ── Shared State (polling-based) ─────────────────────────────
state_lock = threading.Lock()
state = {
    'packets': 0, 'blocked': 0, 'allowed': 0,
    'alerts': 0, 'threat_score': 0, 'running': False,
    'status': 'MONITORING',
}
# Ring buffer of log events — frontend polls and reads by index
event_log = deque(maxlen=500)
event_index = 0   # global monotonic counter


def push_event(evt: dict):
    """Add event to the shared log buffer."""
    global event_index
    with state_lock:
        evt['id'] = event_index
        event_index += 1
        event_log.append(evt)


def push_log(cls, msg, src):
    push_event({
        'type': 'log',
        'time': datetime.now().strftime('%H:%M:%S'),
        'src': src, 'msg': msg, 'cls': cls
    })


def push_stats():
    with state_lock:
        snap = dict(state)
    push_event({'type': 'stats', **snap})


# ── Background normal traffic ─────────────────────────────────
def background_traffic():
    msgs = [
        'HTTP GET /index.html → 200 OK',
        'DNS query resolved successfully',
        'TLS 1.3 handshake complete',
        'Keep-alive connection maintained',
        'HTTPS GET /api/health → 200 OK',
        'NTP sync successful',
        'TCP session established normally',
        'HTTPS POST /api/login → 200 OK',
    ]
    while True:
        time.sleep(2.5)
        with state_lock:
            running = state['running']
        if not running:
            with state_lock:
                state['packets'] += random.randint(3, 10)
                state['allowed'] += random.randint(1, 3)
            push_log('info', random.choice(msgs),
                     f"192.168.1.{random.randint(10, 254)}")
            push_stats()


threading.Thread(target=background_traffic, daemon=True).start()

# ── Flask Routes ──────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, attacks=ATTACKS, ai_available=AI_AVAILABLE)


@app.route('/events')
def events():
    """Polling endpoint — returns all events since <since> index."""
    since = int(request.args.get('since', 0))
    with state_lock:
        snap = dict(state)
        new_events = [e for e in event_log if e.get('id', 0) >= since]
    return jsonify({
        'events': new_events,
        'state': snap,
        'next_id': event_index
    })


@app.route('/run-test', methods=['POST'])
def run_test():
    attack_type = request.json.get('type')
    if attack_type not in ATTACKS:
        return jsonify({'error': 'Invalid attack type'}), 400
    with state_lock:
        if state['running']:
            return jsonify({'error': 'Test already running'}), 400

    def _run():
        with state_lock:
            state['running'] = True
            state['status'] = 'UNDER ATTACK'
        atk = ATTACKS[attack_type]
        push_event({'type': 'attack_start', 'label': atk['label']})

        for cls, msg in atk['events']:
            time.sleep(0.75)
            with state_lock:
                state['packets'] += random.randint(10, 60)
                if cls == 'blocked':
                    state['blocked'] += 1
                    state['alerts']  += 1
                elif cls == 'allowed':
                    state['allowed'] += 1
                elif cls == 'warning':
                    state['alerts'] += 1
                state['threat_score'] = min(95, state['alerts'] * 7)
            push_log(cls, msg, random.choice(atk['src_ips']))
            push_stats()

        push_event({
            'type': 'attack_end',
            'threat': atk['threat'],
            'confidence': atk['confidence'],
            'anomaly': atk['anomaly']
        })
        with state_lock:
            state['running'] = False
            state['status'] = 'MONITORING'

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'status': 'started'})


@app.route('/ai-analyze', methods=['POST'])
def ai_analyze():
    attack_type = request.json.get('type')
    if attack_type not in ATTACKS:
        return jsonify({'error': 'Invalid attack type'}), 400
    atk = ATTACKS[attack_type]

    if not AI_AVAILABLE:
        text, decision = FALLBACK_AI.get(attack_type, ('Analysis unavailable.', 'monitor'))
        return jsonify({'analysis': text, 'decision': decision})

    prompt = (
        f"You are an AI network security analyst. Analyze this event in exactly 4 sentences:\n\n"
        f"Attack: {atk['label']}\nContext: {atk['context']}\n"
        f"Threat: {atk['threat']}% | Confidence: {atk['confidence']}% | Anomaly: {atk['anomaly']}%\n\n"
        f"Sentence 1: What the AI detected and why it's suspicious.\n"
        f"Sentence 2: Why this is dangerous if not stopped.\n"
        f"Sentence 3: The key behavioral indicators that triggered the alert.\n"
        f"Sentence 4: Start with 'Decision: BLOCK', 'Decision: MONITOR', or 'Decision: ALLOW' then explain.\n\n"
        f"No bullet points, no headers, just 4 clear sentences."
    )
    try:
        resp = ai_client.messages.create(
            model='claude-opus-4-5', max_tokens=350,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text
        lower = text.lower()
        if 'decision: block' in lower:     decision = 'block'
        elif 'decision: monitor' in lower: decision = 'monitor'
        else:                              decision = 'allow'
        return jsonify({'analysis': text, 'decision': decision})
    except Exception as e:
        text, decision = FALLBACK_AI.get(attack_type, (str(e), 'monitor'))
        return jsonify({'analysis': text, 'decision': decision})


# ── HTML Template ─────────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Security Defense Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --bdr:#30363d;--bdr2:#484f58;
  --tx:#e6edf3;--tx2:#8b949e;--tx3:#6e7681;
  --g:#3fb950;--gb:#0d2818;--gd:#1a3827;
  --r:#f85149;--rb:#2d1010;--rd:#3d1c1c;
  --y:#d29922;--yb:#271f07;--yd:#3d2e0a;
  --b:#388bfd;--bb:#0d1f33;--bd:#1c2d4a;
  --p:#8957e5;--pd:#2d1f4e;
  --t:#39d353;--td:#143820;
  --mono:'JetBrains Mono','Courier New',monospace;
  --sans:'Inter',sans-serif;
  --rad:6px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:var(--mono);font-size:13px;min-height:100vh}
.topbar{background:var(--bg2);border-bottom:1px solid var(--bdr);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.brand{display:flex;align-items:center;gap:12px}
.brand-logo{width:36px;height:36px;background:var(--gd);border:1px solid var(--g);border-radius:var(--rad);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:var(--g)}
.brand-name{font-size:15px;font-weight:600;color:var(--tx);font-family:var(--sans)}
.brand-sub{font-size:11px;color:var(--tx3);font-family:var(--sans)}
.badges{display:flex;align-items:center;gap:8px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:11px;font-weight:500;border:1px solid;font-family:var(--sans)}
.bg-g{background:var(--gb);color:var(--g);border-color:var(--gd)}
.bg-r{background:var(--rb);color:var(--r);border-color:var(--rd)}
.bg-gr{background:var(--bg3);color:var(--tx2);border-color:var(--bdr)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.main{padding:20px 24px;max-width:1440px;margin:0 auto}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.metric{background:var(--bg2);border:1px solid var(--bdr);border-radius:var(--rad);padding:14px 16px}
.ml{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--tx3);margin-bottom:6px;font-family:var(--sans)}
.mv{font-size:28px;font-weight:700;line-height:1;transition:color .3s}
.mbar{height:3px;background:var(--bg3);border-radius:2px;margin-top:8px;overflow:hidden}
.mbf{height:100%;border-radius:2px;transition:width .4s ease}
.cg{color:var(--g)}.cr{color:var(--r)}.cy{color:var(--y)}
.fg{background:var(--g)}.fr{background:var(--r)}.fy{background:var(--y)}.fp{background:var(--p)}
.grid{display:grid;grid-template-columns:235px 1fr 285px;gap:16px;margin-bottom:16px}
.panel{background:var(--bg2);border:1px solid var(--bdr);border-radius:var(--rad);overflow:hidden}
.ph{padding:10px 14px;border-bottom:1px solid var(--bdr);font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--tx2);display:flex;align-items:center;justify-content:space-between;font-family:var(--sans)}
.pb{padding:12px}
.ab{width:100%;text-align:left;padding:9px 11px;border:1px solid var(--bdr);border-radius:var(--rad);background:transparent;color:var(--tx2);cursor:pointer;margin-bottom:7px;font-family:var(--mono);font-size:12px;display:flex;align-items:center;gap:9px;transition:all .15s}
.ab:hover{background:var(--bg3);color:var(--tx);border-color:var(--bdr2)}
.ab.active{background:var(--bb);color:var(--b);border-color:var(--bd)}
.ico{width:24px;height:24px;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;flex-shrink:0}
.i-BF{background:var(--yd);color:var(--y)}.i-PS{background:var(--bd);color:var(--b)}
.i-DD{background:var(--rd);color:var(--r)}.i-SQ{background:var(--pd);color:var(--p)}
.i-AD{background:var(--td);color:var(--t)}
.rb{width:100%;padding:10px;border:1px solid var(--bdr2);border-radius:var(--rad);background:transparent;color:var(--tx);cursor:pointer;font-family:var(--mono);font-size:12px;margin-top:10px;transition:all .15s;font-weight:500}
.rb:hover:not(:disabled){background:var(--bb);border-color:var(--bd);color:var(--b)}
.rb:disabled{opacity:.4;cursor:default}
.rb.running{border-color:var(--yd);color:var(--y)}
.divhr{border:none;border-top:1px solid var(--bdr);margin:10px 0}
.lw{height:285px;overflow-y:auto}
.lw::-webkit-scrollbar{width:4px}
.lw::-webkit-scrollbar-thumb{background:var(--bdr2);border-radius:2px}
.lr{display:grid;grid-template-columns:62px 150px 1fr;gap:8px;padding:3px 0;border-bottom:1px solid #1a1f27;font-size:11.5px;line-height:1.5}
.lt{color:var(--tx3)}.ls{color:var(--b);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ci{color:var(--tx2)}.ca{color:var(--g)}.cw{color:var(--y)}.cb{color:var(--r);font-weight:500}
.brow{margin-bottom:10px}
.blab{display:flex;justify-content:space-between;font-size:10px;color:var(--tx2);margin-bottom:4px;font-family:var(--sans)}
.btrk{height:5px;background:var(--bg3);border-radius:3px;overflow:hidden}
.bf{height:100%;border-radius:3px;transition:width .5s ease;background:var(--g)}
.abox{background:var(--bg3);border:1px solid var(--bdr);border-radius:var(--rad);padding:10px 12px;min-height:110px;font-size:12px;line-height:1.75;color:var(--tx2)}
.abox.loading{color:var(--tx3);font-style:italic}
.dec{margin-top:10px;padding:9px 14px;border-radius:var(--rad);font-weight:600;text-align:center;font-size:12px;letter-spacing:.05em;font-family:var(--sans);display:none}
.db{background:var(--rb);color:var(--r);border:1px solid var(--rd)}
.dm{background:var(--yb);color:var(--y);border:1px solid var(--yd)}
.da{background:var(--gb);color:var(--g);border:1px solid var(--gd)}
.hist{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:10px}
.hc{background:var(--bg2);border:1px solid var(--bdr);border-radius:var(--rad);padding:10px 12px}
.ht{font-size:12px;font-weight:500;color:var(--tx);margin-bottom:5px}
.hres{font-size:11px;font-family:var(--sans)}
.hres.blocked{color:var(--r)}.hres.monitor{color:var(--y)}.hres.allowed{color:var(--g)}
.hs{font-size:10px;color:var(--tx3);margin-top:4px;font-family:var(--sans)}
.empty{color:var(--tx3);font-size:12px;font-family:var(--sans);grid-column:1/-1;padding:8px 0}
.stl{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--tx3);margin-bottom:8px;font-family:var(--sans)}
.spin{display:inline-block;width:10px;height:10px;border:1.5px solid var(--tx3);border-top-color:var(--y);border-radius:50%;animation:sp .8s linear infinite;margin-right:6px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
@media(max-width:1100px){.grid{grid-template-columns:210px 1fr}.grid>:last-child{grid-column:1/-1}}
@media(max-width:700px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.main{padding:12px}}
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <div class="brand-logo">AI</div>
    <div>
      <div class="brand-name">AI Security Defense Dashboard</div>
      <div class="brand-sub">Network Security &amp; AI Defense — AEU Demo</div>
    </div>
  </div>
  <div class="badges">
    <span class="badge bg-g" id="sys-status"><span class="dot"></span>&nbsp;MONITORING</span>
    <span class="badge bg-gr" id="pkt-badge">Packets: 0</span>
    <span class="badge {% if ai_available %}bg-g{% else %}bg-r{% endif %}">
      AI&nbsp;{% if ai_available %}Online{% else %}Offline{% endif %}
    </span>
  </div>
</div>

<div class="main">
  <div class="metrics">
    <div class="metric">
      <div class="ml">Threat Score</div>
      <div class="mv cg" id="m-threat">0%</div>
      <div class="mbar"><div class="mbf fg" id="mb-threat" style="width:0%"></div></div>
    </div>
    <div class="metric">
      <div class="ml">Blocked</div>
      <div class="mv cr" id="m-blocked">0</div>
      <div class="mbar"><div class="mbf fr" id="mb-blocked" style="width:0%"></div></div>
    </div>
    <div class="metric">
      <div class="ml">Allowed</div>
      <div class="mv cg" id="m-allowed">0</div>
      <div class="mbar"><div class="mbf fg" id="mb-allowed" style="width:0%"></div></div>
    </div>
    <div class="metric">
      <div class="ml">Alerts</div>
      <div class="mv cy" id="m-alerts">0</div>
      <div class="mbar"><div class="mbf fy" id="mb-alerts" style="width:0%"></div></div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="ph">Test Cases</div>
      <div class="pb">
        {% for key, atk in attacks.items() %}
        <button class="ab" id="btn-{{key}}" onclick="selectAttack('{{key}}',this)">
          <span class="ico i-{{atk.icon}}">{{atk.icon}}</span>{{atk.label}}
        </button>
        {% endfor %}
        <hr class="divhr">
        <button class="rb" id="run-btn" onclick="runTest()" disabled>Select a test case &#8629;</button>
      </div>
    </div>

    <div class="panel">
      <div class="ph">
        <span>Live Network Traffic Log</span>
        <span id="log-count" style="color:var(--tx3)">0 events</span>
      </div>
      <div class="pb" style="padding:8px 12px">
        <div class="lw" id="log-area"></div>
      </div>
    </div>

    <div class="panel">
      <div class="ph">AI Analysis (Explainable AI)</div>
      <div class="pb">
        <div style="margin-bottom:14px">
          <div class="brow">
            <div class="blab"><span>Threat Level</span><span id="v-thr">&#8212;</span></div>
            <div class="btrk"><div class="bf" id="b-thr" style="width:0%"></div></div>
          </div>
          <div class="brow">
            <div class="blab"><span>AI Confidence</span><span id="v-conf">&#8212;</span></div>
            <div class="btrk"><div class="bf fy" id="b-conf" style="width:0%"></div></div>
          </div>
          <div class="brow">
            <div class="blab"><span>Anomaly Score</span><span id="v-anom">&#8212;</span></div>
            <div class="btrk"><div class="bf fp" id="b-anom" style="width:0%"></div></div>
          </div>
        </div>
        <div class="stl">AI Reasoning</div>
        <div class="abox loading" id="ai-out">Select a test case and click Run to see AI reasoning...</div>
        <div class="dec" id="dec-box"></div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="ph">Detection History</div>
    <div class="pb">
      <div class="hist" id="history">
        <div class="empty">No tests run yet. Select a test case above to begin.</div>
      </div>
    </div>
  </div>
</div>

<script>
const ATTACKS = {{ attacks | tojson }};
let selected = null, running = false, logCount = 0, history = [];
let nextId = 0, maxB = 1, maxA = 1, maxAl = 1;

// ── Polling (replaces SSE) ────────────────────────────────────
function poll() {
  fetch('/events?since=' + nextId)
    .then(r => r.json())
    .then(data => {
      data.events.forEach(processEvent);
      if (data.next_id > nextId) nextId = data.next_id;
    })
    .catch(() => {})
    .finally(() => setTimeout(poll, 800));
}
poll();

function processEvent(d) {
  if (d.type === 'log')          addLog(d);
  else if (d.type === 'stats')   updateStats(d);
  else if (d.type === 'attack_start') onStart(d);
  else if (d.type === 'attack_end')   onEnd(d);
}

function addLog(d) {
  const area = document.getElementById('log-area');
  const row  = document.createElement('div');
  row.className = 'lr';
  const cls = d.cls === 'blocked' ? 'cb' : d.cls === 'warning' ? 'cw' : d.cls === 'allowed' ? 'ca' : 'ci';
  row.innerHTML = `<span class="lt">${d.time}</span><span class="ls">${d.src}</span><span class="lm ${cls}">${d.msg}</span>`;
  area.appendChild(row);
  area.scrollTop = area.scrollHeight;
  if (area.children.length > 400) area.removeChild(area.firstChild);
  document.getElementById('log-count').textContent = (++logCount) + ' events';
}

function updateStats(d) {
  document.getElementById('pkt-badge').textContent = 'Packets: ' + d.packets.toLocaleString();
  const t = d.threat_score;
  const tc = t < 30 ? 'g' : t < 65 ? 'y' : 'r';
  const te = document.getElementById('m-threat');
  te.textContent = t + '%'; te.className = 'mv c' + tc;
  const tb = document.getElementById('mb-threat');
  tb.style.width = t + '%'; tb.className = 'mbf f' + tc;
  document.getElementById('m-blocked').textContent = d.blocked;
  document.getElementById('m-allowed').textContent = d.allowed;
  document.getElementById('m-alerts').textContent  = d.alerts;
  maxB  = Math.max(maxB,  d.blocked || 1);
  maxA  = Math.max(maxA,  d.allowed || 1);
  maxAl = Math.max(maxAl, d.alerts  || 1);
  document.getElementById('mb-blocked').style.width = Math.min(100, d.blocked/maxB*100)  + '%';
  document.getElementById('mb-allowed').style.width = Math.min(100, d.allowed/maxA*100)  + '%';
  document.getElementById('mb-alerts').style.width  = Math.min(100, d.alerts /maxAl*100) + '%';
}

function onStart(d) {
  running = true;
  const btn = document.getElementById('run-btn');
  btn.innerHTML = '<span class="spin"></span>Running: ' + d.label;
  btn.className = 'rb running'; btn.disabled = true;
  setStatus('r', 'UNDER ATTACK');
  const out = document.getElementById('ai-out');
  out.className = 'abox loading';
  out.textContent = 'AI engine processing traffic patterns...';
  document.getElementById('dec-box').style.display = 'none';
  resetBars();
}

function onEnd(d) {
  setBar('b-thr',  d.threat,      d.threat > 70 ? 'fr' : d.threat > 40 ? 'fy' : 'fg');
  document.getElementById('v-thr').textContent  = d.threat + '%';
  setBar('b-conf', d.confidence, 'fy');
  document.getElementById('v-conf').textContent = d.confidence + '%';
  setBar('b-anom', d.anomaly,    'fp');
  document.getElementById('v-anom').textContent = d.anomaly + '%';

  fetch('/ai-analyze', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({type: selected})
  })
  .then(r => r.json())
  .then(r => {
    const out = document.getElementById('ai-out');
    out.className = 'abox'; out.textContent = r.analysis;
    const dec = document.getElementById('dec-box');
    const labels = {block:'⛔  BLOCK — Threat Confirmed', monitor:'◈  MONITOR — Elevated Vigilance', allow:'✓  ALLOW — No Threat Detected'};
    const cls   = {block:'dec db', monitor:'dec dm', allow:'dec da'};
    dec.textContent = labels[r.decision] || labels.monitor;
    dec.className   = cls[r.decision]   || cls.monitor;
    dec.style.display = 'block';
    history.unshift({type: ATTACKS[selected].label, result: r.decision, threat: d.threat});
    renderHistory();
  })
  .catch(err => { document.getElementById('ai-out').textContent = 'Error: ' + err.message; });

  running = false;
  const btn = document.getElementById('run-btn');
  btn.innerHTML = '&#9654;  Run Analysis &#8212; ' + ATTACKS[selected].label;
  btn.className = 'rb'; btn.disabled = false;
  setStatus('g', 'MONITORING');
}

function setBar(id, pct, cls) {
  const el = document.getElementById(id);
  el.style.width = pct + '%'; el.className = 'bf ' + cls;
}
function resetBars() {
  ['b-thr','b-conf','b-anom'].forEach(id => document.getElementById(id).style.width = '0%');
  ['v-thr','v-conf','v-anom'].forEach(id => document.getElementById(id).textContent = '\u2014');
}
function setStatus(color, text) {
  const el = document.getElementById('sys-status');
  el.className = 'badge bg-' + color;
  el.innerHTML = '<span class="dot"></span>&nbsp;' + text;
}
function selectAttack(type, btn) {
  document.querySelectorAll('.ab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  selected = type;
  const rb = document.getElementById('run-btn');
  rb.disabled = false;
  rb.innerHTML = '&#9654;  Run Analysis &#8212; ' + ATTACKS[type].label;
  const out = document.getElementById('ai-out');
  out.className = 'abox loading';
  out.textContent = 'Ready: ' + ATTACKS[type].label + '. Click Run Analysis to start.';
  document.getElementById('dec-box').style.display = 'none';
  resetBars();
}
function runTest() {
  if (!selected || running) return;
  fetch('/run-test', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({type: selected})
  }).catch(console.error);
}
function renderHistory() {
  const grid = document.getElementById('history');
  if (!history.length) { grid.innerHTML = '<div class="empty">No tests run yet.</div>'; return; }
  const icons  = {block:'⛔', monitor:'◈', allow:'✓'};
  const labels = {block:'BLOCKED', monitor:'MONITORING', allow:'ALLOWED'};
  grid.innerHTML = history.slice(0,10).map(h =>
    `<div class="hc">
      <div class="ht">${h.type}</div>
      <div class="hres ${h.result==='block'?'blocked':h.result==='monitor'?'monitor':'allowed'}">
        ${icons[h.result]||'◈'} ${labels[h.result]||'MONITORING'}
      </div>
      <div class="hs">Threat Score: ${h.threat}%</div>
    </div>`
  ).join('');
}
</script>
</body>
</html>"""

# ── Entry Point ───────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8888))
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║      AI Security Defense Dashboard — AEU Demo       ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  Open browser:  http://localhost:{port}                 ║")
    ai_stat = 'ONLINE (Anthropic API)' if AI_AVAILABLE else 'OFFLINE — set ANTHROPIC_API_KEY'
    print(f"║  AI Analysis:   {ai_stat:<37}║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Test Cases:  Brute Force  |  Port Scan  |  DDoS     ║")
    print("║               SQL Injection  |  Adversarial Attack    ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    def _auto_open_browser():
        url = f"http://127.0.0.1:{port}"
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass

    if os.environ.get('AUTO_OPEN_BROWSER', '1').strip().lower() not in {'0', 'false', 'no', 'off'}:
        threading.Timer(1.0, _auto_open_browser).start()

    app.run(debug=False, threaded=True, host='0.0.0.0', port=port)

