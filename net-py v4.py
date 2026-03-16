"""
Net-PY — combined single-file network monitor.
  1. Flask web server  → http://0.0.0.0:5000/
  2. ARP packet sniffer (scapy) — live on-host detection
  3. Syslog UDP listener (port 514) — receives DAI drops from switches

Usage:
    sudo python netpy.py
"""

import json, os, re, socket, ipaddress, threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string

# ── Config ────────────────────────────────────────────────────────────────────

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "events.json")

SUBNET = ipaddress.ip_network("192.168.1.0/24")

TRUSTED_BINDINGS = {
    "192.168.1.254": "50:95:51:93:A2:C0",
    "192.168.1.119": "A8:A1:59:60:49:23",
}

SYSLOG_PORT = 514
FLASK_PORT  = 5000
MAX_EVENTS  = 500
MAX_ALERTS  = 200

# ── Shared state ──────────────────────────────────────────────────────────────

_lock         = threading.Lock()
known_devices = {}   # mac → {ip, first_seen, last_seen}
seen_ip_mac   = {}   # ip  → mac
events        = []
alerts        = []

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_full():  return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def now_short(): return datetime.now().strftime("%H:%M:%S")
def norm_mac(mac): return mac.upper().strip()
def in_subnet(ip):
    try:    return ipaddress.ip_address(ip) in SUBNET
    except: return False

# ── Persistence ───────────────────────────────────────────────────────────────

def load_data():
    global known_devices, seen_ip_mac, events, alerts
    if not os.path.exists(DATA_FILE):
        print("[INIT] No previous data — starting fresh.")
        return
    try:
        with open(DATA_FILE, encoding="utf-8") as f:
            data = json.load(f)
        with _lock:
            for d in data.get("devices", []):
                mac = norm_mac(d["mac"])
                ip  = d.get("ip", "Unknown")
                known_devices[mac] = {
                    "ip": ip,
                    "first_seen": d.get("first_seen", now_full()),
                    "last_seen":  d.get("last_seen",  now_full()),
                }
                if ip not in ("0.0.0.0", "Unknown"):
                    seen_ip_mac[ip] = mac
            events = data.get("events", [])
            alerts = data.get("alerts", [])
        print(f"[INIT] Loaded {len(known_devices)} devices, {len(events)} events, {len(alerts)} alerts.")
    except Exception as e:
        print(f"[INIT] Failed to load data: {e}")


def save_data():
    """Serialise state to disk. Must be called with _lock held."""
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    payload = {
        "updated": now_full(),
        "trusted_bindings": [{"ip": ip, "mac": mac} for ip, mac in TRUSTED_BINDINGS.items()],
        "devices": [{"mac": m, **info} for m, info in known_devices.items()],
        "alerts":  alerts[-MAX_ALERTS:],
        "events":  events[-MAX_EVENTS:],
    }
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

# ── Core logic ────────────────────────────────────────────────────────────────

def _add_event(port, ip, mac, reason):
    events.append({"time": now_short(), "port": port, "senderIp": ip, "senderMac": mac, "reason": reason})
    print(f"[EVENT] {ip} {mac} — {reason}")

def _add_alert(kind, ip, mac, message):
    alerts.append({"time": now_short(), "type": kind, "ip": ip, "mac": mac, "message": message})
    print(f"[ALERT] {message} | {ip} {mac}")


def update_device(ip, mac, port="LIVE"):
    mac = norm_mac(mac)
    with _lock:
        now = now_full()

        # Trusted-binding conflict checks
        if ip in TRUSTED_BINDINGS and norm_mac(TRUSTED_BINDINGS[ip]) != mac:
            _add_event(port, ip, mac, f"BLOCKED — IP spoof of trusted {ip} (expected {norm_mac(TRUSTED_BINDINGS[ip])})")
            save_data(); return

        trusted_ip = next((p for p, m in TRUSTED_BINDINGS.items() if norm_mac(m) == mac and p != ip), None)
        if trusted_ip:
            _add_event(port, ip, mac, f"BLOCKED — trusted MAC misuse (expected IP {trusted_ip})")
            save_data(); return

        # New or known device
        if mac not in known_devices:
            known_devices[mac] = {"ip": ip, "first_seen": now, "last_seen": now}
            _add_alert("new_device", ip, mac, "New device connected")
        else:
            old_ip = known_devices[mac]["ip"]
            known_devices[mac].update({"ip": ip, "last_seen": now})
            if old_ip != ip and ip not in ("0.0.0.0", "Unknown"):
                _add_event(port, ip, mac, f"Device changed IP from {old_ip} to {ip}")

        if ip == "0.0.0.0":
            _add_event(port, ip, mac, "ARP probe (pre-DHCP)")
        elif not in_subnet(ip):
            _add_event(port, ip, mac, "Subnet mismatch")

        if ip in seen_ip_mac and seen_ip_mac[ip] != mac:
            _add_event(port, ip, mac, f"Duplicate IP — previously seen with {seen_ip_mac[ip]}")

        seen_ip_mac[ip] = mac
        save_data()

# ── ARP sniffer ───────────────────────────────────────────────────────────────

def start_arp_sniffer():
    try:
        from scapy.all import sniff, ARP
        print("[SNIFFER] Starting ARP sniffer...")
        def handle(pkt):
            try:
                if ARP in pkt:
                    update_device(pkt[ARP].psrc, pkt[ARP].hwsrc, "LIVE")
            except Exception as e:
                print(f"[SNIFFER] Error: {e}")
        sniff(prn=handle, store=False, filter="arp")
    except ImportError:
        print("[SNIFFER] scapy not installed — ARP sniffing disabled.")
    except Exception as e:
        print(f"[SNIFFER] Failed to start: {e}")

# ── Syslog listener ───────────────────────────────────────────────────────────

_HEADER_RE = re.compile(
    r"^<\d+>\s+\w+\s+\d+\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+\S+:\s+\S+\s+\d+\s+%%\s+(?P<severity>\w+)\s+(?P<body>.+)$"
)
_DROP_RE  = re.compile(r"DAI dropped ARP frame rcvd on i/f (?P<port>\S+) in vlan (?P<vlan>\d+), due to - (?P<reason>.+)$")
_ETH_RE   = re.compile(r"Ethernet header-\s*dest (?P<dest>[0-9A-Fa-f:]{17}),\s*src (?P<src>[0-9A-Fa-f:]{17}),\s*type/len (?P<type>0x[0-9A-Fa-f]+)")
_ARP_RE   = re.compile(r"ARP PKT-\s*op (?P<op>\w+),\s*sender mac (?P<smac>[0-9A-Fa-f:]{17}),\s*sender ip (?P<sip>[\d.]+),\s*target mac (?P<tmac>[0-9A-Fa-f:]{17}),\s*target ip (?P<tip>[\d.]+)")
_LINK_RE  = re.compile(r"Link (?P<state>Down|Up):\s*(?P<port>\S+)")

_pending: dict = {}


def _likely_cause(sender_ip, reason):
    if sender_ip == "0.0.0.0":
        return "Pre-DHCP ARP probe or missing DHCP snooping binding"
    if "DHCP SNOOP DB MATCH FAILURE" in (reason or "").upper():
        return "IP/MAC not found in DHCP snooping table — possibly static IP"
    return "Potential ARP validation failure"


def _finalize_dai_event(key):
    ev = _pending.pop(key, None)
    if not ev:
        return
    defaults = {"time": now_short(), "port": "Unknown", "vlan": "Unknown",
                "senderMac": "Unknown", "senderIp": "Unknown",
                "targetMac": "Unknown", "targetIp": "Unknown",
                "reason": "Unknown", "severity": "WARN", "type": "DAI_DROP"}
    for k, v in defaults.items():
        ev.setdefault(k, v)
    ev["likelyCause"] = _likely_cause(ev["senderIp"], ev["reason"])

    if ev["senderMac"] not in ("Unknown", ""):
        update_device(ev["senderIp"], ev["senderMac"], port=ev.get("port", "SYSLOG"))
    else:
        with _lock:
            events.append(ev)
            save_data()
    print("[DAI]", json.dumps(ev))


def process_syslog_line(message):
    message = message.strip()
    if not message:
        return
    hm = _HEADER_RE.match(message)
    if not hm:
        print("[SYSLOG] No header match:", message[:120])
        return

    log_time, host, severity, body = hm.group("time"), hm.group("host"), hm.group("severity"), hm.group("body")

    dm = _DROP_RE.search(body)
    if dm:
        key = f"{host}|{log_time}||{dm.group('port')}"
        _pending[key] = {"time": log_time, "switch": host, "port": dm.group("port"),
                         "vlan": dm.group("vlan"), "reason": dm.group("reason").strip(),
                         "severity": severity, "type": "DAI_DROP"}
        return

    em = _ETH_RE.search(body)
    if em:
        for key in list(_pending):
            if key.startswith(f"{host}|{log_time}|"):
                _pending[key].update({"senderMac": em.group("src").upper(),
                                      "destMac": em.group("dest").upper(),
                                      "ethType": em.group("type")})
                break
        return

    am = _ARP_RE.search(body)
    if am:
        smac = am.group("smac").upper()
        for key in list(_pending):
            ev = _pending.get(key, {})
            if key.startswith(f"{host}|{log_time}|") and ev.get("senderMac", "") in ("", "Unknown", smac):
                ev.update({"senderMac": smac, "senderIp": am.group("sip"),
                            "targetMac": am.group("tmac").upper(),
                            "targetIp": am.group("tip"), "arpOp": am.group("op")})
                _finalize_dai_event(key)
                break
        return

    lm = _LINK_RE.search(body)
    if lm:
        with _lock:
            events.append({"time": log_time, "port": lm.group("port"),
                           "senderIp": "-", "senderMac": "-",
                           "reason": f"Link {lm.group('state')} on {lm.group('port')} (switch {host})",
                           "type": f"LINK_{lm.group('state').upper()}"})
            save_data()


def start_syslog_listener():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", SYSLOG_PORT))
        print(f"[SYSLOG] Listening on 0.0.0.0:{SYSLOG_PORT} ...")
        while True:
            data, addr = sock.recvfrom(4096)
            line = data.decode(errors="ignore").strip()
            print(f"[SYSLOG] From {addr[0]}: {line}")
            process_syslog_line(line)
    except PermissionError:
        print("[SYSLOG] Permission denied on port 514 — run as root.")
    except Exception as e:
        print(f"[SYSLOG] Error: {e}")

# ── Flask ─────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Net-PY Dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--danger:#da3633;}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial;}
.container{max-width:1200px;margin:auto;padding:25px;}
h1{margin-top:0;}
.hero{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;}
.badge{border:1px solid var(--border);padding:10px;border-radius:8px;background:var(--panel);}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:20px;}
.stat{background:var(--panel);border:1px solid var(--border);padding:20px;border-radius:10px;}
.stat .label{color:var(--muted);font-size:14px;}
.stat .value{font-size:26px;font-weight:bold;}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:15px;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:15px;}
.span12{grid-column:span 12;}.span8{grid-column:span 8;}.span4{grid-column:span 4;}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px;}
.table-wrap.scrollable{max-height:320px;overflow-y:auto;}
table{width:100%;border-collapse:collapse;}
th,td{padding:10px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap;}
th{color:var(--muted);position:sticky;top:0;background:var(--panel);z-index:1;}
td.reason{white-space:normal;word-break:break-word;min-width:180px;max-width:320px;}
tr:last-child td{border-bottom:none;}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.card-header h2{margin:0;}
.btn{background:var(--danger);color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:13px;}
.btn:hover{opacity:0.8;}
.log{background:#0b0f14;border:1px solid var(--border);border-radius:8px;padding:10px;font-family:monospace;max-height:300px;overflow:auto;white-space:pre-wrap;}
.muted{color:var(--muted);}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <div><h1>Net-PY Network Monitor</h1><p class="muted">ARP monitoring and network device detection dashboard</p></div>
    <div class="badge" id="lastUpdated">Updated: --</div>
  </div>
  <section class="stats">
    <div class="stat"><div class="label">Trusted Bindings</div><div class="value" id="bindingCount">0</div></div>
    <div class="stat"><div class="label">Known Devices</div><div class="value" id="deviceCount">0</div></div>
    <div class="stat"><div class="label">Alerts</div><div class="value" id="alertCount">0</div></div>
    <div class="stat"><div class="label">Events</div><div class="value" id="dropCount">0</div></div>
  </section>
  <div class="grid">
    <section class="card span4">
      <h2>Trusted Bindings</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>MAC</th></tr></thead>
        <tbody id="bindingsBody"></tbody>
      </table></div>
    </section>
    <section class="card span8">
      <div class="card-header"><h2>Dropped / Suspicious Events</h2></div>
      <div class="table-wrap scrollable"><table>
        <thead><tr><th>Time</th><th>Port</th><th>IP</th><th>MAC</th><th>Reason</th></tr></thead>
        <tbody id="eventsBody"></tbody>
      </table></div>
    </section>
    <section class="card span12">
      <div class="card-header">
        <h2>New Device Alerts</h2>
        <button class="btn" onclick="clearAlerts()">Clear Alerts</button>
      </div>
      <div class="table-wrap scrollable"><table>
        <thead><tr><th>Time</th><th>Type</th><th>IP</th><th>MAC</th><th>Message</th></tr></thead>
        <tbody id="alertsBody"></tbody>
      </table></div>
    </section>
    <section class="card span12">
      <h2>Known Devices</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>MAC</th><th>First Seen</th><th>Last Seen</th></tr></thead>
        <tbody id="devicesBody"></tbody>
      </table></div>
    </section>
    <section class="card span12">
      <h2>Event Log</h2>
      <div class="log" id="logBox">Loading...</div>
    </section>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
const row = cells => `<tr>${cells.map(c=>`<td>${c}</td>`).join("")}</tr>`;
const empty = (cols, msg) => `<tr><td colspan="${cols}" class="muted">${msg}</td></tr>`;

function renderBindings(bs){
  $("bindingCount").textContent = bs.length;
  $("bindingsBody").innerHTML = bs.length ? bs.map(b=>row([b.ip,b.mac])).join("") : empty(2,"No trusted bindings");
}
function renderDevices(ds){
  $("deviceCount").textContent = ds.length;
  $("devicesBody").innerHTML = ds.length ? ds.map(d=>row([d.ip,d.mac,d.first_seen,d.last_seen])).join("") : empty(4,"No devices seen");
}
function renderAlerts(as){
  $("alertCount").textContent = as.length;
  $("alertsBody").innerHTML = as.length ? as.map(a=>row([a.time,a.type,a.ip,a.mac,a.message])).join("") : empty(5,"No alerts");
}
function renderEvents(es){
  $("dropCount").textContent = es.length;
  $("eventsBody").innerHTML = es.length
    ? es.map(e=>`<tr><td>${e.time||"-"}</td><td>${e.port||"-"}</td><td>${e.senderIp||"-"}</td><td>${e.senderMac||"-"}</td><td class="reason">${e.reason||"-"}</td></tr>`).join("")
    : empty(5,"No events");
}
function renderLog(es){
  $("logBox").textContent = es.length ? es.map((e,i)=>`[${i+1}] ${e.time} | ${e.port} | ${e.senderIp} (${e.senderMac}) | ${e.reason}`).join("\n") : "No events";
}
async function clearAlerts(){
  try { await fetch("/api/clear-alerts",{method:"POST"}); await loadDashboard(); }
  catch(e){ alert("Failed to clear alerts: "+e); }
}
async function loadDashboard(){
  try {
    const d = await fetch("/api/events").then(r=>r.json());
    renderBindings(d.trusted_bindings||[]);
    renderDevices(d.devices||[]);
    renderAlerts(d.alerts||[]);
    renderEvents(d.events||[]);
    renderLog(d.events||[]);
    $("lastUpdated").textContent = "Updated: "+(d.updated||"--");
  } catch(e){ $("logBox").textContent = "Error loading data: "+e; }
}
loadDashboard();
setInterval(loadDashboard, 10000);
</script>
</body>
</html>"""

app = Flask(__name__)

@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/api/clear-alerts", methods=["POST"])
def api_clear_alerts():
    global alerts
    with _lock:
        alerts = []
        save_data()
    print("[API] Alerts cleared")
    return jsonify({"status": "ok"})

@app.route("/api/events")
def api_events():
    with _lock:
        devices_list = [{"mac": m, **info} for m, info in known_devices.items()]
        payload = {
            "updated": now_full(),
            "trusted_bindings": [{"ip": ip, "mac": mac} for ip, mac in TRUSTED_BINDINGS.items()],
            "devices": devices_list,
            "alerts":  list(alerts[-MAX_ALERTS:]),
            "events":  list(events[-MAX_EVENTS:]),
        }
    print(f"[API] {len(devices_list)} devices | {len(payload['alerts'])} alerts | {len(payload['events'])} events")
    return jsonify(payload)

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    load_data()
    threading.Thread(target=start_arp_sniffer,     daemon=True).start()
    threading.Thread(target=start_syslog_listener, daemon=True).start()
    print(f"[WEB] Dashboard → http://0.0.0.0:{FLASK_PORT}/")
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, use_reloader=False)
