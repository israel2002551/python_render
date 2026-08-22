"""Render-ready MQTT receiver for encrypted ESP32 FHIR observations."""

import json
import os
import threading
from collections import deque
from datetime import datetime, timezone

from Crypto.Cipher import AES
from flask import Flask, Response, jsonify
import paho.mqtt.client as mqtt


BROKER = os.getenv("MQTT_BROKER", "broker.hivemq.com")
PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPIC = os.getenv("MQTT_TOPIC", "health/fhir")
CLIENT_ID = os.getenv("MQTT_CLIENT_ID", "health-dashboard-render")
MAX_POINTS = int(os.getenv("MAX_POINTS", "120"))


def load_aes_key() -> bytes:
    key_hex = os.getenv("AES_KEY_HEX", "").strip()
    if len(key_hex) != 32:
        raise RuntimeError("AES_KEY_HEX must contain exactly 32 hexadecimal characters")
    try:
        return bytes.fromhex(key_hex)
    except ValueError as exc:
        raise RuntimeError("AES_KEY_HEX is not valid hexadecimal") from exc


AES_KEY = load_aes_key()
app = Flask(__name__)
state_lock = threading.Lock()
latest = {"updated_at": None, "vitals": {}, "messages_received": 0, "last_error": None}
history = deque(maxlen=MAX_POINTS)

LOINC_FIELDS = {
    "8867-4": "heart_rate_bpm",
    "8480-6": "systolic_bp_mmhg",
    "8462-4": "diastolic_bp_mmhg",
    "59408-5": "spo2_percent",
    "8310-5": "temperature_c",
    "9279-1": "respiratory_rate_bpm",
    "X-PTT": "ptt_ms",
}


def decrypt_gcm_hex(payload: str) -> str:
    if len(payload) < 56 or len(payload) % 2:
        raise ValueError("invalid encrypted payload length")
    nonce = bytes.fromhex(payload[:24])
    ciphertext = bytes.fromhex(payload[24:-32])
    tag = bytes.fromhex(payload[-32:])
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def extract_vitals(bundle: dict) -> dict:
    if bundle.get("resourceType") != "Bundle":
        raise ValueError("FHIR payload is not a Bundle")

    vitals = {}
    for entry in bundle.get("entry", []):
        resource = entry.get("resource", {})
        coding = resource.get("code", {}).get("coding", [])
        if not coding:
            continue
        field = LOINC_FIELDS.get(coding[0].get("code"))
        value = resource.get("valueQuantity", {}).get("value")
        if field and isinstance(value, (int, float)):
            vitals[field] = value
    return vitals


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        client.subscribe(TOPIC, qos=1)
        app.logger.info("Subscribed to MQTT topic %s", TOPIC)
    else:
        app.logger.error("MQTT connection failed: %s", reason_code)


def on_message(client, userdata, message):
    try:
        bundle = json.loads(decrypt_gcm_hex(message.payload.decode("utf-8")))
        sample = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "vitals": extract_vitals(bundle),
        }
        with state_lock:
            latest.update(sample)
            latest["messages_received"] += 1
            latest["last_error"] = None
            history.append(sample)
    except Exception as exc:  # Keep the MQTT loop alive after malformed public-topic traffic.
        app.logger.warning("Rejected MQTT message: %s", exc)
        with state_lock:
            latest["last_error"] = str(exc)


def create_mqtt_client():
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=CLIENT_ID)
    except AttributeError:
        client = mqtt.Client(client_id=CLIENT_ID)
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect_async(BROKER, PORT, keepalive=60)
    client.loop_start()
    return client


mqtt_client = create_mqtt_client()


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "mqtt_connected": mqtt_client.is_connected()})


@app.get("/api/v1/vitals")
def get_vitals():
    with state_lock:
        return jsonify(dict(latest))


@app.get("/api/v1/history")
def get_history():
    with state_lock:
        return jsonify(list(history))


@app.get("/")
def index():
    return Response("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Health Monitor</title><style>
*{box-sizing:border-box}body{margin:0;background:#07111f;color:#e5edf8;font-family:Arial,sans-serif}
main{max-width:1050px;margin:auto;padding:32px 20px}header{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:28px}
h1{margin:0;font-size:1.7rem}.sub{color:#9fb0c8;margin-top:7px}.state{padding:8px 12px;border-radius:20px;background:#182a42;color:#b7caff;font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.card{background:#101e31;border:1px solid #243a57;border-radius:14px;padding:18px}
.label{color:#9fb0c8;font-size:.85rem}.value{font-size:2rem;font-weight:700;margin-top:8px}.unit{font-size:.9rem;color:#9fb0c8;margin-left:4px}
section{margin-top:28px;background:#101e31;border:1px solid #243a57;border-radius:14px;padding:18px}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:10px;border-bottom:1px solid #243a57}th{color:#9fb0c8}.empty{color:#9fb0c8}
.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:16px}.chart{background:#0b1727;border:1px solid #243a57;border-radius:10px;padding:12px}.chart-title{font-size:.9rem;color:#b7caff;margin:0 0 8px}.chart canvas{display:block;width:100%;height:190px}
</style></head><body><main><header><div><h1>ESP32 Health Monitor</h1><div class="sub">Encrypted FHIR telemetry</div></div><div class="state" id="state">Connecting…</div></header>
<div class="grid" id="cards"></div><section><h2>Recent samples</h2><div id="recent" class="empty">Waiting for readings from the ESP32…</div></section></main>
<section><h2>Live trends</h2><div class="chart-grid">
<div class="chart"><p class="chart-title">Heart rate</p><canvas data-key="heart_rate_bpm" data-color="#ff6b6b"></canvas></div>
<div class="chart"><p class="chart-title">Blood oxygen (SpO₂)</p><canvas data-key="spo2_percent" data-color="#43d9a3"></canvas></div>
<div class="chart"><p class="chart-title">Temperature</p><canvas data-key="temperature_c" data-color="#bc7cff"></canvas></div>
<div class="chart"><p class="chart-title">Respiratory rate</p><canvas data-key="respiratory_rate_bpm" data-color="#ffd166"></canvas></div>
</div></section>
<script>
const fields=[['heart_rate_bpm','Heart rate','bpm'],['systolic_bp_mmhg','Systolic BP','mmHg'],['diastolic_bp_mmhg','Diastolic BP','mmHg'],['spo2_percent','SpO₂','%'],['temperature_c','Temperature','°C'],['respiratory_rate_bpm','Respiratory rate','breaths/min'],['ptt_ms','PTT','ms']];
const cards=document.querySelector('#cards'); cards.innerHTML=fields.map(([key,label,unit])=>`<div class="card"><div class="label">${label}</div><div class="value" id="${key}">--<span class="unit">${unit}</span></div></div>`).join('');
function show(v){return Number.isFinite(v)?(Math.round(v*10)/10):'--'}
function drawChart(canvas,samples){const values=samples.map(s=>s.vitals[canvas.dataset.key]).filter(Number.isFinite);const ctx=canvas.getContext('2d'),ratio=devicePixelRatio||1,w=canvas.clientWidth,h=canvas.clientHeight;canvas.width=w*ratio;canvas.height=h*ratio;ctx.scale(ratio,ratio);ctx.clearRect(0,0,w,h);if(!values.length){ctx.fillStyle='#9fb0c8';ctx.font='14px Arial';ctx.fillText('Waiting for data',14,32);return}let lo=Math.min(...values),hi=Math.max(...values),pad=Math.max((hi-lo)*.15,1);lo-=pad;hi+=pad;ctx.strokeStyle='#243a57';ctx.lineWidth=1;for(let i=0;i<4;i++){let y=18+i*(h-42)/3;ctx.beginPath();ctx.moveTo(38,y);ctx.lineTo(w-8,y);ctx.stroke()}ctx.fillStyle='#9fb0c8';ctx.font='11px Arial';ctx.fillText(hi.toFixed(1),2,22);ctx.fillText(lo.toFixed(1),2,h-19);const points=samples.map((s,i)=>({x:38+i*(w-48)/Math.max(samples.length-1,1),v:s.vitals[canvas.dataset.key]})).filter(p=>Number.isFinite(p.v));ctx.strokeStyle=canvas.dataset.color;ctx.lineWidth=2;ctx.beginPath();points.forEach((p,i)=>{const y=18+(hi-p.v)*(h-42)/(hi-lo);i?ctx.lineTo(p.x,y):ctx.moveTo(p.x,y)});ctx.stroke()}
function drawCharts(history){document.querySelectorAll('canvas[data-key]').forEach(canvas=>drawChart(canvas,history))}
async function refresh(){try{const [vitals,health,history]=await Promise.all([fetch('/api/v1/vitals').then(r=>r.json()),fetch('/healthz').then(r=>r.json()),fetch('/api/v1/history').then(r=>r.json())]);
fields.forEach(([key,,unit])=>document.getElementById(key).innerHTML=`${show(vitals.vitals[key])}<span class="unit">${unit}</span>`);
document.getElementById('state').textContent=health.mqtt_connected?'MQTT connected':'Waiting for MQTT';
drawCharts(history);
const recent=document.getElementById('recent'); if(!history.length){recent.textContent='Waiting for readings from the ESP32…';return}
recent.innerHTML='<table><thead><tr><th>Received</th><th>Heart rate</th><th>SpO₂</th><th>Temperature</th></tr></thead><tbody>'+history.slice(-10).reverse().map(s=>`<tr><td>${new Date(s.received_at).toLocaleTimeString()}</td><td>${show(s.vitals.heart_rate_bpm)} bpm</td><td>${show(s.vitals.spo2_percent)}%</td><td>${show(s.vitals.temperature_c)} °C</td></tr>`).join('')+'</tbody></table>';
}catch(e){document.getElementById('state').textContent='Dashboard connection error'}} refresh(); setInterval(refresh,3000);
</script></body></html>""", mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
