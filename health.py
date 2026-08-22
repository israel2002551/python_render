"""Render-ready MQTT receiver for encrypted ESP32 FHIR observations."""

import json
import os
import threading
from collections import deque
from datetime import datetime, timezone

from Crypto.Cipher import AES
from flask import Flask, jsonify
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
    return jsonify({
        "service": "ESP32 encrypted FHIR receiver",
        "latest": "/api/v1/vitals",
        "history": "/api/v1/history",
        "health": "/healthz",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
