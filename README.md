# HEALTH

ESP32-based vital-sign monitoring prototype. The firmware collects readings,
builds a FHIR Bundle, encrypts it with AES-GCM, and publishes it to MQTT. The
Python service decrypts those messages and exposes the latest readings over HTTP.

## Files

- `health.ino` — ESP32 firmware.
- `health.py` — desktop MQTT dashboard.

## Setup

1. Install the Arduino libraries listed at the top of `health.ino` and upload
   the sketch after setting `ssid` and `password`. The default pin map targets
   an ESP32-S3 and uses GPIO 8 (SDA) and GPIO 9 (SCL) for the 16x2 I2C LCD
   (`0x27`). ECG input is GPIO 4, an ADC-capable S3 pin.
   Keep `secrets.h` local; it contains the device AES key and is ignored by Git.
   Use `secrets.example.h` as the template if creating another key.
2. Install the Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set `AES_KEY_HEX` to the 32-character hexadecimal form of the 16-byte key
   in `health.ino`, then start the service with `python health.py`.

## Render deployment

1. Push this project to GitHub and create a Render **Web Service** from it.
   The included `render.yaml` Blueprint supplies the build and start commands.
2. In Render Environment settings, add the secret `AES_KEY_HEX`. Enter the
   firmware key as hexadecimal without `0x`, commas, or spaces. For example,
   bytes `0x12, 0xAB` begin with `12ab`.
3. After deployment, use `/healthz` to check the service, `/api/v1/vitals`
   for the latest reading, and `/api/v1/history` for recent in-memory samples.

The service intentionally runs one Gunicorn worker, so MQTT samples are not
duplicated by multiple subscriber processes.

Both components use the public HiveMQ broker and subscribe/publish on
`health/fhir`. The AES key must match in both files. This is a prototype: do
not send identifiable or clinical data through the public topic.

## Measurement limits

The firmware applies basic ECG and PPG conditioning, signal-quality checks,
motion rejection, and PTT consistency checks. It is not a medically validated
device. In particular, the PTT blood-pressure model must be calibrated and
validated against a clinical reference for each intended use; a rejected or
unavailable estimate is published as an empty FHIR value.

Respiratory rate is only calculated when ADS1292R channel 2 is actually wired
and configured to carry a respiration/impedance waveform. It must stay
unavailable for an ECG-only channel.
