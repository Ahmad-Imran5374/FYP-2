import __main__
import joblib
import numpy as np
import pandas as pd
from kafka import KafkaConsumer
import requests
from requests.exceptions import RequestException

# Monkey patch for loading custom transformers
def replace_inf_with_nan(x):
    return np.where(np.isinf(x), np.nan, x)
__main__.replace_inf_with_nan = replace_inf_with_nan

# ─────────────────────────────────────────────────────
# CORRECTED LABEL MEANINGS
MALICIOUS_LABEL = 0  # malicious = 0
NORMAL_LABEL = 1     # normal = 1
LABEL_MAP = {0: "Malicious", 1: "Normal"}
DEVICE_LABELS = {0: "IoT Device", 1: "Non-IoT Device"}

# ─────────────────────────────────────────────────────
# CONFIGURATION
MODEL1_CONF_THRESHOLD = 0.50
MODEL2_CONF_THRESHOLD = 0.95
MERN_ENDPOINT = "http://localhost:5000/api/packets"
KAFKA_TOPIC = "CicFlowmeter"
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]

# Flow feature columns used during classifier training
FEATURE_COLUMNS = [
    'Protocol', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
    'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min',
    'Packet Length Max', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
    'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Fwd Segment Size Avg', 'Bwd Segment Size Avg', 'Fwd Bytes/Bulk Avg',
    'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg', 'Bwd Bytes/Bulk Avg',
    'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'FWD Init Win Bytes', 'Bwd Init Win Bytes', 'Fwd Act Data Pkts',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# ─────────────────────────────────────────────────────
# Load trained models
classifier_pipeline = joblib.load("Models/classifier.pkl")
attack_model = joblib.load("Models/attack.pkl")

# ─────────────────────────────────────────────────────
# Setup Kafka Consumer
consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    auto_offset_reset="earliest",
    enable_auto_commit=True,
    group_id="flow-classifier",
    value_deserializer=lambda m: m.decode("utf-8")
)
print("[✓] Kafka consumer listening for messages...")

# ─────────────────────────────────────────────────────
streak = {'malicious': 0}

for msg in consumer:
    raw = msg.value.strip()
    print(f"\n[Raw Kafka Message] {raw}")

    try:
        parts = raw.split(",")
        while parts and parts[-1] in ("", "NeedManualLabel"):
            parts.pop()

        if len(parts) < 7:
            print("[!] Skipping: not enough fields")
            continue

        flow_id, src_ip, src_port, dst_ip, dst_port, protocol, timestamp = parts[:7]
        features = [float(x) for x in parts[7:]]

        if len(features) != len(FEATURE_COLUMNS) - 1:
            print(f"[!] Feature count mismatch: {len(features)} found vs {len(FEATURE_COLUMNS) - 1} expected")
            continue

        # Build DataFrame
        df = pd.DataFrame([features], columns=FEATURE_COLUMNS[1:])
        df.insert(0, 'Protocol', protocol)

        # ── Model 1: Device Classification ──
        proba = classifier_pipeline.predict_proba(df)[0]
        pred_label = classifier_pipeline.predict(df)[0]
        conf = float(np.max(proba))
        device_str = DEVICE_LABELS.get(pred_label, f"Label-{pred_label}")

        print(f"[Model1] prediction = {device_str} ({pred_label}) (conf = {conf:.2f})")

        if pred_label == 0 and conf >= MODEL1_CONF_THRESHOLD:
            # ── Model 2: Attack Detection ──
            atk_proba = attack_model.predict_proba(df)[0]
            atk_pred = attack_model.predict(df)[0]
            atk_conf = float(np.max(atk_proba))
            label_str = LABEL_MAP.get(atk_pred, f"Label-{atk_pred}")

            print(f"[Model2] attack = {label_str} ({atk_pred}) (conf = {atk_conf:.2f})")

            packet = {
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "device_type": device_str,
                "attack_label": int(atk_pred),
                "attack_confidence": atk_conf
            }

            if atk_conf >= MODEL2_CONF_THRESHOLD:
                if atk_pred == MALICIOUS_LABEL:
                    streak['malicious'] += 1
                    print(f"[→] Malicious streak: {streak['malicious']}/5")
                    if streak['malicious'] >= 3:
                        try:
                            res = requests.post(MERN_ENDPOINT, json=packet, timeout=2)
                            res.raise_for_status()
                            print(f"[⚠️] ALERT SENT: {packet}")
                        except RequestException as e:
                            print(f"[!] Alert send failed: {e}")
                        streak['malicious'] = 0
                else:
                    streak['malicious'] = 0
                    try:
                        res = requests.post(MERN_ENDPOINT, json=packet, timeout=2)
                        res.raise_for_status()
                        print(f"[✓] Normal packet sent: {packet}")
                    except RequestException as e:
                        print(f"[!] Normal send failed: {e}")
            else:
                print(f"[→] Skipped MERN: Low confidence = {atk_conf:.2f}")
                streak['malicious'] = 0
        else:
            print(f"[→] Skipped attack model: device = {device_str}, conf = {conf:.2f}")
            streak['malicious'] = 0

    except Exception as e:
        print(f"[✗] ERROR processing message: {e}")
