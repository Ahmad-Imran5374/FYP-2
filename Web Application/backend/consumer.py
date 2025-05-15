import joblib
import numpy as np
import pandas as pd
from kafka import KafkaConsumer
import requests
from requests.exceptions import RequestException

# ─── Constants ────────────────────────────────────────────────
NORMAL_LABEL           = 0
MALICIOUS_LABEL        = 1
LABEL_MAP              = {
    NORMAL_LABEL:    "Normal",
    MALICIOUS_LABEL: "Malicious"
}
MODEL1_CONF_THRESHOLD  = 0.967
MODEL2_CONF_THRESHOLD  = 0.65

def replace_inf_with_nan(X):
    arr = np.array(X, dtype=float)
    arr[np.isinf(arr)] = np.nan
    return arr

# ─── Load models ───────────────────────────────────────────────
classifier    = joblib.load("MLModels/classifier.pkl")
label_encoder = joblib.load("MLModels/classifier_label_encoder.pkl")
attack_model  = joblib.load("mLModels/attack.pkl")

# ─── Attack‐model feature names ────────────────────────────────
atk_names = getattr(attack_model, "feature_names_in_", None)
if atk_names is None:
    atk_names = [
        # … your 77 feature names in order …
        "Flow ID","Src IP","Src Port","Dst IP","Dst Port","Protocol","Timestamp",
        "Flow Duration","Total Fwd Packet","Total Bwd packets",
        "Total Length of Fwd Packet","Total Length of Bwd Packet",
        "Fwd Packet Length Max","Fwd Packet Length Min",
        "Fwd Packet Length Mean","Fwd Packet Length Std",
        "Bwd Packet Length Max","Bwd Packet Length Min",
        "Bwd Packet Length Mean","Bwd Packet Length Std",
        "Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std",
        "Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean",
        "Fwd IAT Std","Fwd IAT Max","Fwd IAT Min","Bwd IAT Total",
        "Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
        "Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
        "Fwd Header Length","Bwd Header Length","Fwd Packets/s",
        "Bwd Packets/s","Packet Length Min","Packet Length Max",
        "Packet Length Mean","Packet Length Std","Packet Length Variance",
        "FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count",
        "ACK Flag Count","URG Flag Count","CWR Flag Count","ECE Flag Count",
        "Down/Up Ratio","Average Packet Size","Fwd Segment Size Avg",
        "Bwd Segment Size Avg","Fwd Bytes/Bulk Avg","Fwd Packet/Bulk Avg",
        "Fwd Bulk Rate Avg","Bwd Bytes/Bulk Avg","Bwd Packet/Bulk Avg",
        "Bwd Bulk Rate Avg","Subflow Fwd Packets","Subflow Fwd Bytes",
        "Subflow Bwd Packets","Subflow Bwd Bytes","FWD Init Win Bytes",
        "Bwd Init Win Bytes","Fwd Act Data Pkts","Fwd Seg Size Min",
        "Active Mean","Active Std","Active Max","Active Min",
        "Idle Mean","Idle Std","Idle Max","Idle Min"
    ]

n_clf = classifier.n_features_in_
n_atk = getattr(attack_model, "n_features_in_", len(atk_names))

print(f"[i] classifier expects {n_clf} features, attack_model expects {n_atk}")

# ─── Kafka & backend config ────────────────────────────────────
KAFKA_TOPIC             = "CicFlowmeter"
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]
MERN_ENDPOINT           = "http://localhost:5000/api/packets"

consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    auto_offset_reset="earliest",
    enable_auto_commit=True,
    group_id="flow-classifier",
    value_deserializer=lambda m: m.decode("utf-8")
)
print("[✓] Kafka consumer started. Listening for messages…")

for msg in consumer:
    raw = msg.value.strip()
    print(f"\n[Raw Kafka Message] {raw}")
    try:
        parts = raw.split(",")
        # strip trailing “NeedManualLabel” markers if present
        while parts and parts[-1].strip().lower() in ("needmanuallabel", ""):
            parts.pop()

        # numeric features begin at index 7
        raw_vals = [float(x) for x in parts[7:]]

        # ── Model 1: Device Classification ───────────────────
        clf_vals = (raw_vals + [0.0]*n_clf)[:n_clf]
        Xc       = replace_inf_with_nan(clf_vals).reshape(1, -1)

        proba1   = classifier.predict_proba(Xc)[0]
        enc1     = int(classifier.predict(Xc)[0])
        device   = label_encoder.inverse_transform([enc1])[0]
        conf1    = float(proba1[enc1])
        print(f"[Model1] device_type = {device} (conf={conf1:.3f})")

        # only if IoT Device with high confidence
        if device == "IoT Device" and conf1 > MODEL1_CONF_THRESHOLD:
            # ── Model 2: Attack Detection ────────────────────
            atk_vals = (raw_vals + [0.0]*n_atk)[:n_atk]
            # create DF, replace inf/-inf with NaN, then fill all NaN with 0
            df_atk = (
                pd.DataFrame([atk_vals], columns=atk_names)
                  .replace([np.inf, -np.inf], np.nan)
                  .fillna(0)
            )

            proba2   = attack_model.predict_proba(df_atk)[0]
            enc2     = int(attack_model.predict(df_atk)[0])
            conf2    = float(proba2[enc2])
            lbl2_str = LABEL_MAP.get(enc2, "Unknown")
            print(f"[Model2] attack_label = {enc2} ({lbl2_str}) (conf={conf2:.3f})")

            # only send if attack confidence is high
            if conf2 > MODEL2_CONF_THRESHOLD:
                packet = {
                    "device_type":       device,
                    "device_confidence": conf1,
                    "attack_label":      enc2,      # 1 = malicious, 0 = normal
                    "attack_type":       lbl2_str,
                    "attack_confidence": conf2
                }
                resp = requests.post(MERN_ENDPOINT, json=packet, timeout=2)
                resp.raise_for_status()
                print(f"[✓] Sent to MERN: {resp.status_code} → {packet}")
            else:
                print(f"[→] Skipping MERN send: Model2 confidence {conf2:.3f} ≤ {MODEL2_CONF_THRESHOLD}")
        else:
            print(f"[→] Skipping Model2: device={device}, conf1={conf1:.3f}")

    except Exception as e:
        print(f"[✗] ERROR: {e}")
        continue
