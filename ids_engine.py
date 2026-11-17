import csv
import json
import math
import os
import sqlite3
from datetime import datetime

DB_FILE = "university_ids.db"
MODEL_FILE = "model_weights.json"

# The 6 features defined in Milestone 2 Section 5.2
FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Flow Bytes/s",
]

DEFAULT_MODEL = {
    "learning_rate": 0.08,
    "bias": -0.5,
    "weights": {
        "Destination Port": 0.25,
        "Flow Duration": -0.15,
        "Total Fwd Packets": 0.45,
        "Total Backward Packets": -0.10,
        "Flow Packets/s": 0.65,
        "Flow Bytes/s": 0.55,
    },
    # Reference scales for log/linear normalization
    "scales": {
        "Destination Port": 65535.0,
        "Flow Duration": 120000000.0,
        "Total Fwd Packets": 1000.0,
        "Total Backward Packets": 1000.0,
        "Flow Packets/s": 100000.0,
        "Flow Bytes/s": 10000000.0,
    },
    "training_updates": 0,
}


class AdaptiveIDSEngine:
    def __init__(self, db_path=DB_FILE, model_path=MODEL_FILE):
        self.db_path = db_path
        self.model_path = model_path
        self.model = self._load_model()
        self._init_db()

    def _load_model(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, "r") as f:
                return json.load(f)
        self._save_model(DEFAULT_MODEL)
        return DEFAULT_MODEL.copy()

    def _save_model(self, model_data=None):
        if model_data is not None:
            self.model = model_data
        with open(self.model_path, "w") as f:
            json.dump(self.model, f, indent=4)

    def _init_db(self):
        """Creates SQLite tables aligned with Milestone 2 Section 4 ERD."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS NetworkTrafficLogs (
                LogID INTEGER PRIMARY KEY AUTOINCREMENT,
                DstPort INTEGER,
                FlowDuration REAL,
                TotFwdPkts INTEGER,
                TotBwdPkts INTEGER,
                FlowPktsPerSec REAL,
                FlowBytesPerSec REAL,
                ActualLabel TEXT
            );

            CREATE TABLE IF NOT EXISTS Records (
                RecordID INTEGER PRIMARY KEY AUTOINCREMENT,
                LogID INTEGER,
                TimeCreated TEXT,
                NormalizedVector TEXT,
                FOREIGN KEY(LogID) REFERENCES NetworkTrafficLogs(LogID)
            );

            CREATE TABLE IF NOT EXISTS Alerts (
                AlertID INTEGER PRIMARY KEY AUTOINCREMENT,
                RecordID INTEGER,
                ThreatClassification TEXT,
                ThreatProbability REAL,
                Status TEXT,
                ReviewedByHuman INTEGER DEFAULT 0,
                FOREIGN KEY(RecordID) REFERENCES Records(RecordID)
            );
                
                CREATE TABLE IF NOT EXISTS Reports (
                ReportID INTEGER PRIMARY KEY AUTOINCREMENT,
                TimeGenerated TEXT,
                SourceFile TEXT,
                TotalRecords INTEGER,
                ThreatsDetected INTEGER,
                BenignFlows INTEGER,
                UncertainFlows INTEGER,
                WeightUpdates INTEGER,
                Accuracy REAL,
                F1Score REAL,
                FPR REAL
            );
            CREATE TABLE IF NOT EXISTS Alerts (
                AlertID INTEGER PRIMARY KEY AUTOINCREMENT,
                RecordID INTEGER,
                ThreatClassification TEXT,
                ThreatProbability REAL,
                Status TEXT,
                ReviewedByHuman INTEGER DEFAULT 0,
                ActionTaken TEXT DEFAULT 'NONE',
                FOREIGN KEY(RecordID) REFERENCES Records(RecordID)
            );
            """
        )
        # Safely add ActionTaken column if upgrading an older university_ids.db
        cur.execute("PRAGMA table_info(Alerts)")
        columns = [col[1] for col in cur.fetchall()]
        if "ActionTaken" not in columns:
            cur.execute("ALTER TABLE Alerts ADD COLUMN ActionTaken TEXT DEFAULT 'NONE'")
        conn.commit()
        conn.close()

    def _clean_number(self, val):
        """Milestone 2 Section 5.2: Replace NaN, null, infinity, or negative noise with 0."""
        if val is None:
            return 0.0
        s = str(val).strip().lower()
        if s in ("", "nan", "null", "inf", "-inf", "infinity", "-infinity"):
            return 0.0
        try:
            num = float(s)
            if math.isnan(num) or math.isinf(num) or num < 0:
                return 0.0
            return num
        except ValueError:
            return 0.0

    def _normalize_features(self, raw_dict):
        """Scales raw CIC-IDS2017 flow metrics into a 0.0 - 1.0 range."""
        norm = {}
        for feat in FEATURES:
            val = self._clean_number(raw_dict.get(feat, 0.0))
            scale = self.model["scales"][feat]
            if feat == "Destination Port":
                # Sensitive ports (<= 1024) get higher risk weighting
                norm[feat] = 0.85 if 0 < val <= 1024 else min(val / scale, 1.0)
            else:
                # Log-scaling handles massive spikes in Packets/s and Bytes/s smoothly
                norm[feat] = min(math.log1p(val) / math.log1p(scale), 1.0)
        return norm

    def predict_probability(self, norm_features):
        """Calculates continuous 0-100% threat probability via sigmoid activation."""
        z = self.model["bias"]
        for feat in FEATURES:
            z += self.model["weights"][feat] * norm_features[feat]
        # Clamp z to prevent math overflow
        z = max(min(z, 20.0), -20.0)
        prob = 1.0 / (1.0 + math.exp(-z))
        return round(prob * 100.0, 2)

    def classify_score(self, prob):
        """Maps probability to Threat, Uncertain (Human Review), or Benign."""
        if prob >= 70.0:
            return "THREAT"
        elif prob >= 40.0:
            return "UNCERTAIN"
        return "BENIGN"

    def adapt_weights(self, norm_features, target_binary, predicted_prob):
        """
        ML Learning Step: Adjusts feature weights and bias when a mistake occurs
        or when an uncertain anomaly is resolved by an analyst.
        target_binary: 1.0 for Threat, 0.0 for Benign
        """
        lr = self.model["learning_rate"]
        pred_scaled = predicted_prob / 100.0
        error = target_binary - pred_scaled

        for feat in FEATURES:
            self.model["weights"][feat] += lr * error * norm_features[feat]
            self.model["weights"][feat] = round(self.model["weights"][feat], 5)

        self.model["bias"] = round(self.model["bias"] + (lr * error), 5)
        self.model["training_updates"] += 1
        self._save_model()

    def process_csv(self, csv_path, auto_learn=True, limit=None):
        """Reads CIC-IDS2017 CSV, stores records in SQLite, scores, and adapts on errors."""
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV file not found: {csv_path}")

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        stats = {
            "total": 0,
            "threats": 0,
            "benign": 0,
            "uncertain": 0,
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "weight_adjustments": 0,
        }

        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            # Strip leading/trailing spaces from headers (CIC-IDS2017 quirk)
            reader.fieldnames = [h.strip() for h in reader.fieldnames]

            for idx, row in enumerate(reader):
                if limit and idx >= limit:
                    break

                clean_row = {k.strip(): v for k, v in row.items() if k}
                raw_label = clean_row.get("Label", "UNKNOWN").strip()
                norm_vec = self._normalize_features(clean_row)
                prob = self.predict_probability(norm_vec)
                classification = self.classify_score(prob)

                # Store Log -> Record -> Alert in SQLite
                cur.execute(
                    """
                    INSERT INTO NetworkTrafficLogs
                    (DstPort, FlowDuration, TotFwdPkts, TotBwdPkts, FlowPktsPerSec, FlowBytesPerSec, ActualLabel)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(self._clean_number(clean_row.get("Destination Port"))),
                        self._clean_number(clean_row.get("Flow Duration")),
                        int(self._clean_number(clean_row.get("Total Fwd Packets"))),
                        int(self._clean_number(clean_row.get("Total Backward Packets"))),
                        self._clean_number(clean_row.get("Flow Packets/s")),
                        self._clean_number(clean_row.get("Flow Bytes/s")),
                        raw_label,
                    ),
                )
                log_id = cur.lastrowid

                cur.execute(
                    "INSERT INTO Records (LogID, TimeCreated, NormalizedVector) VALUES (?, ?, ?)",
                    (log_id, datetime.now().isoformat(timespec="seconds"), json.dumps(norm_vec)),
                )
                record_id = cur.lastrowid

                status = "NEEDS_REVIEW" if classification == "UNCERTAIN" else "LOGGED"
                cur.execute(
                    """
                    INSERT INTO Alerts (RecordID, ThreatClassification, ThreatProbability, Status)
                    VALUES (?, ?, ?, ?)
                    """,
                    (record_id, classification, prob, status),
                )

                stats["total"] += 1
                if classification == "THREAT":
                    stats["threats"] += 1
                elif classification == "UNCERTAIN":
                    stats["uncertain"] += 1
                else:
                    stats["benign"] += 1

                # Evaluate against ground-truth CSV label if present
                if raw_label != "UNKNOWN":
                    is_actual_threat = 0.0 if raw_label.upper() == "BENIGN" else 1.0
                    is_pred_threat = 1.0 if classification == "THREAT" else 0.0

                    if is_actual_threat == 1.0 and is_pred_threat == 1.0:
                        stats["tp"] += 1
                    elif is_actual_threat == 0.0 and is_pred_threat == 1.0:
                        stats["fp"] += 1
                    elif is_actual_threat == 0.0 and is_pred_threat == 0.0:
                        stats["tn"] += 1
                    elif is_actual_threat == 1.0 and is_pred_threat == 0.0:
                        stats["fn"] += 1

                    # Trigger adaptive learning on misclassifications OR uncertain confidence
                    wrong_prediction = (is_actual_threat == 1.0 and classification != "THREAT") or (
                        is_actual_threat == 0.0 and classification == "THREAT"
                    )
                    if auto_learn and (wrong_prediction or classification == "UNCERTAIN"):
                        self.adapt_weights(norm_vec, is_actual_threat, prob)
                        stats["weight_adjustments"] += 1

        conn.commit()
        conn.close()
        return stats

    def get_uncertain_alerts(self, limit=15):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT a.AlertID, a.ThreatProbability, l.DstPort, l.FlowDuration,
                   l.TotFwdPkts, l.FlowPktsPerSec, l.ActualLabel, r.NormalizedVector
            FROM Alerts a
            JOIN Records r ON a.RecordID = r.RecordID
            JOIN NetworkTrafficLogs l ON r.LogID = l.LogID
            WHERE a.Status = 'NEEDS_REVIEW'
            ORDER BY a.AlertID DESC LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    def resolve_uncertain_alert(self, alert_id, is_threat):
        """Human analyst labels an uncertain record -> updates DB and retrains model weights."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT a.ThreatProbability, r.NormalizedVector
            FROM Alerts a
            JOIN Records r ON a.RecordID = r.RecordID
            WHERE a.AlertID = ?
            """,
            (alert_id,),
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return False

        prob, norm_json = row
        norm_vec = json.loads(norm_json)
        target = 1.0 if is_threat else 0.0
        new_class = "THREAT" if is_threat else "BENIGN"

        # Update ML weights based on human feedback
        self.adapt_weights(norm_vec, target, prob)

        cur.execute(
            """
            UPDATE Alerts
            SET ThreatClassification = ?, Status = 'RESOLVED', ReviewedByHuman = 1
            WHERE AlertID = ?
            """,
            (new_class, alert_id),
        )
        conn.commit()
        conn.close()
        return True

    def get_recent_alerts(self, limit=15):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT a.AlertID, r.TimeCreated, a.ThreatClassification, a.ThreatProbability,
                   l.DstPort, l.FlowPktsPerSec, l.FlowBytesPerSec, l.ActualLabel, a.Status
            FROM Alerts a
            JOIN Records r ON a.RecordID = r.RecordID
            JOIN NetworkTrafficLogs l ON r.LogID = l.LogID
            ORDER BY a.AlertID DESC LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    def save_and_export_report(self, source_file, stats, metrics, export_dir="reports"):
        """
        Saves a summary record of the analysis run to SQLite and exports
        a formatted .txt report file for administrators.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(source_file)

        acc = round(metrics["accuracy"], 2) if metrics else 0.0
        f1 = round(metrics["f1"], 2) if metrics else 0.0
        fpr = round(metrics["fpr"], 2) if metrics else 0.0

        # 1. Insert session summary into the SQLite Reports table
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Reports (TimeGenerated, SourceFile, TotalRecords, ThreatsDetected,
                                 BenignFlows, UncertainFlows, WeightUpdates, Accuracy, F1Score, FPR)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                base_name,
                stats["total"],
                stats["threats"],
                stats["benign"],
                stats["uncertain"],
                stats["weight_adjustments"],
                acc,
                f1,
                fpr,
            ),
        )
        report_id = cur.lastrowid
        conn.commit()
        conn.close()

        # 2. Export a readable text report to disk
        os.makedirs(export_dir, exist_ok=True)
        export_path = os.path.join(export_dir, f"ids_report_{report_id}_{file_stamp}.txt")

        with open(export_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write(f"UNIVERSITY NETWORK IDS - ANALYSIS REPORT #{report_id}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated On   : {timestamp}\n")
            f.write(f"Dataset Source : {base_name}\n")
            f.write(f"Total Model Updates to Date: {self.model['training_updates']}\n\n")

            f.write("--- TRAFFIC CLASSIFICATION SUMMARY ---\n")
            f.write(f"Total Flows Analyzed : {stats['total']}\n")
            f.write(f"Confirmed Threats    : {stats['threats']}\n")
            f.write(f"Benign Activity      : {stats['benign']}\n")
            f.write(f"Uncertain (Flagged)  : {stats['uncertain']}\n")
            f.write(f"ML Weight Adjustments: {stats['weight_adjustments']}\n\n")

            if metrics:
                f.write("--- PERFORMANCE METRICS (VS. MILESTONE 2 TARGETS) ---\n")
                f.write(f"Accuracy  : {acc:.2f}%  (Target: >= 85.00%)\n")
                f.write(f"Recall    : {metrics['recall']:.2f}%\n")
                f.write(f"Precision : {metrics['precision']:.2f}%\n")
                f.write(f"F1-Score  : {f1:.2f}%\n")
                f.write(f"FPR       : {fpr:.2f}%  (Target: <= 15.00%)\n\n")

            f.write("--- CURRENT LEARNED FEATURE WEIGHTS ---\n")
            f.write(f"Bias: {self.model['bias']:+.5f}\n")
            for feat, weight in self.model["weights"].items():
                f.write(f"  {feat:<24}: {weight:+.5f}\n")
            f.write("=" * 60 + "\n")

        return report_id, export_path

    def get_past_reports(self, limit=10):
        """Retrieves historical session reports from the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ReportID,
                   TimeGenerated,
                   SourceFile,
                   TotalRecords,
                   ThreatsDetected,
                   UncertainFlows,
                   Accuracy,
                   F1Score,
                   FPR
            FROM Reports
            ORDER BY ReportID DESC LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    def evaluate_alert(self, alert_id):
        """
        Inspects a specific alert, ranks which features drove the threat probability,
        diagnoses the likely attack pattern, and recommends analyst next actions.
        """
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT a.AlertID,
                   a.ThreatClassification,
                   a.ThreatProbability,
                   a.Status,
                   a.ActionTaken,
                   l.DstPort,
                   l.FlowDuration,
                   l.TotFwdPkts,
                   l.TotBwdPkts,
                   l.FlowPktsPerSec,
                   l.FlowBytesPerSec,
                   r.NormalizedVector
            FROM Alerts a
                     JOIN Records r ON a.RecordID = r.RecordID
                     JOIN NetworkTrafficLogs l ON r.LogID = l.LogID
            WHERE a.AlertID = ?
            """,
            (alert_id,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return None

        (
            aid, classification, prob, status, action_taken,
            port, duration, fwd_pkts, bwd_pkts, pkts_s, bytes_s, norm_json
        ) = row
        norm_vec = json.loads(norm_json)

        # 1. Calculate individual feature risk contributions (weight * normalized value)
        contributions = {}
        for feat in FEATURES:
            contributions[feat] = round(self.model["weights"][feat] * norm_vec[feat], 4)

        sorted_drivers = sorted(contributions.items(), key=lambda x: x[1], reverse=True)

        # 2. Determine Severity Tier
        if prob >= 85.0:
            severity = "CRITICAL"
        elif prob >= 70.0:
            severity = "HIGH"
        elif prob >= 40.0:
            severity = "MODERATE (HUMAN REVIEW)"
        else:
            severity = "LOW / BENIGN"

        # 3. Diagnose Attack Vector & Recommend Next Actions
        sensitive_ports = {21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080}

        if classification == "BENIGN":
            profile = "Normal Campus Network Activity"
            actions = [
                "No containment required; continue passive monitoring.",
                "If this traffic caused service degradation, override classification to retrain weights.",
            ]
        elif pkts_s > 5000 and bytes_s < 500000:
            profile = "High-Velocity Volumetric Flood / Port Sweep (DDoS or Recon)"
            actions = [
                "Apply temporary rate-limiting or ACL block on the source IP at the campus edge firewall.",
                "Check switch port utilization on the affected academic or residence hall VLAN.",
                "Correlate destination port targets with firewall drop logs to confirm scan scope.",
            ]
        elif port in sensitive_ports:
            profile = f"Targeted Service Probing / Brute-Force Attempt (Port {port})"
            actions = [
                f"Audit authentication and connection logs on the destination host for Port {port}.",
                "Verify that campus VPN and MFA policies are enforced for external access to this service.",
                "Check vulnerability scanner reports to ensure the target service is patched.",
            ]
        elif duration > 10000000 and fwd_pkts > 50:
            profile = "Prolonged Session / Potential Slow-Rate Exhaustion or Exfiltration"
            actions = [
                "Inspect active session state and outbound byte ratios on the destination server.",
                "Cross-reference source/destination IPs against authorized university research or backup servers.",
                "Isolate host network interface if unauthorized data transfer is confirmed.",
            ]
        else:
            profile = "Anomalous Traffic Pattern (Uncertain / Novel Behavior)"
            actions = [
                "Cross-reference traffic timestamp with scheduled university lab or IT maintenance windows.",
                "Capture a 60-second targeted PCAP on the subnet gateway for manual packet inspection.",
                "Submit analyst verdict (Threat vs. Benign) to update the adaptive ML model weights.",
            ]

        return {
            "alert_id": aid,
            "classification": classification,
            "probability": prob,
            "severity": severity,
            "status": status,
            "action_taken": action_taken,
            "profile": profile,
            "raw_metrics": {
                "Destination Port": port,
                "Flow Duration": duration,
                "Fwd / Bwd Packets": f"{fwd_pkts} / {bwd_pkts}",
                "Flow Packets/s": round(pkts_s, 2),
                "Flow Bytes/s": round(bytes_s, 2),
            },
            "top_drivers": sorted_drivers[:3],
            "recommended_actions": actions,
        }

    def log_analyst_action(self, alert_id, action_description):
        """Records the containment/triage action taken by the security analyst."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE Alerts SET ActionTaken = ?, ReviewedByHuman = 1 WHERE AlertID = ?",
            (action_description, alert_id),
        )
        updated = cur.rowcount > 0
        conn.commit()
        conn.close()
        return updated