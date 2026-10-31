import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional

DEFAULT_HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scan_history.json")
DEFAULT_CSV_FILE = os.path.join(os.path.dirname(__file__), "scan_history.csv")

class HistoryManager:
    """Manages saving, loading, searching, and exporting scan results to JSON/CSV."""

    def __init__(self, json_path: str = DEFAULT_HISTORY_FILE, csv_path: str = DEFAULT_CSV_FILE):
        self.json_path = json_path
        self.csv_path = csv_path
        self._ensure_storage()

    def _ensure_storage(self):
        if not os.path.exists(self.json_path):
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def load_history(self) -> List[Dict[str, Any]]:
        """Loads all scan records from JSON file."""
        try:
            if os.path.exists(self.json_path):
                with open(self.json_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading scan history: {e}")
        return []

    def save_scan(self, scan_record: Dict[str, Any]) -> bool:
        """Appends a new scan record with timestamp and unique ID."""
        records = self.load_history()
        if "timestamp" not in scan_record:
            scan_record["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if "id" not in scan_record:
            scan_record["id"] = f"SCAN-{int(datetime.now().timestamp()*1000)}"

        # Prepend so newest is first
        records.insert(0, scan_record)

        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
            self._sync_csv(records)
            return True
        except Exception as e:
            print(f"Error saving scan record: {e}")
            return False

    def _sync_csv(self, records: List[Dict[str, Any]]):
        """Flattens records and writes to CSV for convenient export."""
        fieldnames = [
            "id", "timestamp", "url", "risk_score", "classification",
            "ml_prediction", "ml_confidence", "vt_detected", "gsb_detected",
            "phishtank_detected", "reasons"
        ]
        try:
            with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for rec in records:
                    reasons = "; ".join(rec.get("risk_factors", []))
                    writer.writerow({
                        "id": rec.get("id", ""),
                        "timestamp": rec.get("timestamp", ""),
                        "url": rec.get("url", ""),
                        "risk_score": rec.get("risk_score", 0),
                        "classification": rec.get("classification", ""),
                        "ml_prediction": rec.get("ml_prediction", ""),
                        "ml_confidence": rec.get("ml_confidence", 0),
                        "vt_detected": rec.get("vt_stats", {}).get("malicious", 0),
                        "gsb_detected": rec.get("gsb_status", {}).get("is_threat", False),
                        "phishtank_detected": rec.get("phishtank_status", {}).get("is_phish", False),
                        "reasons": reasons
                    })
        except Exception as e:
            print(f"Error syncing CSV history: {e}")

    def filter_history(self, search_query: Optional[str] = None, classification: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filters scans by URL keyword or risk classification."""
        records = self.load_history()
        filtered = records
        if search_query:
            query = search_query.lower()
            filtered = [r for r in filtered if query in r.get("url", "").lower()]
        if classification and classification != "All":
            filtered = [r for r in filtered if r.get("classification") == classification]
        return filtered

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Calculates total scans, breakdown of classifications, average risk score."""
        records = self.load_history()
        total = len(records)
        if total == 0:
            return {
                "total_scans": 0,
                "threats_detected": 0,
                "avg_risk_score": 0.0,
                "classifications": {"Low Risk": 0, "Moderate Risk": 0, "High Risk": 0, "Critical Risk": 0, "Inconclusive": 0}
            }
        
        counts = {"Low Risk": 0, "Moderate Risk": 0, "High Risk": 0, "Critical Risk": 0, "Inconclusive": 0}
        total_score = 0
        threat_count = 0

        for r in records:
            cls = r.get("classification", "Inconclusive")
            counts[cls] = counts.get(cls, 0) + 1
            score = r.get("risk_score", 0)
            total_score += score
            if cls in ("High Risk", "Critical Risk"):
                threat_count += 1

        return {
            "total_scans": total,
            "threats_detected": threat_count,
            "avg_risk_score": round(total_score / total, 1),
            "classifications": counts
        }

    def clear_history(self) -> bool:
        """Clears scan history."""
        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            if os.path.exists(self.csv_path):
                os.remove(self.csv_path)
            return True
        except Exception as e:
            print(f"Error clearing history: {e}")
            return False
