"""
SDN Traffic Classifier - Log Analyzer
Reads traffic_log.csv and prints a summary of classification results.
"""

import csv
import sys
import os
from collections import defaultdict, Counter

LOG_FILE = "traffic_log.csv"


def load_log(path):
    if not os.path.exists(path):
        sys.exit(f"[ERROR] Log file '{path}' not found. Run the controller first.")
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def analyze(rows):
    total = len(rows)
    if total == 0:
        print("No traffic logged yet.")
        return

    labels   = Counter(r["classification"] for r in rows)
    src_ips  = Counter(r["src_ip"] for r in rows)
    dst_ips  = Counter(r["dst_ip"] for r in rows)

    print("\n" + "=" * 50)
    print("  SDN TRAFFIC CLASSIFIER — LOG ANALYSIS")
    print("=" * 50)
    print(f"  Total packets logged : {total}\n")

    print("  Classification Breakdown:")
    print("  " + "-" * 30)
    for label in ["TCP", "UDP", "ICMP", "Other"]:
        count = labels.get(label, 0)
        pct   = count / total * 100
        bar   = "█" * int(pct / 2)
        print(f"  {label:<8} {count:>6} pkt  {pct:5.1f}%  {bar}")

    print("\n  Top 5 Source IPs:")
    for ip, cnt in src_ips.most_common(5):
        print(f"    {ip:<18} {cnt} packets")

    print("\n  Top 5 Destination IPs:")
    for ip, cnt in dst_ips.most_common(5):
        print(f"    {ip:<18} {cnt} packets")

    print("=" * 50 + "\n")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    rows = load_log(path)
    analyze(rows)
