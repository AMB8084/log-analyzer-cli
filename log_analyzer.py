import argparse
import sys
import os
import re
from collections import Counter, defaultdict

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)'
)


def analyze_log(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    malformed_lines = 0
    total_requests = 0
    error_count = 0

    ip_counter = Counter()
    endpoint_counter = Counter()
    hourly_counter = Counter()
    suspicious_ips = defaultdict(int)

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            match = LOG_PATTERN.match(line)
            if not match:
                malformed_lines += 1
                continue

            total_requests += 1
            data = match.groupdict()

            ip = data["ip"]
            endpoint = data["endpoint"]
            status = data["status"]
            time_str = data["time"]

            ip_counter[ip] += 1
            endpoint_counter[endpoint] += 1

            if status.startswith("4") or status.startswith("5"):
                error_count += 1

            time_parts = time_str.split(":")
            if len(time_parts) >= 2:
                date = time_parts[0]
                hour = time_parts[1]
                hourly_counter[f"{date} {hour}:00"] += 1

            if status == "401" and endpoint == "/login":
                suspicious_ips[ip] += 1

    error_rate = (error_count / total_requests * 100) if total_requests else 0

    print("\n" + "=" * 40)
    print("LOG ANALYSIS REPORT")
    print("=" * 40)

    print("\n[1] BASE METRICS")
    print(f"- Total Valid Requests: {total_requests}")
    print(f"- Total Unique IPs: {len(ip_counter)}")
    print(f"- Malformed Lines Skipped: {malformed_lines}")
    print(f"- Error Rate (4xx & 5xx): {error_rate:.2f}%")

    print("\n[2] TOP 10 ENDPOINTS")
    for endpoint, count in endpoint_counter.most_common(10):
        print(f"    {endpoint:<25} | {count} requests")

    print("\n[3] HOURLY TRAFFIC DISTRIBUTION")
    max_traffic = max(hourly_counter.values()) if hourly_counter else 1
    for hour, count in sorted(hourly_counter.items()):
        bar = "█" * int((count / max_traffic) * 20)
        print(f"    {hour} | {count:>5} reqs | {bar}")

    print("\n[4] SUSPICIOUS ACTIVITY (Bonus)")
    found_suspicious = False
    for ip, count in suspicious_ips.items():
        if count >= 3:
            print(f"     IP: {ip} hit 401 on /login {count} times.")
            found_suspicious = True
    if not found_suspicious:
        print("     No major suspicious login activities detected.")

    print("\n" + "=" * 40 + "\n")


def main():
    parser = argparse.ArgumentParser(description="HamAmooz Log Analyzer CLI Tool")
    parser.add_argument(
        "file_path", help="Path to the access log file (e.g., access.log)"
    )

    args = parser.parse_args()
    analyze_log(args.file_path)


if __name__ == "__main__":
    main()
