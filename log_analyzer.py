import argparse
import sys
import os
import re
from collections import Counter

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)'
)


def analyze_log(file_path):
    malformed_lines = 0
    total_requests = 0
    error_count = 0

    ip_counter = Counter()
    endpoint_counter = Counter()

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

            ip_counter[data["ip"]] += 1
            endpoint_counter[data["endpoint"]] += 1

            if data["status"].startswith("4") or data["status"].startswith("5"):
                error_count += 1

    error_rate = (error_count / total_requests * 100) if total_requests else 0

    print("=== Base Report ===")
    print(f"Total Valid Requests: {total_requests}")
    print(f"Total Unique IPs: {len(ip_counter)}")
    print(f"Error Rate (4xx/5xx): {error_rate:.2f}%\n")

    print("--- Top 10 Endpoints ---")
    for endpoint, count in endpoint_counter.most_common(10):
        print(f"{endpoint}: {count} requests")


def main():
    parser = argparse.ArgumentParser(description="A CLI tool to analyze access logs.")
    parser.add_argument("file_path", help="Path to the access log file")

    args = parser.parse_args()
    analyze_log(args.file_path)


if __name__ == "__main__":
    main()
