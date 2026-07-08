import argparse
import sys
import os
import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)'
)


def analyze_log(file_path):
    malformed_lines = 0
    total_requests = 0

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

    print(f"Total Requests: {total_requests}")
    print(f"Malformed Lines Skipped: {malformed_lines}")


def main():
    parser = argparse.ArgumentParser(description="A CLI tool to analyze access logs.")
    parser.add_argument("file_path", help="Path to the access log file")

    args = parser.parse_args()
    analyze_log(args.file_path)


if __name__ == "__main__":
    main()
