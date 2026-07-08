import argparse
import sys
import os


def analyze_log(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    print(f"Analyzing {file_path}...\n")
    with open(file_path, "r") as file:
        for line_number, line in enumerate(file, 1):
            pass


def main():
    parser = argparse.ArgumentParser(description="A CLI tool to analyze access logs.")
    parser.add_argument("file_path", help="Path to the access log file")

    args = parser.parse_args()
    analyze_log(args.file_path)


if __name__ == "__main__":
    main()
