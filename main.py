import argparse
import json
from scanner import scan_directory
from analyzer import analyze_file
from engine import evaluate

from colorama import Fore, Style, init  

# Initialize colorama and auto-reset colors after each print
init(autoreset=True)


# Convert numeric score into human-readable risk level
def get_level(score):
    if score < 50:
        return "LOW"
    elif score < 120:
        return "MEDIUM"
    else:
        return "HIGH"


# Pretty-print analysis result in terminal with color coding
def print_result(result):
    score = result["score"]
    level = result["level"]

    # Assign color based on risk level
    if level == "LOW":
        color = Fore.GREEN
    elif level == "MEDIUM":
        color = Fore.YELLOW
    else:
        color = Fore.RED

    # File header
    print(f"\n{Fore.CYAN}File:{Style.RESET_ALL} {result['file']}")
    print(f"{Fore.CYAN}Score:{Style.RESET_ALL} {color}{score} ({level}){Style.RESET_ALL}")

    # Findings section (API hits + behavioral detections)
    print(f"{Fore.CYAN}Findings:{Style.RESET_ALL}")

    for fnd in result["findings"]:
        print(f"{Fore.MAGENTA}- {fnd['type']} (+{fnd['score']}){Style.RESET_ALL}")

        # List matched APIs (if any)
        if fnd.get("matches"):
            for api in fnd["matches"]:
                print(f"   {Fore.RED}→ {api}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser()

    # Input directory containing binaries to analyze
    parser.add_argument("--path", required=True)

    # Optional comma-separated extension filter (e.g. exe,dll)
    parser.add_argument("--extensions", required=False)

    # Enable JSON output mode
    parser.add_argument("--json", action="store_true")

    # Output file for JSON report
    parser.add_argument("--output", default="report.json")

    args = parser.parse_args()

    # Default file types to scan
    extensions = ["exe", "dll"]

    # Override extensions if provided by user
    if args.extensions:
        extensions = args.extensions.split(",")

    # Scan target directory
    files = scan_directory(args.path, extensions)

    results = []

    # Process each file individually
    for f in files:
        print(f"{Fore.BLUE}[+] Analyzing:{Style.RESET_ALL} {f}")

        # Extract PE metadata and imports
        info = analyze_file(f)

        # Evaluate risk score and behavioral findings
        score, findings = evaluate(info)

        result = {
            "file": f,
            "score": score,
            "level": get_level(score),
            "findings": findings
        }

        # Real-time CLI output (colored)
        print_result(result)

        results.append(result)

    # Export full analysis report to JSON if enabled
    if args.json:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)

        print(f"\n{Fore.GREEN}[+] JSON saved to: {args.output}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()