import argparse
import json
from scanner import scan_directory
from analyzer import analyze_file
from engine import evaluate
from colorama import Fore, Style, init

init(autoreset=True)


def get_level(score):
    if score < 50:
        return "LOW"
    elif score < 120:
        return "MEDIUM"
    else:
        return "HIGH"


def print_result(result):
    score = result["score"]
    level = result["level"]

    # ======================
    # COLOR FOR SCORE LEVEL
    # ======================
    if level == "LOW":
        color = Fore.GREEN
    elif level == "MEDIUM":
        color = Fore.YELLOW
    else:
        color = Fore.RED

    print(f"\n{Fore.CYAN}File:{Style.RESET_ALL} {result['file']}")
    print(f"{Fore.CYAN}Score:{Style.RESET_ALL} {color}{score} ({level}){Style.RESET_ALL}")

    print(f"{Fore.CYAN}Findings:{Style.RESET_ALL}")

    for fnd in result["findings"]:
        print(f"{Fore.MAGENTA}- {fnd['type']} (+{fnd['score']}){Style.RESET_ALL}")

        if fnd.get("matches"):
            for api in fnd["matches"]:
                print(f"   {Fore.RED}→ {api}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--extensions", required=False)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", default="report.json")
    args = parser.parse_args()

    extensions = ["exe", "dll"]

    if args.extensions:
        extensions = args.extensions.split(",")

    files = scan_directory(args.path, extensions)

    results = []

    for f in files:
        print(f"{Fore.BLUE}[+] Analyzing:{Style.RESET_ALL} {f}")

        info = analyze_file(f)
        score, findings = evaluate(info)

        result = {
            "file": f,
            "score": score,
            "level": get_level(score),
            "findings": findings
        }

        # ======================
        # REAL-TIME COLORED OUTPUT
        # ======================
        print_result(result)

        results.append(result)

    # ======================
    # JSON OUTPUT
    # ======================
    if args.json:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)

        print(f"\n{Fore.GREEN}[+] JSON saved to: {args.output}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()