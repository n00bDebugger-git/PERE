import argparse
import json
from scanner import scan_directory
from analyzer import analyze_file
from engine import evaluate
from rules import annotate_timestamp_anomalies

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

    if result.get("signature_details"):
        sig = result["signature_details"]
        print(f"{Fore.CYAN}Signature:{Style.RESET_ALL}")
        if sig.get("signature_status"):
            print(f"  {Fore.YELLOW}Status: {Style.RESET_ALL}{sig['signature_status']}")
        if sig.get("publisher"):
            print(f"  {Fore.YELLOW}Publisher: {Style.RESET_ALL}{sig['publisher']}")
        if sig.get("subject_cn"):
            print(f"  {Fore.YELLOW}Subject CN: {Style.RESET_ALL}{sig['subject_cn']}")
        if sig.get("issuer_cn"):
            print(f"  {Fore.YELLOW}Issuer CN: {Style.RESET_ALL}{sig['issuer_cn']}")
        if sig.get("not_valid_before") and sig.get("not_valid_after"):
            print(f"  {Fore.YELLOW}Valid: {Style.RESET_ALL}{sig['not_valid_before']} -> {sig['not_valid_after']}")
        if sig.get("signature_algorithm"):
            print(f"  {Fore.YELLOW}Algorithm: {Style.RESET_ALL}{sig['signature_algorithm']}")
        if sig.get("trusted_vendor") is not None:
            print(f"  {Fore.YELLOW}Trusted vendor: {Style.RESET_ALL}{sig['trusted_vendor']}")

    # Findings section (API hits + behavioral detections)
    print(f"{Fore.CYAN}Findings:{Style.RESET_ALL}")

    for fnd in result["findings"]:
        print(f"{Fore.MAGENTA}- {fnd['type']} (+{fnd['score']}){Style.RESET_ALL}")

        # List matched APIs or anomaly details
        if fnd.get("matches"):
            for key, value in fnd["matches"].items():
                print(f"   {Fore.RED}-> {key}: {Style.RESET_ALL}{value}")

    if result.get("timestamps"):
        print(f"{Fore.CYAN}Timestamps:{Style.RESET_ALL}")
        for key in ["created", "modified"]:
            value = result["timestamps"].get(key)
            if value:
                print(f"  {Fore.YELLOW}{key.capitalize()}: {Style.RESET_ALL}{value}")

    if result.get("entropy"):
        entropy = result["entropy"]
        print(f"{Fore.CYAN}Entropy:{Style.RESET_ALL}")
        if entropy.get("file_entropy") is not None:
            print(f"  {Fore.YELLOW}File: {Style.RESET_ALL}{entropy['file_entropy']}")
        if entropy.get("max_section_entropy") is not None:
            print(f"  {Fore.YELLOW}Max section: {Style.RESET_ALL}{entropy['max_section_entropy']}")
        if entropy.get("high_entropy_sections"):
            names = ", ".join([sec["name"] for sec in entropy["high_entropy_sections"][:3]])
            print(f"  {Fore.YELLOW}High entropy sections: {Style.RESET_ALL}{names}")


def main():
    parser = argparse.ArgumentParser(
        description="PERE — PE Risk Engine: analyze PE files and compute heuristic risk scores.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --path C:\\samples --timestamps --json --output findings.json\n"
            "  python main.py --path C:\\Windows\\System32 --extensions exe,dll\n"
        ),
    )


    # Input directory containing binaries to analyze
    parser.add_argument("--path", required=True)

    # Optional comma-separated extension filter (e.g. exe,dll)
    parser.add_argument("--extensions", required=False)

    # Include timestamp details and anomaly scoring
    parser.add_argument("--timestamps", action="store_true")

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
    print(f"{Fore.CYAN}[+] Scanning:{Style.RESET_ALL} {args.path}", flush=True)
    files = scan_directory(args.path, extensions)
    print(f"{Fore.CYAN}[+] Matched files:{Style.RESET_ALL} {len(files)}", flush=True)

    if not files:
        print(f"{Fore.YELLOW}[!] No matching files found in: {args.path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Looking for extensions: {', '.join(extensions)}{Style.RESET_ALL}")

        if args.json:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump([], f, indent=4)
            print(f"\n{Fore.GREEN}[+] JSON saved to: {args.output}{Style.RESET_ALL}", flush=True)

        return

    results = []

    # Collect metadata for all files so timestamp anomalies can be scored against the full set
    print(f"{Fore.CYAN}[+] Loading metadata for matched files:{Style.RESET_ALL}", flush=True)
    file_infos = []
    total_files = len(files)
    for index, f in enumerate(files, start=1):
        print(f"{Fore.CYAN}[+] Loading metadata ({index}/{total_files}):{Style.RESET_ALL} {f}", flush=True)
        file_infos.append(analyze_file(f, timestamps=args.timestamps))

    if args.timestamps:
        annotate_timestamp_anomalies(file_infos)

    # Process each file individually
    total_files = len(file_infos)
    for index, file_info in enumerate(file_infos, start=1):
        print(f"{Fore.BLUE}[+] Analyzing ({index}/{total_files}):{Style.RESET_ALL} {file_info['path']}", flush=True)

        # Evaluate risk score and behavioral findings
        score, findings = evaluate(file_info)

        result = {
            "file": file_info["path"],
            "score": score,
            "level": get_level(score),
            "findings": findings,
            "signature_details": file_info.get("signature_details", {}),
            "signature": file_info.get("signature", "unsigned")
        }

        if args.timestamps and file_info.get("timestamps"):
            result["timestamps"] = file_info["timestamps"]

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