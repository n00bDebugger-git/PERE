import datetime
import time

# API definitions and risk scoring (initial scoring assisted by AI, manually adjusted)

# Memory manipulation APIs – used for allocation, protection changes and shellcode handling
memory_apis = {
    "VirtualAlloc": 30,
    "VirtualAllocEx": 35,
    "VirtualProtect": 25,
    "VirtualProtectEx": 25,
    "WriteProcessMemory": 45,
    "ReadProcessMemory": 20,
    "NtAllocateVirtualMemory": 35,
    "NtWriteVirtualMemory": 45
}

# Process injection APIs – indicate cross-process interaction or code execution
injection_apis = {
    "CreateRemoteThread": 50,
    "CreateRemoteThreadEx": 50,
    "NtCreateThreadEx": 50,
    "OpenProcess": 30,
    "NtOpenProcess": 30,
    "QueueUserAPC": 45,
    "SetThreadContext": 45,
    "GetThreadContext": 20,
    "SuspendThread": 25,
    "ResumeThread": 25
}

# Execution APIs – process spawning and command execution
execution_apis = {
    "CreateProcessA": 20,
    "CreateProcessW": 20,
    "WinExec": 25,
    "ShellExecuteA": 15,
    "ShellExecuteW": 15,
    "system": 25
}

# Dynamic DLL loading – often used in loaders or obfuscation
dll_apis = {
    "LoadLibraryA": 20,
    "LoadLibraryW": 20,
    "LoadLibraryExA": 25,
    "LoadLibraryExW": 25,
    "GetProcAddress": 25,
    "LdrLoadDll": 25
}

# Persistence via registry
persistence_apis = {
    "RegOpenKeyExA": 10,
    "RegOpenKeyExW": 10,
    "RegSetValueExA": 20,
    "RegSetValueExW": 20,
    "RegCreateKeyExA": 20,
    "RegCreateKeyExW": 20
}

# File system interaction – low risk alone, higher in context
file_apis = {
    "CreateFileA": 5,
    "CreateFileW": 5,
    "WriteFile": 5,
    "ReadFile": 5,
    "DeleteFileA": 10,
    "DeleteFileW": 10
}

# Match imported APIs against a scoring dictionary
def match_apis(imports, api_dict):
    return {api: api_dict[api] for api in api_dict if api in imports}


# Main evaluation logic – combines API scoring and behavioral heuristics
def evaluate_rules(file_info):
    imports = file_info["imports"]

    # signature metadata (trust model)
    signature = file_info.get("signature", "unsigned")   # unsigned | selfsigned | valid
    publisher = file_info.get("publisher", None)

    total_score = 0
    findings = []

    # trusted vendors list (highest trust level)
    trusted_publishers = [
        "Microsoft Corporation",
        "Google LLC",
        "Adobe Inc."
    ]

    # trusted signed binary overrides all scoring
    if signature == "valid" and publisher in trusted_publishers:
        return 0, [{
            "type": "Trusted Vendor Signature",
            "score": 0,
            "matches": {
                "publisher": publisher
            }
        }]

    # valid signature but unknown publisher (low trust)
    if signature == "valid" and publisher not in trusted_publishers:
        total_score += 20
        findings.append({
            "type": "Untrusted Signed Binary",
            "score": 20,
            "matches": {
                "publisher": publisher
            }
        })

    # self-signed binary (common in malware or internal tools)
    elif signature == "selfsigned":
        total_score += 40
        findings.append({
            "type": "Self-Signed Binary",
            "score": 40,
            "matches": {}
        })

    # unsigned binary (no trust signals)
    elif signature == "unsigned":
        total_score += 40
        findings.append({
            "type": "Unsigned Binary",
            "score": 40,
            "matches": {}
        })

    # API category scoring (behavioral signals)
    api_groups = [
        ("Memory APIs", memory_apis),
        ("Injection APIs", injection_apis),
        ("Execution APIs", execution_apis),
        ("DLL APIs", dll_apis),
        ("Persistence APIs", persistence_apis),
        ("File APIs", file_apis),
    ]

    for name, api_dict in api_groups:
        matches = match_apis(imports, api_dict)

        if matches:
            score = sum(matches.values())
            total_score += score

            findings.append({
                "type": name,
                "score": score,
                "matches": matches
            })

    # classic process injection pattern detection
    if (
        "VirtualAlloc" in imports and
        "WriteProcessMemory" in imports and
        "CreateRemoteThread" in imports
    ):
        total_score += 80
        findings.append({
            "type": "Injection Chain",
            "score": 80,
            "matches": {
                "VirtualAlloc": 30,
                "WriteProcessMemory": 45,
                "CreateRemoteThread": 50
            }
        })

    # stealth injection using NT APIs
    if (
        "OpenProcess" in imports and
        "NtCreateThreadEx" in imports
    ):
        total_score += 60
        findings.append({
            "type": "Stealth Injection",
            "score": 60,
            "matches": {
                "OpenProcess": 30,
                "NtCreateThreadEx": 50
            }
        })

    # dynamic API resolution typical for loaders
    if (
        ("LoadLibraryA" in imports or "LoadLibraryW" in imports) and
        "GetProcAddress" in imports
    ):
        total_score += 40
        findings.append({
            "type": "Dynamic API Resolution",
            "score": 40,
            "matches": {
                "LoadLibrary": 20,
                "GetProcAddress": 25
            }
        })

    timestamp_anomalies = file_info.get("timestamp_anomalies", [])
    for anomaly in timestamp_anomalies:
        total_score += anomaly["score"]
        findings.append(anomaly)

    return total_score, findings


def annotate_timestamp_anomalies(file_infos):
    valid_epochs = []
    for info in file_infos:
        ts = None
        timestamps = info.get("timestamps", {})
        if timestamps.get("pe_epoch") is not None:
            ts = timestamps["pe_epoch"]
        elif timestamps.get("modified_epoch") is not None:
            ts = timestamps["modified_epoch"]

        if ts is not None:
            valid_epochs.append(ts)

    if not valid_epochs:
        return

    sorted_epochs = sorted(valid_epochs)
    median = sorted_epochs[len(sorted_epochs) // 2]
    now = time.time()

    for info in file_infos:
        timestamps = info.get("timestamps", {})
        if not timestamps:
            continue

        ts = timestamps.get("pe_epoch") or timestamps.get("modified_epoch")
        if ts is None:
            continue

        anomalies = []

        if ts > now + 86400:
            anomalies.append({
                "type": "Future Timestamp",
                "score": 30,
                "matches": {
                    "timestamp": timestamps.get("pe") or timestamps.get("modified")
                }
            })

        if ts < datetime.datetime(2000, 1, 1).timestamp():
            anomalies.append({
                "type": "Historic Timestamp",
                "score": 20,
                "matches": {
                    "timestamp": timestamps.get("pe") or timestamps.get("modified")
                }
            })

        if abs(ts - median) >= 3 * 31536000 and len(valid_epochs) > 1:
            anomalies.append({
                "type": "Timestamp Outlier",
                "score": 20,
                "matches": {
                    "timestamp": timestamps.get("pe") or timestamps.get("modified"),
                    "median": datetime.datetime.utcfromtimestamp(median).isoformat() + "Z"
                }
            })

        info["timestamp_anomalies"] = anomalies
