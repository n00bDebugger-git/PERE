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
    signed = file_info.get("signed", False)

    total_score = 0
    findings = []

    # Score API categories
    for name, api_dict in [
        ("Memory APIs", memory_apis),
        ("Injection APIs", injection_apis),
        ("Execution APIs", execution_apis),
        ("DLL APIs", dll_apis),
        ("Persistence APIs", persistence_apis),
        ("File APIs", file_apis),
    ]:
        matches = match_apis(imports, api_dict)

        if matches:
            score = sum(matches.values())
            total_score += score

            findings.append({
                "type": name,
                "score": score,
                "matches": matches
            })

    # Basic trust heuristic – unsigned binaries are more suspicious
    if not signed:
        total_score += 40
        findings.append({
            "type": "Unsigned file",
            "score": 40,
            "matches": {}
        })

    # Classic injection chain (allocate → write → execute)
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
                "VirtualAlloc": 0,
                "WriteProcessMemory": 0,
                "CreateRemoteThread": 0
            }
        })

    # Lower-level / stealth injection using NT APIs
    if (
        "OpenProcess" in imports and
        "NtCreateThreadEx" in imports
    ):
        total_score += 60
        findings.append({
            "type": "Stealth Injection",
            "score": 60,
            "matches": {
                "OpenProcess": 0,
                "NtCreateThreadEx": 0
            }
        })

    # Dynamic API resolution – typical for loaders and obfuscation
    if (
        any(x in imports for x in ["LoadLibraryA", "LoadLibraryW"]) and
        "GetProcAddress" in imports
    ):
        total_score += 40
        findings.append({
            "type": "Dynamic API Resolution",
            "score": 40,
            "matches": {
                "LoadLibrary": 0,
                "GetProcAddress": 0
            }
        })

    return total_score, findings