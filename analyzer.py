import pefile

# Analyze PE file and extract basic metadata used for risk evaluation
def analyze_file(path):
    info = {
        "path": path,
        "signed": False,   # Placeholder – signature analysis not implemented yet
        "imports": []      # List of imported API functions
    }

    try:
        # Load and parse PE structure
        pe = pefile.PE(path)

        # Check if import table exists
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            # Iterate over imported DLLs
            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                # Iterate over imported functions from each DLL
                for imp in entry.imports:

                    # Some entries may not have a name (ordinal imports)
                    if imp.name:
                        info["imports"].append(imp.name.decode())

    except Exception:
        # Fail silently – invalid/corrupted PE or unsupported file
        pass

    return info