import os

# Recursively scans a directory and returns files matching given extensions
def scan_directory(path, scanned_extensions):
    files = []

    # Walk through all directories and subdirectories
    for root, dirs, filenames in os.walk(path):

        # Iterate over all files in current directory
        for f in filenames:

            # Check file against all target extensions
            for extension in scanned_extensions:

                # Case-insensitive extension match (e.g. .exe, .dll)
                if f.lower().endswith(f".{extension.lower()}"):

                    # Store full absolute path to matched file
                    files.append(os.path.join(root, f))

    return files