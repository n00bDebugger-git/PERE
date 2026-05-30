import os

# Recursively scans a directory and returns files matching given extensions
def scan_directory(path, scanned_extensions):
    files = []

    if not os.path.isdir(path):
        return files

    normalized_extensions = [ext.lower().lstrip('.') for ext in scanned_extensions if ext]

    # Walk through all directories and subdirectories
    for root, dirs, filenames in os.walk(path):

        # Iterate over all files in current directory
        for f in filenames:

            # Check file against all target extensions
            for extension in normalized_extensions:

                # Case-insensitive extension match (e.g. .exe, .dll)
                if f.lower().endswith(f".{extension}"):

                    # Store full absolute path to matched file
                    files.append(os.path.join(root, f))

    return files