import os
import datetime
import math
import pefile
import warnings
warnings.filterwarnings("ignore") # Supress cryptography warnings about unsupported signature types

TRUSTED_PUBLISHERS = [
    "Microsoft Corporation",
    "Google LLC",
    "Adobe Inc."
]


def calculate_entropy(data):
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count:
            freq = count / length
            entropy -= freq * math.log2(freq)
    return entropy

# Analyze PE file and extract basic metadata used for risk evaluation
def analyze_file(path, timestamps=False):
    info = {
        "path": path,
        # signature: one of "unsigned", "selfsigned", "valid"
        "signature": "unsigned",
        "publisher": None,
        "imports": [],      # List of imported API functions
        "signature_details": {
            "signature_status": "unsigned",
            "signed": False,
            "publisher": None,
            "subject": None,
            "subject_cn": None,
            "subject_o": None,
            "issuer": None,
            "issuer_cn": None,
            "issuer_o": None,
            "not_valid_before": None,
            "not_valid_after": None,
            "serial_number": None,
            "signature_algorithm": None,
            "trusted_vendor": False
        }
    }

    try:
        with open(path, "rb") as f:
            raw_data = f.read()
            file_entropy = calculate_entropy(raw_data)
            info["entropy"] = {
                "file_entropy": round(file_entropy, 3),
                "high_entropy_sections": []
            }
    except Exception:
        raw_data = None

    if timestamps:
        info["timestamps"] = {}
        try:
            stats = os.stat(path)
            info["timestamps"]["modified_epoch"] = int(stats.st_mtime)
            info["timestamps"]["created_epoch"] = int(stats.st_ctime)
            info["timestamps"]["modified"] = datetime.datetime.utcfromtimestamp(stats.st_mtime).isoformat() + "Z"
            info["timestamps"]["created"] = datetime.datetime.utcfromtimestamp(stats.st_ctime).isoformat() + "Z"
        except Exception:
            pass

    try:
        pe = pefile.PE(path)

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        info["imports"].append(imp.name.decode())

        # Signature extraction
        try:
            sec_idx = None
            try:
                sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            except Exception:
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                    sec_idx = 4

            if sec_idx is not None and sec_idx < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]

                if getattr(sec, "Size", 0) and getattr(sec, "VirtualAddress", 0):
                    start = int(sec.VirtualAddress)
                    size = int(sec.Size)
                    blob = pe.__data__[start:start + size]

                    if len(blob) > 8:
                        pkcs7_data = blob[8:]

                        # Try parsing with cryptography
                        try:
                            from cryptography.hazmat.primitives.serialization import pkcs7
                            from cryptography.x509.oid import NameOID

                            certs = None
                            try:
                                certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
                            except Exception:
                                certs = None

                            if certs:
                                cert = certs[0]
                                subj = cert.subject
                                issuer = cert.issuer

                                def _get_dn_attr(name, oid):
                                    attrs = name.get_attributes_for_oid(oid)
                                    return attrs[0].value if attrs else None

                                subject_cn = _get_dn_attr(subj, NameOID.COMMON_NAME)
                                subject_o = _get_dn_attr(subj, NameOID.ORGANIZATION_NAME)
                                issuer_cn = _get_dn_attr(issuer, NameOID.COMMON_NAME)
                                issuer_o = _get_dn_attr(issuer, NameOID.ORGANIZATION_NAME)

                                publisher = subject_o or subject_cn
                                info["publisher"] = publisher

                                try:
                                    if issuer.rfc4514_string() == subj.rfc4514_string():
                                        info["signature"] = "selfsigned"
                                    else:
                                        info["signature"] = "valid"
                                except Exception:
                                    info["signature"] = "valid"

                                info["signature_details"].update({
                                    "signature_status": info["signature"],
                                    "signed": True,
                                    "publisher": publisher,
                                    "subject": subj.rfc4514_string(),
                                    "subject_cn": subject_cn,
                                    "subject_o": subject_o,
                                    "issuer": issuer.rfc4514_string(),
                                    "issuer_cn": issuer_cn,
                                    "issuer_o": issuer_o,
                                    "not_valid_before": cert.not_valid_before.isoformat() + "Z" if cert.not_valid_before else None,
                                    "not_valid_after": cert.not_valid_after.isoformat() + "Z" if cert.not_valid_after else None,
                                    "serial_number": format(cert.serial_number, 'X'),
                                    "signature_algorithm": getattr(cert.signature_hash_algorithm, 'name', None),
                                    "trusted_vendor": bool(publisher and publisher in TRUSTED_PUBLISHERS)
                                })
                            else:
                                info["signature"] = "valid"
                                info["signature_details"]["signature_status"] = "valid"
                                info["signature_details"]["signed"] = True

                        except Exception:
                            info["signature"] = "valid"
        except Exception:
            pass

        # Only collect file system timestamps for created and modified times
        # (PE header timestamp is excluded by user request).

        if hasattr(pe, "sections"):
            max_section_entropy = 0.0
            section_entropies = []
            for section in pe.sections:
                try:
                    section_name = section.Name.decode(errors="ignore").rstrip("\x00")
                except Exception:
                    section_name = "<unknown>"

                try:
                    section_data = section.get_data()
                    section_entropy = calculate_entropy(section_data)
                except Exception:
                    section_entropy = 0.0

                section_entropies.append({
                    "name": section_name,
                    "entropy": round(section_entropy, 3)
                })

                if section_entropy > max_section_entropy:
                    max_section_entropy = section_entropy

                if section_entropy >= 7.0:
                    info["entropy"]["high_entropy_sections"].append({
                        "name": section_name,
                        "entropy": round(section_entropy, 3)
                    })

            info["entropy"]["max_section_entropy"] = round(max_section_entropy, 3)
            info["entropy"]["sections"] = section_entropies

    except Exception:
        pass

    return info
