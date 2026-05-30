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


def append_error(info, context, exc):
    info.setdefault("errors", []).append({
        "context": context,
        "error": str(exc)
    })


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
        "errors": [],
        "sections": [],
        "section_analysis": {},
        "entropy": {
            "file_entropy": None,
            "high_entropy_sections": []
        },
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
    except Exception as e:
        raw_data = None
        append_error(info, "file_read", e)

    if timestamps:
        info["timestamps"] = {}
        try:
            stats = os.stat(path)
            info["timestamps"]["modified_epoch"] = int(stats.st_mtime)
            info["timestamps"]["created_epoch"] = int(stats.st_ctime)
            info["timestamps"]["modified"] = datetime.datetime.utcfromtimestamp(stats.st_mtime).isoformat() + "Z"
            info["timestamps"]["created"] = datetime.datetime.utcfromtimestamp(stats.st_ctime).isoformat() + "Z"
        except Exception as e:
            append_error(info, "timestamps", e)

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

                        except Exception as e:
                            info["signature"] = "valid"
                            append_error(info, "certificate_parse", e)
        except Exception as e:
            append_error(info, "signature_directory", e)

        # Only collect file system timestamps for created and modified times
        # (PE header timestamp is excluded by user request).

        if hasattr(pe, "sections"):
            max_section_entropy = 0.0
            section_entropies = []
            overlay_start = 0
            known_names = {".text", ".rdata", ".rsrc", ".data", ".idata", ".edata", ".pdata", ".reloc", ".tls", ".rptr"}
            packer_name_patterns = ["UPX", "ASPACK", "MPRESS", "PEPACK", "PECUP", "NONSENSE", "MARK", "KPACK", "PETITE", "XPACK", "THUMPER"]
            suspicious_section_names = []
            packer_section_names = []
            invalid_sections = []
            section_map = {
                ".text": None,
                ".rdata": None,
                ".rsrc": None
            }

            for section in pe.sections:
                try:
                    section_name = section.Name.decode(errors="ignore").rstrip("\x00")
                except Exception:
                    section_name = "<unknown>"

                raw_size = int(section.SizeOfRawData)
                virt_size = int(getattr(section, "Misc_VirtualSize", 0))
                raw_start = int(section.PointerToRawData)
                raw_end = raw_start + raw_size
                overlay_start = max(overlay_start, raw_end)

                try:
                    section_data = section.get_data()
                    section_entropy = calculate_entropy(section_data)
                except Exception:
                    section_entropy = 0.0

                section_info = {
                    "name": section_name,
                    "virtual_size": virt_size,
                    "raw_size": raw_size,
                    "raw_offset": raw_start,
                    "entropy": round(section_entropy, 3),
                    "characteristics": int(getattr(section, "Characteristics", 0)),
                    "is_executable": bool(getattr(section, "Characteristics", 0) & 0x20000000),
                    "is_writable": bool(getattr(section, "Characteristics", 0) & 0x80000000),
                    "is_readable": bool(getattr(section, "Characteristics", 0) & 0x40000000)
                }

                section_entropies.append(section_info)
                info["sections"].append(section_info)

                if section_entropy > max_section_entropy:
                    max_section_entropy = section_entropy

                if section_entropy >= 7.0:
                    info["entropy"]["high_entropy_sections"].append({
                        "name": section_name,
                        "entropy": round(section_entropy, 3)
                    })

                if section_name.lower() in section_map:
                    section_map[section_name.lower()] = section_info

                if section_name and section_name.lower() not in known_names:
                    if any(ch.isalnum() or ch in "._" for ch in section_name):
                        suspicious_section_names.append(section_name)
                    else:
                        invalid_sections.append(section_name)

                upper_name = section_name.upper()
                if any(pattern in upper_name for pattern in packer_name_patterns):
                    packer_section_names.append(section_name)

            info["entropy"]["max_section_entropy"] = round(max_section_entropy, 3)
            info["entropy"]["sections"] = section_entropies

            overlay_info = {
                "present": False,
                "start": None,
                "size": 0,
                "entropy": None
            }
            if overlay_start < len(pe.__data__):
                overlay_info["present"] = True
                overlay_info["start"] = overlay_start
                overlay_info["size"] = len(pe.__data__) - overlay_start
                if raw_data is not None and overlay_info["size"] > 0:
                    overlay_data = pe.__data__[overlay_start:]
                    overlay_info["entropy"] = round(calculate_entropy(overlay_data), 3)

            info["section_analysis"] = {
                "overlay": overlay_info,
                "known_sections": section_map,
                "suspicious_section_names": suspicious_section_names,
                "invalid_sections": invalid_sections,
                "packer_section_names": packer_section_names,
                "section_count": len(pe.sections)
            }

            if raw_data is not None:
                packer_signatures = [b"UPX0", b"UPX1", b"UPX2", b"ASPack", b"MPRESS1", b"MPRESS2", b"PETITE", b"PECompact", b"Themida", b"DRP32", b"NICE" ]
                raw_upper = raw_data.upper()
                found = []
                for sig in packer_signatures:
                    if sig.upper() in raw_upper:
                        found.append(sig.decode(errors="ignore"))
                if found:
                    info["section_analysis"]["packer_signatures"] = found

    except Exception as e:
        append_error(info, "pe_analysis", e)

    except Exception as e:
        append_error(info, "pe_analysis", e)

    return info
