import pefile
import warnings
warnings.filterwarnings("ignore") # Supress cryptography warnings about unsupported signature types

# Analyze PE file and extract basic metadata used for risk evaluation
def analyze_file(path):
    info = {
        "path": path,
        # signature: one of "unsigned", "selfsigned", "valid"
        "signature": "unsigned",
        "publisher": None,
        "imports": []      # List of imported API functions
    }

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

                                org_attrs = subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                                cn_attrs = subj.get_attributes_for_oid(NameOID.COMMON_NAME)

                                publisher = None
                                if org_attrs:
                                    publisher = org_attrs[0].value
                                elif cn_attrs:
                                    publisher = cn_attrs[0].value

                                info["publisher"] = publisher

                                try:
                                    if cert.issuer.rfc4514_string() == cert.subject.rfc4514_string():
                                        info["signature"] = "selfsigned"
                                    else:
                                        info["signature"] = "valid"
                                except Exception:
                                    info["signature"] = "valid"
                            else:
                                info["signature"] = "valid"

                        except Exception:
                            info["signature"] = "valid"

        except Exception:
            pass

    except Exception:
        pass

    return info
