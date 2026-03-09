import os
import csv
import magic
import subprocess
import hashlib
import math
import json



# Utility Functions

def normalize_path(path):
    return path.replace("\\", "_").replace("/", "_").replace(":", "")


def normalize_stream_name(name):
    return (
        name.replace("\\", "_")
        .replace("/", "_")
        .replace(":", "_")
        .replace("*", "_")
        .replace("?", "_")
        .replace("\"", "_")
        .replace("<", "_")
        .replace(">", "_")
        .replace("|", "_")
    )


def unique_path(base_path, ext):
    candidate = f"{base_path}.{ext}"
    if not os.path.exists(candidate):
        return candidate
    i = 1
    while True:
        candidate = f"{base_path}_{i}.{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


def compute_sha256(file_path):
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"[!] SHA256 failed for {file_path}: {e}")
        return "error"


def file_entropy(path, chunk_size=8192):
    freq = [0] * 256
    total = 0

    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                for b in chunk:
                    freq[b] += 1
                total += len(chunk)
    except Exception as e:
        print(f"[!] Entropy calculation failed for {path}: {e}")
        return None

    if total == 0:
        return 0.0

    ent = 0.0
    for count in freq:
        if count:
            p = count / total
            ent -= p * math.log2(p)

    return ent



# MIME → Extension Mapping

EXT_MAP = {
        # Images
        'image/png': 'png',
        'image/jpeg': 'jpeg',
        'image/bmp': 'bmp',
        'image/svg+xml': 'svg',
        'image/vnd.adobe.photoshop': 'psd',

        # Videos
        'video/mp4': 'mp4',
        'video/x-msvideo': 'avi',
        'video/x-matroska': 'mkv',

        # Audio
        'audio/mpeg': 'mp3',
        'audio/wav': 'wav',
        'audio/ogg': 'ogg',
        'audio/aac': 'aac',
        'audio/flac': 'flac',

        # Documents
        'application/pdf': 'pdf',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
        'application/vnd.ms-excel': 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
        'application/vnd.ms-powerpoint': 'ppt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
        'text/plain': 'txt',

        # Archives
        'application/zip': 'zip',
        'application/vnd.rar': 'rar',
        'application/x-7z-compressed': '7z',
        'application/gzip': 'gz',
        'application/x-tar': 'tar',

        # Executables
        'application/x-msdownload': 'exe',
        'application/x-ms-installer': 'msi',
        'application/x-executable': 'elf',
        'application/x-elf': 'elf',

        # Code/Markup
        'text/html': 'html',
        'application/json': 'json',
        'text/x-python': 'py',
        'application/javascript': 'js',
        'application/xml': 'xml',
        'text/xml': 'xml',
        'application/x-yaml': 'yaml',
        'text/yaml': 'yaml',

        # eBooks
        'application/epub+zip': 'epub',
        'application/x-mobipocket-ebook': 'mobi',

        # Design
        'application/postscript': 'ai'
}


def detect_and_rename(stream_file_path):
    try:
        mime = magic.from_file(stream_file_path, mime=True)
        ext = EXT_MAP.get(mime, 'bin')
        base_path = os.path.splitext(stream_file_path)[0]
        new_path = unique_path(base_path, ext)
        if os.path.abspath(new_path) != os.path.abspath(stream_file_path):
            os.rename(stream_file_path, new_path)
        return new_path, mime
    except Exception as e:
        print(f"[!] Failed to detect/rename {stream_file_path}: {e}")
        return stream_file_path, "unknown"



# Signature Database

SIGNATURES = {
    # Archives & Containers
    'zip': b'PK\x03\x04',
    'rar': b'Rar!',
    '7z': b'7z\xBC\xAF\x27\x1C',
    'tar': b'ustar',
    'gzip': b'\x1F\x8B\x08',
    'cab': b'MSCF',

    # Documents
    'pdf': b'%PDF',
    'doc': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
    'docx': b'PK\x03\x04',
    'rtf': b'{\\rtf',
    'rtf-alt': b'\x7B\x5C\x72\x74\x66\x31',
    'epub': b'PK\x03\x04',
    'xpi': b'PK\x03\x04',

    # Executables & Binaries
    'exe': b'MZ',
    'pe32+': b'MZ',
    'elf': b'\x7fELF',
    'macho': b'\xCF\xFA\xED\xFE',
    'macho32': b'\xCE\xFA\xED\xFE',
    'dex': b'dex\n',
    'class': b'\xCA\xFE\xBA\xBE',
    'wasm': b'\x00asm',
    'msi': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',

    # Scripts, Web, and Markup
    'html': b'<html',
    'js': b'<script',
    'xml': b'<?xml',

    # Images
    'png': b'\x89PNG\r\n\x1a\n',
    'jpeg': b'\xFF\xD8\xFF',
    'gif': b'GIF89a',
    'bmp': b'BM',
    'ico': b'\x00\x00\x01\x00',
    'heic': b'\x00\x00\x00\x18ftypheic',
    'tiff': b'\x49\x49\x2A\x00',

    # Video & Audio
    'avi': b'RIFF',
    'wav': b'RIFF',
    'mp3': b'ID3',
    'flac': b'fLaC',
    'ogg': b'OggS',
    'mkv': b'\x1A\x45\xDF\xA3',
    'mp4': b'\x00\x00\x00\x18ftypmp42',
    'mov': b'\x00\x00\x00\x18ftypqt',

    # Fonts
    'ttf': b'\x00\x01\x00\x00\x00',
    'woff': b'wOFF',
    'eot': b'LP\x00\x00',

    # Flash
    'swf': b'FWS',
    'swf-zlib': b'CWS',
    'swf-lzma': b'ZWS',

    # Virtual Disks & ISO
    'iso': b'CD001',
    'vhd': b'conectix',
    'vmdk': b'KDMV',
    'vdi': b'<<< Virt',
    'img': b'\xEB\x3C\x90',

    # Shortcuts
    'lnk': b'\x4C\x00\x00\x00',

    # Databases
    'sqlite': b'SQLite format 3'
}


def scan_for_polyglot_signatures(file_path):
    matches = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        for label, sig in SIGNATURES.items():
            if sig in data:
                matches.append(label)
    except Exception as e:
        print(f"[!] Signature scan failed for {file_path}: {e}")
    return matches



# ADS Stream Listing

def list_ads_streams(file_path):
    safe_path = file_path.replace("'", "''")
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            f"$p = '{safe_path}'; "
            "Get-Item -LiteralPath $p -Stream * | "
            "Where-Object { $_.Stream -and $_.Stream -notin @('::$DATA', ':$DATA') } | "
            "Select-Object -ExpandProperty Stream | "
            "ConvertTo-Json -Compress"
        )
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"[!] PowerShell ADS listing failed for {file_path}: {e}")
        return []

    if result.returncode != 0:
        err = result.stderr.strip() or "Unknown error"
        print(f"[!] PowerShell ADS listing failed for {file_path}: {err}")
        return []

    stdout = result.stdout.strip()
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except Exception as e:
        print(f"[!] Failed to parse ADS JSON for {file_path}: {e}")
        return []

    if isinstance(data, list):
        return data
    if isinstance(data, str):
        return [data]
    return []



# IOC Logic

def derive_iocs(is_ads, signatures, entropy_value):
    iocs = []

    if is_ads:
        iocs.append("ADS_PRESENT")

    if len(signatures) > 1:
        iocs.append("POLYGLOT_DETECTED")

    if entropy_value is not None and entropy_value > 7.2:
        iocs.append("HIGH_ENTROPY")

    if is_ads and 'exe' in signatures:
        iocs.append("EXECUTABLE_IN_ADS")

    return iocs if iocs else ["NONE"]


def derive_ioc_likelihood(iocs):
    if "ADS_PRESENT" in iocs and "POLYGLOT_DETECTED" in iocs:
        return "HIGH"
    if "POLYGLOT_DETECTED" in iocs:
        return "MEDIUM"
    if "HIGH_ENTROPY" in iocs:
        return "MEDIUM"
    return "LOW"



# ADS Extraction (Live)

def extract_ads_live(full_path, report_data):
    if not os.path.isfile(full_path):
        return

    main_hash = compute_sha256(full_path)
    main_entropy = file_entropy(full_path)
    main_signatures = scan_for_polyglot_signatures(full_path)

    main_iocs = derive_iocs(False, main_signatures, main_entropy)
    main_likelihood = derive_ioc_likelihood(main_iocs)

    try:
        main_mime = magic.from_file(full_path, mime=True)
    except Exception as e:
        print(f"[!] MIME detection failed for {full_path}: {e}")
        main_mime = "unknown"

    report_data.append({
        "Source": "Live",
        "File": full_path,
        "Stream": "Main_stream",
        "MIME Type": main_mime,
        "Main_File_SHA256": main_hash,
        "Stream_SHA256": "NA",
        "Extracted": "None",
        "Polyglot Indicators": ",".join(main_signatures) or "None",
        "Risk_Indicators": ",".join(main_iocs),
        "Risk_Likelihood": main_likelihood
    })

    streams = list_ads_streams(full_path)
    for stream in streams:
        if not stream or not str(stream).strip():
            continue
        stream = str(stream).strip()
        ads_path = f"{full_path}:{stream}"

        safe_dir = os.path.join(LIVE_DIR, normalize_path(full_path))
        os.makedirs(safe_dir, exist_ok=True)

        stream_file_name = normalize_stream_name(stream)
        temp_path = os.path.join(safe_dir, stream_file_name + ".stream")
        try:
            with open(ads_path, "rb") as i, open(temp_path, "wb") as o:
                o.write(i.read())
        except Exception as e:
            print(f"[!] Failed to extract ADS {ads_path}: {e}")
            continue

        renamed, mime = detect_and_rename(temp_path)
        stream_hash = compute_sha256(renamed)
        stream_entropy = file_entropy(renamed)
        stream_signatures = scan_for_polyglot_signatures(renamed)

        iocs = derive_iocs(True, stream_signatures, stream_entropy)
        likelihood = derive_ioc_likelihood(iocs)

        report_data.append({
            "Source": "Live",
            "File": full_path,
            "Stream": stream,
            "MIME Type": mime,
            "Main_File_SHA256": main_hash,
            "Stream_SHA256": stream_hash,
            "Extracted": renamed,
            "Polyglot Indicators": ",".join(stream_signatures) or "None",
            "Risk_Indicators": ",".join(iocs),
            "Risk_Likelihood": likelihood
        })



# Main

def main():
    report_data = []

    path = input("Enter file or folder path: ").strip('"')
    output_dir = input("Enter output directory: ").strip()

    if not output_dir:
        print("Output directory required.")
        return

    global LIVE_DIR
    LIVE_DIR = os.path.join(output_dir, "live")
    os.makedirs(LIVE_DIR, exist_ok=True)

    if os.path.isfile(path):
        extract_ads_live(path, report_data)
    else:
        for root, _, files in os.walk(path):
            for f in files:
                extract_ads_live(os.path.join(root, f), report_data)

    csv_path = os.path.join(output_dir, "report.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Source", "File", "Stream", "MIME Type",
                "Main_File_SHA256", "Stream_SHA256",
                "Extracted",
                "Polyglot Indicators", "Risk_Indicators", "Risk_Likelihood"
            ]
        )
        writer.writeheader()
        writer.writerows(report_data)

    print(f"\n Report written to {csv_path}")


if __name__ == "__main__":
    main()
