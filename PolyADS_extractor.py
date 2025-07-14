import os
import csv
import magic
import subprocess
import hashlib


def normalize_path(path):
    return path.replace("\\", "_").replace("/", "_").replace(":", "")


def detect_and_rename(stream_file_path):
    try:
        mime = magic.from_file(stream_file_path, mime=True)
        print(f"    [+] MIME: {mime}")

        ext_map = {
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

        ext = ext_map.get(mime, '.bin')
        new_path = os.path.splitext(stream_file_path)[0] + ext
        os.rename(stream_file_path, new_path)
        return new_path, mime
    except Exception as e:
        print(f"    [!] MIME detect failed: {e}")
        return stream_file_path, 'unknown'


def compute_sha256(file_path):
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "error"


def scan_for_polyglot_signatures(file_path):
    signatures = {
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

    matches = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        for label, sig in signatures.items():
            if sig in content:
                matches.append(label)
    except Exception:
        return []
    return matches


def extract_ads_live(full_path, report_data):
    if not os.path.isfile(full_path):
        print(f"[!] Skipping non-file: {full_path}")
        return

    # Run polyglot detection on main file too
    polyglot_main = scan_for_polyglot_signatures(full_path)
    if len(polyglot_main) > 1:
        print(f"[!] ⚠ Polyglot detected in main file: {full_path}")
        report_data.append({
            "Source": "Live",
            "File": full_path,
            "Stream": "<main file>",
            "MIME Type": "N/A",
            "SHA256": compute_sha256(full_path),
            "Extracted": "N/A",
            "ADS Path": "N/A",
            "Polyglot Indicators": ", ".join(polyglot_main)
        })

    folder_safe = normalize_path(full_path)
    target_folder = os.path.join(LIVE_DIR, folder_safe)
    os.makedirs(target_folder, exist_ok=True)

    try:
        directory = os.path.dirname(full_path)
        filename = os.path.basename(full_path)
        print(f"[*] Checking file: {full_path}")
        print(f"[*] Running: dir /r \"{directory}\"")
        output = subprocess.check_output(f'dir /r "{directory}"', shell=True, text=True)
        for line in output.splitlines():
            if ':$DATA' in line and filename in line:
                print(f"    [DEBUG] Line with ADS: {line}")
                parts = line.strip().split()
                print(f"    [DEBUG] Parts: {parts}")
                stream = None
                for part in parts:
                    if ':$DATA' in part and part.startswith(filename + ':'):
                        stream = part.split(":", 1)[1].replace(":$DATA", "")
                        print(f"    [*] Attempting to extract: {full_path}:{stream}")
                        break
                if not stream:
                    continue

                stream_path = os.path.join(target_folder, f"{stream}.stream")
                try:
                    ads_path = f"{full_path}:{stream}"
                    with open(ads_path, 'rb') as in_file, open(stream_path, 'wb') as out_file:
                        out_file.write(in_file.read())
                    renamed, mime = detect_and_rename(stream_path)
                    sha256 = compute_sha256(renamed)
                    polyglot = scan_for_polyglot_signatures(renamed)
                    report_data.append({
                        "Source": "Live",
                        "File": full_path,
                        "Stream": stream,
                        "MIME Type": mime,
                        "SHA256": sha256,
                        "Extracted": renamed,
                        "Polyglot Indicators": ", ".join(polyglot) if len(polyglot) > 1 else "None",
                        "ADS Path": f"{full_path}:{stream}:$DATA"
                    })
                    print(f"[+] {full_path}:{stream} → {renamed}")
                except Exception as ex:
                    print(f"    [!] Extraction failed: {ex}")
    except Exception as e:
        print(f"[!] Failed to scan {full_path}: {e}")


def main():

    report_data = []
    main_file_reports = []

    print("Select mode:")
    print("1. Scan live NTFS folder or file")
    choice = input("Enter 1: ")

    if choice == '1':
        path = input("Enter full path to folder or file: ").strip('"')
        if os.path.exists(path):
            # Ask for output path after path is valid
            global OUTPUT_DIR, LIVE_DIR, REPORT_FILE
            output_path = input("Enter output folder path (required): ").strip()
            if not output_path:
                print("❌ Output folder is required.")
                return


            OUTPUT_DIR = output_path
            LIVE_DIR = os.path.join(OUTPUT_DIR, "live")
            REPORT_FILE = os.path.join(OUTPUT_DIR, "report.csv")

            os.makedirs(OUTPUT_DIR, exist_ok=True)
            os.makedirs(LIVE_DIR, exist_ok=True)

            if os.path.isfile(path):
                extract_ads_live(path, report_data)
            elif os.path.isdir(path):
                print("[*] Scanning recursively...")
                for root, _, files in os.walk(path):
                    for f in files:
                        full_path = os.path.join(root, f)
                        print(f"[*] Scanning file: {full_path}")
                        extract_ads_live(full_path, report_data)
            else:
                print("❌ Invalid path type.")
        else:
            print("❌ Path not found.")

        with open(REPORT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["Source", "File", "Stream", "MIME Type", "SHA256",  "Extracted", "ADS Path", "Polyglot Indicators"])
            writer.writeheader()
            for row in report_data:
                writer.writerow(row)

        print(f"\n✅ Done. Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
