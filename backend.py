import os
import csv
import magic
import subprocess
import hashlib
import math
import json        # still used by list_ads_streams
import time
import requests



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



# VirusTotal Integration

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
# Free public API: 4 lookups/minute → 15 s between requests
VT_REQUEST_DELAY = 15


def _fmt_ts(ts) -> str:
    """Convert a Unix timestamp to a readable UTC string, or return N/A."""
    if not ts:
        return "N/A"
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)


def check_virustotal(sha256: str, api_key: str) -> dict:
    """
    Query VirusTotal v3 /files/{hash} and return a fully enriched result dict.

    Fields returned (all keys always present, value is "N/A" when absent):
      Identity   : found, sha256, md5, sha1, meaningful_name, known_names,
                   file_size, type_description, magic, type_tag
      Detection  : verdict, malicious, suspicious, harmless, undetected,
                   timeout, failures, total_engines
      Reputation : reputation, votes_malicious, votes_harmless
      Threat     : threat_label, threat_category, threat_name, tags
      Timeline   : first_submitted, last_submitted, last_analyzed,
                   times_submitted, unique_sources
      Sigma      : sigma_critical, sigma_high, sigma_medium, sigma_low
      IDS        : ids_high, ids_medium, ids_low
      Sandbox    : sandbox_summary
      PE / packers: imphash, authentihash, compiler
      File-ID    : trid_top, detectiteasy_top
      Links      : vt_link
      Error      : error
    """
    url = VT_API_URL.format(hash=sha256)
    headers = {
        "accept":   "application/json",
        "x-apikey": api_key,
    }

    # ── base skeleton so every key is always present ─────────────────────────
    base = {
        "found": False, "sha256": sha256,
        "md5": "N/A", "sha1": "N/A",
        "meaningful_name": "N/A", "known_names": "N/A",
        "file_size": "N/A", "type_description": "N/A",
        "magic": "N/A", "type_tag": "N/A",
        "verdict": "NOT FOUND",
        "malicious": "N/A", "suspicious": "N/A",
        "harmless": "N/A", "undetected": "N/A",
        "timeout": "N/A", "failures": "N/A", "total_engines": "N/A",
        "reputation": "N/A",
        "votes_malicious": "N/A", "votes_harmless": "N/A",
        "threat_label": "N/A", "threat_category": "N/A", "threat_name": "N/A",
        "tags": "N/A",
        "first_submitted": "N/A", "last_submitted": "N/A",
        "last_analyzed": "N/A", "times_submitted": "N/A",
        "unique_sources": "N/A",
        "sigma_critical": "N/A", "sigma_high": "N/A",
        "sigma_medium": "N/A", "sigma_low": "N/A",
        "ids_high": "N/A", "ids_medium": "N/A", "ids_low": "N/A",
        "sandbox_summary": "N/A",
        "imphash": "N/A", "authentihash": "N/A", "compiler": "N/A",
        "trid_top": "N/A", "detectiteasy_top": "N/A",
        "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
        "error": "",
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 404:
            return {**base, "verdict": "NOT FOUND"}
        if response.status_code == 401:
            return {**base, "verdict": "AUTH ERROR",
                    "error": "Invalid API key (401)"}
        if response.status_code == 429:
            return {**base, "verdict": "RATE LIMITED",
                    "error": "Rate limit exceeded (429) – wait and retry"}

        response.raise_for_status()
        attrs = response.json()["data"]["attributes"]

        # ── Detection stats ───────────────────────────────────────────────────
        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        timeout    = stats.get("timeout",    0)
        failures   = stats.get("failure",    0) + stats.get("confirmed-timeout", 0)
        total      = sum(stats.values())

        verdict = (
            "MALICIOUS"  if malicious  > 0 else
            "SUSPICIOUS" if suspicious > 0 else
            "CLEAN"
        )

        # ── Threat classification ─────────────────────────────────────────────
        ptc            = attrs.get("popular_threat_classification", {})
        threat_label   = ptc.get("suggested_threat_label", "N/A")
        threat_cats    = [e["value"] for e in ptc.get("popular_threat_category", [])]
        threat_names   = [e["value"] for e in ptc.get("popular_threat_name", [])]

        # ── Sigma ─────────────────────────────────────────────────────────────
        sig_stats = attrs.get("sigma_analysis_stats", {})

        # ── Crowdsourced IDS ──────────────────────────────────────────────────
        ids_stats = attrs.get("crowdsourced_ids_stats", {})

        # ── Sandbox verdicts → compact summary ───────────────────────────────
        sb_verdicts = attrs.get("sandbox_verdicts", {})
        sb_parts = [
            f"{name}: {v.get('category','?')}"
            for name, v in sb_verdicts.items()
        ]
        sandbox_summary = " | ".join(sb_parts) if sb_parts else "N/A"

        # ── PE info ───────────────────────────────────────────────────────────
        pe      = attrs.get("pe_info", {})
        imphash = pe.get("imphash", "N/A")

        # ── DetectItEasy top entry ────────────────────────────────────────────
        die_vals = attrs.get("detectiteasy", {}).get("values", [])
        if die_vals:
            d  = die_vals[0]
            detectiteasy_top = f"{d.get('type','?')}: {d.get('name','?')} {d.get('version','')}"
        else:
            detectiteasy_top = "N/A"

        # ── TrID top entry ────────────────────────────────────────────────────
        trid_list = attrs.get("trid", [])
        if trid_list:
            t        = trid_list[0]
            trid_top = f"{t.get('file_type','?')} ({t.get('probability',0):.1f}%)"
        else:
            trid_top = "N/A"

        # ── Top 3 crowdsourced IDS alert messages ─────────────────────────────
        ids_results  = attrs.get("crowdsourced_ids_results", [])
        ids_high_msg = " | ".join(
            r["rule_msg"] for r in ids_results
            if r.get("alert_severity") == "high"
        )[:300] or "None"

        return {
            **base,
            # identity
            "found":            True,
            "md5":              attrs.get("md5",  "N/A"),
            "sha1":             attrs.get("sha1", "N/A"),
            "meaningful_name":  attrs.get("meaningful_name", "N/A"),
            "known_names":      ", ".join(attrs.get("names", [])[:5]) or "N/A",
            "file_size":        str(attrs.get("size", "N/A")),
            "type_description": attrs.get("type_description", "N/A"),
            "magic":            attrs.get("magic", "N/A"),
            "type_tag":         attrs.get("type_tag", "N/A"),
            # detection
            "verdict":          verdict,
            "malicious":        malicious,
            "suspicious":       suspicious,
            "harmless":         harmless,
            "undetected":       undetected,
            "timeout":          timeout,
            "failures":         failures,
            "total_engines":    total,
            # reputation
            "reputation":       attrs.get("reputation", "N/A"),
            "votes_malicious":  attrs.get("total_votes", {}).get("malicious", "N/A"),
            "votes_harmless":   attrs.get("total_votes", {}).get("harmless",  "N/A"),
            # threat
            "threat_label":     threat_label,
            "threat_category":  ", ".join(threat_cats) or "N/A",
            "threat_name":      ", ".join(threat_names) or "N/A",
            "tags":             ", ".join(attrs.get("tags", [])) or "N/A",
            # timeline
            "first_submitted":  _fmt_ts(attrs.get("first_submission_date")),
            "last_submitted":   _fmt_ts(attrs.get("last_submission_date")),
            "last_analyzed":    _fmt_ts(attrs.get("last_analysis_date")),
            "times_submitted":  attrs.get("times_submitted", "N/A"),
            "unique_sources":   attrs.get("unique_sources",  "N/A"),
            # sigma
            "sigma_critical":   sig_stats.get("critical", 0),
            "sigma_high":       sig_stats.get("high",     0),
            "sigma_medium":     sig_stats.get("medium",   0),
            "sigma_low":        sig_stats.get("low",      0),
            # ids
            "ids_high":         ids_stats.get("high",   0),
            "ids_medium":       ids_stats.get("medium", 0),
            "ids_low":          ids_stats.get("low",    0),
            # sandbox
            "sandbox_summary":  sandbox_summary,
            # pe / packer
            "imphash":          imphash,
            "authentihash":     attrs.get("authentihash", "N/A"),
            "compiler":         detectiteasy_top,
            # file-id
            "trid_top":         trid_top,
            "detectiteasy_top": detectiteasy_top,
            # ids alert detail
            "ids_high_alerts":  ids_high_msg,
        }

    except requests.RequestException as e:
        return {**base, "verdict": "ERROR", "error": str(e)}


def collect_file_paths(path: str) -> list:
    """Return a flat list of file paths from a file or directory."""
    paths = []
    if os.path.isfile(path):
        paths.append(path)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                paths.append(os.path.join(root, f))
    return paths


def scan_files_virustotal(
    file_paths: list,
    api_key: str,
    output_dir: str,
    log_callback=None
) -> list:
    """
    Hash each file and query VirusTotal.

    Writes vt_report.csv to output_dir.
    Returns list of result dicts.
    """
    report_data = []
    total = len(file_paths)

    for idx, path in enumerate(file_paths, start=1):
        if not os.path.isfile(path):
            continue

        filename = os.path.basename(path)

        if log_callback:
            log_callback(f"[{idx}/{total}] Hashing: {filename}\n")

        sha256 = compute_sha256(path)
        if sha256 == "error":
            if log_callback:
                log_callback(f"[!] Could not hash {filename}, skipping.\n")
            continue

        if log_callback:
            log_callback(f"      SHA256: {sha256}\n")
            log_callback(f"      Querying VirusTotal...\n")

        result = check_virustotal(sha256, api_key)

        if "error" in result:
            if log_callback:
                log_callback(f"[!] VT error: {result['error']}\n")
        elif not result.get("found"):
            if log_callback:
                log_callback(f"      → Not found in VirusTotal database\n")
        else:
            if log_callback:
                log_callback(
                    f"      → {result['verdict']}  "
                    f"({result['malicious']}/{result['total_engines']} detections)\n"
                )

        row = {
            # ── Identity ──────────────────────────────────────
            "File":             path,
            "SHA256":           sha256,
            "MD5":              result.get("md5",              "N/A"),
            "SHA1":             result.get("sha1",             "N/A"),
            "Meaningful_Name":  result.get("meaningful_name",  "N/A"),
            "Known_Names":      result.get("known_names",      "N/A"),
            "File_Size":        result.get("file_size",        "N/A"),
            "Type_Description": result.get("type_description", "N/A"),
            "Magic":            result.get("magic",            "N/A"),
            "Type_Tag":         result.get("type_tag",         "N/A"),
            # ── Detection ─────────────────────────────────────
            "Found_in_VT":      str(result.get("found", "N/A")),
            "Verdict":          result.get("verdict",       "ERROR"),
            "Malicious":        str(result.get("malicious",  "N/A")),
            "Suspicious":       str(result.get("suspicious", "N/A")),
            "Harmless":         str(result.get("harmless",   "N/A")),
            "Undetected":       str(result.get("undetected", "N/A")),
            "Timeout":          str(result.get("timeout",    "N/A")),
            "Failures":         str(result.get("failures",   "N/A")),
            "Total_Engines":    str(result.get("total_engines", "N/A")),
            # ── Reputation ────────────────────────────────────
            "VT_Reputation":       str(result.get("reputation",      "N/A")),
            "Community_Malicious": str(result.get("votes_malicious", "N/A")),
            "Community_Harmless":  str(result.get("votes_harmless",  "N/A")),
            # ── Threat classification ─────────────────────────
            "Threat_Label":    result.get("threat_label",    "N/A"),
            "Threat_Category": result.get("threat_category", "N/A"),
            "Threat_Name":     result.get("threat_name",     "N/A"),
            "Tags":            result.get("tags",            "N/A"),
            # ── Timeline ──────────────────────────────────────
            "First_Submitted":  result.get("first_submitted",  "N/A"),
            "Last_Submitted":   result.get("last_submitted",   "N/A"),
            "Last_Analyzed":    result.get("last_analyzed",    "N/A"),
            "Times_Submitted":  str(result.get("times_submitted", "N/A")),
            "Unique_Sources":   str(result.get("unique_sources",  "N/A")),
            # ── Sigma rules ───────────────────────────────────
            "Sigma_Critical": str(result.get("sigma_critical", "N/A")),
            "Sigma_High":     str(result.get("sigma_high",     "N/A")),
            "Sigma_Medium":   str(result.get("sigma_medium",   "N/A")),
            "Sigma_Low":      str(result.get("sigma_low",      "N/A")),
            # ── Crowdsourced IDS ──────────────────────────────
            "IDS_High":        str(result.get("ids_high",   "N/A")),
            "IDS_Medium":      str(result.get("ids_medium", "N/A")),
            "IDS_Low":         str(result.get("ids_low",    "N/A")),
            "IDS_High_Alerts": result.get("ids_high_alerts", "N/A"),
            # ── Sandbox ───────────────────────────────────────
            "Sandbox_Summary": result.get("sandbox_summary", "N/A"),
            # ── PE / Packer ───────────────────────────────────
            "Imphash":         result.get("imphash",      "N/A"),
            "Authentihash":    result.get("authentihash", "N/A"),
            "Compiler_Packer": result.get("compiler",     "N/A"),
            "TrID_Top":        result.get("trid_top",     "N/A"),
            # ── Links & errors ────────────────────────────────
            "VT_Link": result.get("vt_link", "N/A"),
            "Error":   result.get("error",   ""),
        }
        report_data.append(row)

        # Respect VT free-tier rate limit (4 req/min) between requests
        if idx < total:
            if log_callback:
                log_callback(
                    f"      [Rate limit] Waiting {VT_REQUEST_DELAY}s before next request...\n"
                )
            time.sleep(VT_REQUEST_DELAY)

    # Write CSV
    if output_dir and report_data:
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, "vt_report.csv")
        fieldnames = [
            # Identity
            "File", "SHA256", "MD5", "SHA1",
            "Meaningful_Name", "Known_Names", "File_Size",
            "Type_Description", "Magic", "Type_Tag",
            # Detection
            "Found_in_VT", "Verdict",
            "Malicious", "Suspicious", "Harmless", "Undetected",
            "Timeout", "Failures", "Total_Engines",
            # Reputation
            "VT_Reputation", "Community_Malicious", "Community_Harmless",
            # Threat
            "Threat_Label", "Threat_Category", "Threat_Name", "Tags",
            # Timeline
            "First_Submitted", "Last_Submitted", "Last_Analyzed",
            "Times_Submitted", "Unique_Sources",
            # Sigma
            "Sigma_Critical", "Sigma_High", "Sigma_Medium", "Sigma_Low",
            # IDS
            "IDS_High", "IDS_Medium", "IDS_Low", "IDS_High_Alerts",
            # Sandbox
            "Sandbox_Summary",
            # PE / Packer
            "Imphash", "Authentihash", "Compiler_Packer", "TrID_Top",
            # Links
            "VT_Link", "Error",
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(report_data)

        if log_callback:
            log_callback(f"\n[OK] VT report written to {csv_path}\n")

    return report_data



# Main (ADS scan CLI entry-point)

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