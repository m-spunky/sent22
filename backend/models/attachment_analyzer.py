"""
Attachment Security Analyzer — two-tier inspection:

Tier 1 (metadata)   — always runs: extension risk, MIME cross-check,
                       double-extension, suspicious filename keywords, size.

Tier 2 (content)    — runs when bytes are available:
  Documents  — magic-byte verification, PDF JS/action/URL scanning,
               Office macro (VBA AutoOpen/Shell/dropper), OOXML deep
               inspection, RTF OLE/Equation Editor exploit, ZIP contents, LNK.
  Images     — JPEG/PNG/GIF appended payload, EXIF URL extraction,
               PNG hidden text chunks, polyglot (image+ZIP/EXE) detection.
  SVG        — embedded <script>, javascript: URIs, event handlers,
               external href references, <foreignObject>.
  Video      — MP4/MOV atom inspection, metadata URL extraction,
               polyglot header detection, appended archive detection.
"""
import re
import io
import zipfile
import logging

logger = logging.getLogger(__name__)

# ── Extension risk tables ──────────────────────────────────────────────────────

_CRITICAL_EXTS = {
    "exe", "bat", "cmd", "com", "pif", "scr", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "msp", "ps1", "ps2", "reg", "dll", "hta",
    "jar", "apk", "bin", "run", "sh", "bash", "elf", "dex",
}

_HIGH_EXTS = {
    "zip", "rar", "7z", "tar", "gz", "iso", "img", "lnk", "cab",
    "docm", "xlsm", "pptm", "dotm", "xltm", "potm",
}

_MEDIUM_EXTS = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "pdf", "rtf", "odt", "ods", "odp",
}

_IMAGE_EXTS = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif", "ico"}
_SVG_EXTS   = {"svg", "svgz"}
_VIDEO_EXTS = {"mp4", "m4v", "mov", "avi", "mkv", "wmv", "flv", "webm", "3gp", "3g2", "f4v"}

# All extensions worth downloading bytes for content scanning
_CONTENT_SCAN_EXTS = _CRITICAL_EXTS | _HIGH_EXTS | _MEDIUM_EXTS | _IMAGE_EXTS | _SVG_EXTS | _VIDEO_EXTS

_SUSPICIOUS_NAME_RE = re.compile(
    r"invoice|receipt|payment|urgent|account|verify|confirm|"
    r"statement|refund|password|credential|bank|wire.?transfer|"
    r"reward|prize|notification|overdue|reminder",
    re.IGNORECASE,
)

_MIME_EXECUTABLE = {
    "application/x-msdownload", "application/x-executable",
    "application/x-msdos-program", "application/octet-stream",
}

# Max bytes to download per attachment for content scanning (5 MB)
MAX_SCAN_BYTES = 5 * 1024 * 1024


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ext(filename: str) -> str:
    parts = filename.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


# ── Tier 2: Content inspection routines ───────────────────────────────────────

# Known magic-byte signatures: ext → (expected_prefix, offset)
_MAGIC = {
    # Documents
    "pdf":  (b"%PDF", 0),
    "exe":  (b"MZ", 0),
    "dll":  (b"MZ", 0),
    "zip":  (b"PK\x03\x04", 0),
    "jar":  (b"PK\x03\x04", 0),
    "rar":  (b"Rar!", 0),
    "7z":   (b"7z\xbc\xaf\x27\x1c", 0),
    "doc":  (b"\xd0\xcf\x11\xe0", 0),
    "xls":  (b"\xd0\xcf\x11\xe0", 0),
    "ppt":  (b"\xd0\xcf\x11\xe0", 0),
    "docx": (b"PK\x03\x04", 0),
    "xlsx": (b"PK\x03\x04", 0),
    "pptx": (b"PK\x03\x04", 0),
    "rtf":  (b"{\\rtf", 0),
    # Images
    "jpg":  (b"\xff\xd8\xff", 0),
    "jpeg": (b"\xff\xd8\xff", 0),
    "png":  (b"\x89PNG\r\n\x1a\n", 0),
    "gif":  (b"GIF8", 0),
    "bmp":  (b"BM", 0),
    "webp": (b"RIFF", 0),   # RIFF....WEBP
    "tiff": (b"II*\x00", 0),  # little-endian; big-endian is b"MM\x00*"
    # Video
    "mp4":  (b"ftyp", 4),   # 4-byte size then 'ftyp'
    "m4v":  (b"ftyp", 4),
    "mov":  (b"ftyp", 4),
    "avi":  (b"RIFF", 0),
    "flv":  (b"FLV\x01", 0),
    "wmv":  (b"\x30\x26\xb2\x75", 0),
}

_OLE_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _check_magic(data: bytes, ext: str) -> list[str]:
    findings = []
    sig = _MAGIC.get(ext)
    if sig:
        expected, off = sig
        if data[off: off + len(expected)] != expected:
            findings.append(
                f"Signature mismatch: .{ext} file header doesn't match expected magic bytes "
                f"— may be disguised as {ext}"
            )
    # Any non-executable claiming to be a doc but starting with MZ = PE executable
    if ext not in {"exe", "dll", "com", "scr", "pif"} and data[:2] == b"MZ":
        findings.append(
            "File begins with PE/MZ header — executable binary disguised as a document"
        )
    return findings


def _extract_pdf_urls(data: bytes) -> list[str]:
    """Extract all outgoing URLs from raw PDF bytes (URI annotations + plain text)."""
    chunk = data[:2_000_000].decode("latin-1", errors="ignore")
    found = []
    # /URI annotations (clickable links)
    found += re.findall(r"/URI\s*\(([^)]{8,200})\)", chunk)
    # Plain http/https references in body text or streams
    found += re.findall(r"https?://[^\s\)\>\"\\\x00-\x1f]{8,150}", chunk)
    # Deduplicate preserving order
    seen: set = set()
    result = []
    for u in found:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result[:15]


def _inspect_pdf(data: bytes) -> list[str]:
    findings = []
    chunk = data[:1_000_000]

    if b"/JS" in chunk or b"/JavaScript" in chunk:
        findings.append("PDF contains JavaScript — can execute code silently on open")
    if b"/OpenAction" in chunk:
        findings.append("PDF has /OpenAction — triggers automatically when opened")
    if b"/AA" in chunk:
        findings.append("PDF has Additional Actions (/AA) — auto-trigger on various events")
    if b"/Launch" in chunk:
        findings.append("PDF contains /Launch action — can spawn external programs")
    if b"/EmbeddedFile" in chunk or b"/FileSpec" in chunk:
        findings.append("PDF has embedded file(s) — potential hidden payload")
    if b"/Encrypt" in chunk:
        findings.append("PDF is encrypted — commonly used to bypass AV scanners")
    if chunk.count(b"/ObjStm") > 0:
        findings.append("PDF uses object streams — can conceal malicious objects from parsers")
    if b"/AcroForm" in chunk and b"/JS" in chunk:
        findings.append("PDF AcroForm with JavaScript — interactive phishing form")

    # URL extraction from annotations and body text
    urls = _extract_pdf_urls(data)
    if urls:
        suspicious_tlds = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".work", ".click"}
        sus_urls = [u for u in urls if any(t in u.lower() for t in suspicious_tlds)]
        if sus_urls:
            findings.append(f"PDF links to suspicious domain(s): {sus_urls[0][:80]}")
        elif len(urls) > 5:
            findings.append(f"PDF contains {len(urls)} outgoing URLs — review for phishing redirects")
        else:
            findings.append(f"PDF outgoing URL(s): {urls[0][:80]}")

    return findings


def _inspect_ooxml(data: bytes, filename: str) -> list[str]:
    """OOXML Office files (docx/xlsx/pptx) are ZIP archives."""
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()

            # VBA macro project
            if any("vbaProject.bin" in n for n in names):
                findings.append(
                    "Contains vbaProject.bin — VBA macros embedded; macros can execute "
                    "system commands and download payloads"
                )
                # Try to peek inside for auto-run triggers
                try:
                    vba_bytes = zf.read(next(n for n in names if "vbaProject.bin" in n))
                    if b"AutoOpen" in vba_bytes or b"Document_Open" in vba_bytes or b"Auto_Open" in vba_bytes:
                        findings.append("VBA macro has auto-execute trigger (AutoOpen/Document_Open)")
                    if b"Shell" in vba_bytes or b"WScript" in vba_bytes:
                        findings.append("VBA macro references Shell/WScript — can run OS commands")
                    if b"powershell" in vba_bytes.lower() or b"cmd.exe" in vba_bytes.lower():
                        findings.append("VBA macro references PowerShell/cmd.exe — likely malware dropper")
                except Exception:
                    pass

            # External relationships (phone-home / template injection)
            for rel_name in [n for n in names if n.endswith(".rels")][:8]:
                try:
                    rel_content = zf.read(rel_name).decode("utf-8", errors="ignore")
                    if 'Type="External"' in rel_content or "TargetMode=\"External\"" in rel_content:
                        if "http" in rel_content or "ftp" in rel_content:
                            findings.append(
                                f"External relationship in {rel_name} — document fetches remote content on open "
                                f"(template injection / macro delivery)"
                            )
                            break
                except Exception:
                    pass

            # ActiveX controls
            if any("activeX" in n.lower() for n in names):
                findings.append("Contains ActiveX controls — can execute arbitrary code without macro prompts")

            # Embedded executables inside the Office ZIP
            inner_exec = [n for n in names if _ext(n) in _CRITICAL_EXTS]
            if inner_exec:
                findings.append(
                    f"Executable embedded inside Office file: {', '.join(inner_exec[:3])}"
                )

    except zipfile.BadZipFile:
        if _ext(filename) in {"docx", "xlsx", "pptx"}:
            findings.append("OOXML file is not a valid ZIP archive — corrupted or misidentified format")
    except Exception as exc:
        logger.debug(f"[AttachAnalyzer] OOXML inspect error: {exc}")
    return findings


def _inspect_ole(data: bytes) -> list[str]:
    """Binary OLE2 Office (doc/xls/ppt) — scan raw bytes for VBA indicators."""
    findings = []
    if data[:8] != _OLE_SIG:
        return findings

    sample = data[:300_000]
    if b"VBA" in sample or b"_VBA_PROJECT" in sample:
        findings.append("Binary Office file contains VBA macro code")
    if b"AutoOpen" in sample or b"Auto_Open" in sample or b"Document_Open" in sample:
        findings.append("Macro auto-execute trigger detected (AutoOpen/Document_Open)")
    if b"Shell" in sample and b"VBA" in sample:
        findings.append("Macro references Shell() — can execute OS commands")
    if b"WScript" in sample or b"powershell" in sample.lower()[:300_000]:
        findings.append("Macro references WScript/PowerShell — likely script dropper")
    if b"URLDownloadToFile" in sample or b"WinHttpRequest" in sample:
        findings.append("Macro contains download function — fetches remote payload")
    return findings


def _inspect_rtf(data: bytes) -> list[str]:
    findings = []
    if not data[:6].startswith(b"{\\rtf"):
        return findings

    sample = data[:500_000]
    if b"\\objdata" in sample or b"\\object" in sample:
        findings.append("RTF contains embedded OLE object — common exploit delivery vector (e.g. CVE-2017-11882)")
    if b"\\objocx" in sample:
        findings.append("RTF contains OCX/ActiveX object — can execute code without prompts")
    # Equation Editor exploit indicator
    if b"Equation.3" in sample or b"equation.3" in sample.lower():
        findings.append(
            "RTF references Equation Editor (CVE-2017-11882) — critical RCE exploit widely used in phishing"
        )
    if b"\\pict" in sample and b"\\wmetafile" in sample:
        findings.append("RTF contains Windows Metafile image (WMF) — historically exploitable")
    # Hex-encoded shellcode indicators (long hex strings in objdata)
    if b"\\objdata" in sample:
        hex_blobs = re.findall(rb"\\objdata\s+([0-9a-fA-F]{200,})", sample)
        if hex_blobs:
            findings.append("RTF OLE object contains large hex-encoded payload — high shellcode risk")
    return findings


def _inspect_zip(data: bytes) -> list[str]:
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            inner = zf.namelist()

            dangerous = [n for n in inner if _ext(n) in _CRITICAL_EXTS]
            if dangerous:
                findings.append(f"Archive contains dangerous file(s): {', '.join(dangerous[:5])}")

            macro_office = [n for n in inner if _ext(n) in {"docm", "xlsm", "pptm"}]
            if macro_office:
                findings.append(f"Archive contains macro-enabled Office file(s): {', '.join(macro_office[:3])}")

            if len(inner) == 0:
                findings.append("Empty archive — may be a dropper placeholder awaiting stage-2")

            # Password-protected entries
            for info in zf.infolist()[:10]:
                if info.flag_bits & 0x1:
                    findings.append("Password-protected archive — evades automated content scanners")
                    break

            # Zip-slip path traversal
            for name in inner:
                if ".." in name or name.startswith("/"):
                    findings.append(f"Zip-slip path traversal entry: '{name}' — directory escape attack")
                    break

    except zipfile.BadZipFile:
        pass
    except Exception as exc:
        logger.debug(f"[AttachAnalyzer] ZIP inspect error: {exc}")
    return findings


def _inspect_lnk(data: bytes) -> list[str]:
    """Parse Windows .lnk (Shell Link) binary for suspicious command targets."""
    findings = []
    # LNK magic: 4C 00 00 00
    if len(data) < 76 or data[:4] != b"\x4c\x00\x00\x00":
        return findings

    sample = data[:8192].lower()
    dangerous_cmds = [b"powershell", b"cmd.exe", b"wscript", b"cscript",
                      b"mshta", b"regsvr32", b"rundll32", b"certutil"]
    for cmd in dangerous_cmds:
        if cmd in sample:
            findings.append(
                f"LNK shortcut executes '{cmd.decode()}' — runs system command on double-click"
            )
    if b"http://" in sample or b"https://" in sample:
        findings.append("LNK shortcut references remote URL — may download and execute payload")
    if b"\\\\" in data[:8192]:
        findings.append("LNK references UNC network path — may execute code from attacker-controlled share")
    return findings


# ── Image inspection ──────────────────────────────────────────────────────────

def _inspect_image(data: bytes, ext: str) -> list[str]:
    findings = []

    # 1. Polyglot: image that's also an executable or archive
    if data[:2] == b"MZ":
        findings.append("Image file starts with PE/MZ header — executable disguised as image (polyglot)")
    if data[:4] == b"PK\x03\x04":
        findings.append("Image file starts with ZIP signature — polyglot file (image + hidden archive)")

    # 2. Appended data after image end-of-file marker
    if ext in {"jpg", "jpeg"}:
        eoi = data.rfind(b"\xff\xd9")
        if eoi != -1 and eoi < len(data) - 2:
            appended = len(data) - eoi - 2
            if appended > 512:
                findings.append(
                    f"JPEG has {appended:,} bytes after EOI marker — possible steganographic payload appended"
                )
    elif ext == "png":
        iend = data.rfind(b"IEND\xaeB`\x82")
        if iend != -1 and iend + 8 < len(data):
            appended = len(data) - iend - 8
            if appended > 256:
                findings.append(
                    f"PNG has {appended:,} bytes after IEND chunk — possible steganographic payload appended"
                )
    elif ext == "gif":
        trailer = data.rfind(b"\x3b")  # GIF trailer byte
        if trailer != -1 and trailer < len(data) - 1:
            appended = len(data) - trailer - 1
            if appended > 256:
                findings.append(
                    f"GIF has {appended:,} bytes after trailer — possible hidden data"
                )

    # 3. EXIF URL and script extraction (JPEG App1 marker)
    if ext in {"jpg", "jpeg"}:
        exif_pos = data.find(b"\xff\xe1")
        if exif_pos != -1:
            exif_raw = data[exif_pos: exif_pos + 65536].decode("latin-1", errors="ignore")
            urls = re.findall(r"https?://[^\x00-\x1f\s\"'<>]{10,100}", exif_raw)
            if urls:
                findings.append(
                    f"EXIF metadata contains URL: {urls[0][:70]} — possible tracking pixel or redirect"
                )
            if "javascript" in exif_raw.lower() or "<script" in exif_raw.lower():
                findings.append("EXIF metadata contains script content — possible injection attempt")

    # 4. PNG suspicious text chunks (tEXt / zTXt / iTXt)
    if ext == "png" and len(data) > 8:
        pos = 8
        while pos < len(data) - 12:
            try:
                chunk_len = int.from_bytes(data[pos: pos + 4], "big")
                chunk_type = data[pos + 4: pos + 8]
                if chunk_type in {b"tEXt", b"zTXt", b"iTXt"}:
                    chunk_text = data[pos + 8: pos + 8 + min(chunk_len, 4096)].decode("latin-1", errors="ignore")
                    if any(x in chunk_text.lower() for x in ["http", "javascript", "eval(", "<script"]):
                        findings.append(
                            f"PNG {chunk_type.decode()} chunk contains suspicious content (URL/script)"
                        )
                        break
                    if chunk_len > 100_000:
                        findings.append(
                            f"PNG {chunk_type.decode()} chunk is unusually large ({chunk_len:,} bytes) "
                            f"— possible steganographic storage"
                        )
                        break
                if chunk_len == 0 or pos + 4 + 4 + chunk_len + 4 > len(data):
                    break
                pos += 4 + 4 + chunk_len + 4
            except Exception:
                break

    # 5. BMP: check for appended data (BMP has fixed size in header)
    if ext == "bmp" and len(data) >= 14:
        declared = int.from_bytes(data[2:6], "little")
        if declared < len(data) and len(data) - declared > 512:
            findings.append(
                f"BMP file header declares {declared:,} bytes but file is {len(data):,} bytes "
                f"— {len(data) - declared:,} bytes of hidden data"
            )

    return findings


# ── SVG inspection ─────────────────────────────────────────────────────────────

def _inspect_svg(data: bytes) -> list[str]:
    """SVG files are XML — scan for embedded scripts and external references."""
    findings = []
    try:
        text = data[:500_000].decode("utf-8", errors="ignore")
        tl = text.lower()

        if "<script" in tl:
            findings.append("SVG contains <script> element — executes JavaScript when rendered in a browser")
        if "javascript:" in tl:
            findings.append("SVG contains javascript: URI — triggers script execution on click/render")

        for handler in ["onload", "onclick", "onmouseover", "onerror", "onfocus", "onanimationstart"]:
            if handler in tl:
                findings.append(
                    f"SVG has '{handler}' event handler — auto-executes code when image is rendered"
                )
                break

        if "xlink:href" in tl or 'href="http' in tl or 'src="http' in tl:
            findings.append(
                "SVG references external URL — loads remote content on render (SSRF / tracking risk)"
            )
        if "<use" in tl and "href" in tl:
            findings.append(
                "SVG <use> with href — can load and execute content from external SVG documents"
            )
        if "foreignobject" in tl:
            findings.append(
                "SVG <foreignObject> embeds arbitrary HTML — can host phishing forms or scripts"
            )
        if "<iframe" in tl or "<embed" in tl:
            findings.append(
                "SVG contains <iframe>/<embed> — embeds external page content"
            )
    except Exception:
        pass
    return findings


# ── Video inspection ───────────────────────────────────────────────────────────

def _inspect_mp4_atoms(data: bytes) -> list[str]:
    """Walk MP4/MOV box structure for anomalies and embedded metadata URLs."""
    findings = []
    try:
        pos = 0
        ftyp_seen = False
        moov_seen = False
        known_brands = {
            b"mp41", b"mp42", b"isom", b"M4V ", b"M4A ", b"M4P ",
            b"f4v ", b"avc1", b"qt  ", b"3gp5", b"3gp6", b"3gp4",
        }
        while pos < min(len(data), 1_000_000):
            if pos + 8 > len(data):
                break
            box_size = int.from_bytes(data[pos: pos + 4], "big")
            box_type = data[pos + 4: pos + 8]
            if box_size < 8:
                break
            if box_type == b"ftyp":
                ftyp_seen = True
                brand = data[pos + 8: pos + 12]
                if brand not in known_brands:
                    findings.append(
                        f"Unusual MP4 ftyp brand '{brand.decode('latin-1', errors='replace')}' "
                        f"— may not be a legitimate video file"
                    )
            elif box_type == b"moov":
                moov_seen = True
            elif box_type == b"udta":
                udta_text = data[pos + 8: pos + min(pos + box_size, pos + 8 + 8192)].decode("latin-1", errors="ignore")
                urls = re.findall(r"https?://\S{10,100}", udta_text)
                if urls:
                    findings.append(
                        f"MP4 user data (udta) contains URL: {urls[0][:70]}"
                    )
            pos += box_size
        if not ftyp_seen and not moov_seen:
            findings.append("MP4 file is missing required ftyp/moov boxes — invalid or crafted container")
    except Exception:
        pass
    return findings


def _inspect_video(data: bytes, ext: str) -> list[str]:
    findings = []

    # Polyglot: video that's also another format
    if data[:2] == b"MZ":
        findings.append("Video file starts with PE/MZ header — executable disguised as video")
    if data[:4] == b"PK\x03\x04":
        findings.append("Video file starts with ZIP signature — polyglot file (video + hidden archive)")

    # MP4 / MOV / M4V / 3GP container
    if ext in {"mp4", "m4v", "mov", "3gp", "3g2"}:
        findings.extend(_inspect_mp4_atoms(data))

    # AVI: must start RIFF....AVI
    elif ext == "avi":
        if not (data[:4] == b"RIFF" and data[8:12] == b"AVI "):
            findings.append("AVI file has invalid RIFF/AVI header — file may be misidentified")

    # FLV: starts FLV\x01
    elif ext == "flv":
        if data[:4] != b"FLV\x01":
            findings.append("FLV file has invalid header — may be disguised as Flash video")

    # WMV/ASF: starts 30 26 B2 75 (ASF header GUID)
    elif ext == "wmv":
        if data[:4] != b"\x30\x26\xb2\x75":
            findings.append("WMV/ASF file has invalid header")

    # Check for ZIP archive appended to end of any video
    if len(data) > 10_000:
        tail = data[-65536:]
        zip_pos = tail.rfind(b"PK\x03\x04")
        if zip_pos != -1:
            findings.append(
                "ZIP archive signature found near end of video file — possible appended hidden archive"
            )

    return findings


# ── Tier 1: Metadata-only analysis ────────────────────────────────────────────

def analyze_attachment(filename: str, mime_type: str = "", size_bytes: int = 0) -> dict:
    """Tier 1 — metadata heuristics only (no bytes needed)."""
    ext = _ext(filename)
    findings = []
    risk = 0.0

    if ext in _CRITICAL_EXTS:
        risk = 0.97
        findings.append(f"Executable file type (.{ext}) — never open attachments of this type")
    elif ext in _HIGH_EXTS:
        risk = 0.72
        if ext in {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}:
            findings.append(f"Macro-enabled Office format (.{ext}) — macros auto-execute code on open")
        else:
            findings.append(f"Archive/compressed file (.{ext}) — may conceal malicious files")
    elif ext in _MEDIUM_EXTS:
        risk = 0.22
        findings.append(f"Document (.{ext}) — can carry embedded exploits; verify sender before opening")
    elif ext in _SVG_EXTS:
        risk = 0.45
        findings.append(f"SVG image (.{ext}) — can contain embedded JavaScript and external references")
    elif ext in _IMAGE_EXTS:
        risk = 0.05
        findings.append(f"Image file (.{ext}) — scanning for steganography and polyglot indicators")
    elif ext in _VIDEO_EXTS:
        risk = 0.08
        findings.append(f"Video file (.{ext}) — scanning for polyglot and metadata anomalies")

    if mime_type:
        ml = mime_type.lower()
        if ml in _MIME_EXECUTABLE or "executable" in ml or "x-msdownload" in ml:
            risk = max(risk, 0.97)
            findings.append(f"Executable MIME type declared: {mime_type}")
        elif "zip" in ml or "compressed" in ml or "rar" in ml:
            risk = max(risk, 0.55)

    # Double-extension attack  (report.pdf.exe)
    parts = filename.split(".")
    if len(parts) > 2 and parts[-1].lower() in _CRITICAL_EXTS:
        risk = max(risk, 0.97)
        findings.append(
            f"Double-extension attack: disguised as .{parts[-2]} but actually .{parts[-1]}"
        )

    if _SUSPICIOUS_NAME_RE.search(filename):
        risk = min(risk + 0.18, 0.93)
        findings.append(f"Suspicious filename '{filename}' — matches common phishing lure patterns")

    if size_bytes > 10 * 1024 * 1024:
        findings.append(f"Unusually large attachment ({round(size_bytes/1024/1024, 1)} MB)")

    if not findings:
        findings.append(f".{ext or 'unknown'} — no metadata-level threats detected")

    risk_level = (
        "CRITICAL" if risk >= 0.85 else
        "HIGH"     if risk >= 0.65 else
        "MEDIUM"   if risk >= 0.35 else
        "LOW"      if risk >  0.05 else
        "CLEAN"
    )
    return {
        "filename": filename,
        "extension": ext or "none",
        "mime_type": mime_type or "unknown",
        "size_bytes": size_bytes,
        "risk_score": round(risk, 3),
        "risk_level": risk_level,
        "findings": findings,
        "content_scanned": False,
    }


# ── Tier 2: Full content inspection ───────────────────────────────────────────

def analyze_attachment_bytes(
    filename: str,
    mime_type: str,
    size_bytes: int,
    data: bytes,
) -> dict:
    """
    Tier 2 — deep content inspection.
    Runs all content-level checks and merges with Tier 1 metadata analysis.
    """
    base = analyze_attachment(filename, mime_type, size_bytes)
    ext = _ext(filename)

    if not data:
        return base

    content_findings: list[str] = []

    # 1. Magic-byte verification (all types)
    content_findings.extend(_check_magic(data, ext))

    # 2. Type-specific deep scan
    if ext == "pdf":
        content_findings.extend(_inspect_pdf(data))
    elif ext in {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm", "potm"}:
        content_findings.extend(_inspect_ooxml(data, filename))
    elif ext in {"doc", "xls", "ppt"}:
        content_findings.extend(_inspect_ole(data))
    elif ext == "rtf":
        content_findings.extend(_inspect_rtf(data))
    elif ext in {"zip", "jar", "cab"}:
        content_findings.extend(_inspect_zip(data))
    elif ext == "lnk":
        content_findings.extend(_inspect_lnk(data))
    elif ext in _IMAGE_EXTS:
        content_findings.extend(_inspect_image(data, ext))
    elif ext in _SVG_EXTS:
        content_findings.extend(_inspect_svg(data))
    elif ext in _VIDEO_EXTS:
        content_findings.extend(_inspect_video(data, ext))

    if not content_findings:
        return {**base, "content_scanned": True}

    # Content evidence is authoritative — boost risk score
    boost = 0.20 * min(len(content_findings), 3)
    new_risk = round(min(base["risk_score"] + boost, 0.99), 3)
    new_level = (
        "CRITICAL" if new_risk >= 0.85 else
        "HIGH"     if new_risk >= 0.65 else
        "MEDIUM"   if new_risk >= 0.35 else
        "LOW"
    )
    # Put content findings first (higher signal)
    merged = content_findings + [f for f in base["findings"] if "no metadata-level" not in f]

    return {
        **base,
        "risk_score": new_risk,
        "risk_level": new_level,
        "findings": merged,
        "content_scanned": True,
    }


# ── Batch helpers ──────────────────────────────────────────────────────────────

def analyze_attachments(attachments: list) -> dict:
    """Tier 1 batch — metadata only. Used when bytes aren't available."""
    if not attachments:
        return {"count": 0, "max_risk": 0.0, "results": [], "verdict": "NO_ATTACHMENTS"}

    results = [
        analyze_attachment(a.get("filename", "unknown"), a.get("mime_type", ""), a.get("size_bytes", 0))
        for a in attachments
    ]
    return _build_summary(results)


def analyze_attachments_with_bytes(attachments_with_data: list) -> dict:
    """
    Tier 2 batch — each item is a dict with keys:
      filename, mime_type, size_bytes, data (bytes | None)
    Falls back to Tier 1 when data is None.
    """
    if not attachments_with_data:
        return {"count": 0, "max_risk": 0.0, "results": [], "verdict": "NO_ATTACHMENTS"}

    results = []
    for a in attachments_with_data:
        data = a.get("data")
        if data:
            results.append(
                analyze_attachment_bytes(
                    a.get("filename", "unknown"),
                    a.get("mime_type", ""),
                    a.get("size_bytes", 0),
                    data,
                )
            )
        else:
            results.append(
                analyze_attachment(a.get("filename", "unknown"), a.get("mime_type", ""), a.get("size_bytes", 0))
            )
    return _build_summary(results)


def _build_summary(results: list) -> dict:
    max_risk = max((r["risk_score"] for r in results), default=0.0)
    verdict = (
        "CRITICAL"  if max_risk >= 0.85 else
        "HIGH_RISK" if max_risk >= 0.65 else
        "SUSPICIOUS" if max_risk >= 0.35 else
        "LOW_RISK"  if max_risk >  0.05 else
        "CLEAN"
    )
    scanned = sum(1 for r in results if r.get("content_scanned"))
    return {
        "count": len(results),
        "max_risk": round(max_risk, 3),
        "results": results,
        "verdict": verdict,
        "content_scanned_count": scanned,
    }
