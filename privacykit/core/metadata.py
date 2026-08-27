"""
Metadata scrubbing — stripping the story a file tells about you.

The problem is concrete: a photo straight off a phone carries GPS coordinates
accurate to a few metres, the device model, the serial number on some cameras,
and the exact timestamp. A Word document carries the author name, the
organisation, total editing time, and often the name of everyone who revised
it. People share these files believing they are sharing only the visible
content.

Implemented without third-party libraries:

* **JPEG** — parse the segment structure and drop APP1 (EXIF and XMP), APP13
  (IPTC/Photoshop), and COM comment segments, keeping the image data untouched.
  This is lossless: the pixels are never re-encoded, so there is no quality loss.
* **PNG** — drop tEXt, zTXt, iTXt, eXIf, and tIME chunks, recomputing nothing
  because PNG chunks carry their own CRCs and the rest are left byte-identical.
* **Office (.docx/.xlsx/.pptx)** — these are ZIP containers; rebuild them
  without ``docProps/core.xml`` and ``docProps/app.xml``.
* **PDF** — reported rather than stripped. Doing it properly means rewriting the
  cross-reference table, and a half-rewritten PDF is a corrupt PDF. If pypdf is
  installed it is used; otherwise the file is flagged with an explanation.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

SUPPORTED_STRIP = {".jpg", ".jpeg", ".png", ".docx", ".xlsx", ".pptx"}
SUPPORTED_READ = SUPPORTED_STRIP | {".pdf", ".gif", ".webp", ".tiff", ".tif"}


@dataclass
class MetadataReport:
    path: str
    file_type: str = ""
    findings: Dict[str, str] = field(default_factory=dict)
    has_gps: bool = False
    strippable: bool = False
    note: str = ""

    @property
    def count(self) -> int:
        return len(self.findings)

    def summary(self) -> str:
        if not self.findings:
            return "No metadata found."
        bits = f"{self.count} metadata field(s)"
        if self.has_gps:
            bits += " — including GPS location"
        return bits


# ──────────────────────────────────────────────────────────────────────────────
# Inspection
# ──────────────────────────────────────────────────────────────────────────────

def inspect(path: str) -> MetadataReport:
    """Report what metadata a file carries, without modifying it."""
    p = Path(path)
    rep = MetadataReport(path=str(p), file_type=p.suffix.lower())
    if not p.is_file():
        rep.note = "File not found."
        return rep

    ext = p.suffix.lower()
    try:
        if ext in (".jpg", ".jpeg"):
            _inspect_jpeg(p, rep)
        elif ext == ".png":
            _inspect_png(p, rep)
        elif ext in (".docx", ".xlsx", ".pptx"):
            _inspect_office(p, rep)
        elif ext == ".pdf":
            _inspect_pdf(p, rep)
        else:
            rep.note = f"No inspector for '{ext}' files."
    except Exception as exc:
        rep.note = f"Could not read metadata: {type(exc).__name__}: {exc}"

    rep.strippable = ext in SUPPORTED_STRIP
    return rep


def _inspect_jpeg(p: Path, rep: MetadataReport) -> None:
    data = p.read_bytes()
    if data[:2] != b"\xFF\xD8":
        rep.note = "Not a valid JPEG."
        return
    pos = 2
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xDA:      # start of scan — image data follows
            break
        if pos + 4 > len(data):
            break
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        segment = data[pos + 4:pos + 2 + seg_len]

        if marker == 0xE1:
            if segment.startswith(b"Exif\x00\x00"):
                rep.findings["EXIF block"] = f"{len(segment)} bytes"
                _parse_exif(segment[6:], rep)
            elif b"xmpmeta" in segment[:200] or segment.startswith(b"http://ns.adobe.com/xap"):
                rep.findings["XMP metadata"] = f"{len(segment)} bytes (Adobe XMP)"
        elif marker == 0xED:
            rep.findings["IPTC / Photoshop data"] = f"{len(segment)} bytes"
        elif marker == 0xFE:
            try:
                rep.findings["Embedded comment"] = segment.decode("utf-8", "replace")[:120]
            except Exception:
                rep.findings["Embedded comment"] = f"{len(segment)} bytes"
        elif marker == 0xE2 and segment.startswith(b"ICC_PROFILE"):
            rep.findings["ICC colour profile"] = f"{len(segment)} bytes"

        pos += 2 + seg_len


#: The EXIF tags worth surfacing by name — the ones that identify a person.
_EXIF_TAGS = {
    0x010F: "Camera make", 0x0110: "Camera model", 0x0131: "Software",
    0x0132: "Date/time", 0x013B: "Artist", 0x8298: "Copyright",
    0x9003: "Original date/time", 0x9004: "Digitised date/time",
    0xA430: "Camera owner name", 0xA431: "Body serial number",
    0xA433: "Lens make", 0xA434: "Lens model", 0xA435: "Lens serial number",
    0x8825: "GPS data",
}


def _parse_exif(tiff: bytes, rep: MetadataReport) -> None:
    """Minimal TIFF/EXIF IFD walk — enough to name what is present."""
    if len(tiff) < 8:
        return
    endian = "<" if tiff[:2] == b"II" else ">" if tiff[:2] == b"MM" else None
    if endian is None:
        return
    try:
        offset = struct.unpack(endian + "I", tiff[4:8])[0]
        if offset + 2 > len(tiff):
            return
        count = struct.unpack(endian + "H", tiff[offset:offset + 2])[0]
        for i in range(min(count, 100)):
            base = offset + 2 + i * 12
            if base + 12 > len(tiff):
                break
            tag, typ, num = struct.unpack(endian + "HHI", tiff[base:base + 8])
            name = _EXIF_TAGS.get(tag)
            if not name:
                continue
            if tag == 0x8825:
                rep.has_gps = True
                rep.findings["GPS location"] = ("present — the exact coordinates "
                                                "where this was taken")
                continue
            value = ""
            if typ == 2:  # ASCII
                val_off = struct.unpack(endian + "I", tiff[base + 8:base + 12])[0]
                if num <= 4:
                    value = tiff[base + 8:base + 8 + num].decode("ascii", "replace")
                elif val_off + num <= len(tiff):
                    value = tiff[val_off:val_off + num].decode("ascii", "replace")
                value = value.strip("\x00 ")
            if value:
                rep.findings[name] = value
            else:
                rep.findings.setdefault(name, "present")
    except Exception:
        pass


def _inspect_png(p: Path, rep: MetadataReport) -> None:
    data = p.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        rep.note = "Not a valid PNG."
        return
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8].decode("ascii", "replace")
        body = data[pos + 8:pos + 8 + length]
        if ctype in ("tEXt", "zTXt", "iTXt"):
            try:
                key = body.split(b"\x00", 1)[0].decode("latin-1")
                rep.findings[f"Text chunk: {key}"] = f"{length} bytes"
            except Exception:
                rep.findings[f"Text chunk ({ctype})"] = f"{length} bytes"
        elif ctype == "eXIf":
            rep.findings["Embedded EXIF"] = f"{length} bytes"
            _parse_exif(body, rep)
        elif ctype == "tIME":
            rep.findings["Last modified time"] = f"{length} bytes"
        if ctype == "IEND":
            break
        pos += 12 + length


def _inspect_office(p: Path, rep: MetadataReport) -> None:
    import re
    try:
        with zipfile.ZipFile(p) as z:
            names = z.namelist()
            for part in ("docProps/core.xml", "docProps/app.xml"):
                if part not in names:
                    continue
                xml = z.read(part).decode("utf-8", "replace")
                for tag in ("dc:creator", "cp:lastModifiedBy", "dc:title",
                            "dc:subject", "dc:description", "cp:keywords",
                            "cp:lastPrinted", "dcterms:created",
                            "dcterms:modified", "cp:revision", "Company",
                            "Manager", "TotalTime", "Application"):
                    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml, re.S)
                    if m and m.group(1).strip():
                        label = {"dc:creator": "Author",
                                 "cp:lastModifiedBy": "Last modified by",
                                 "TotalTime": "Total editing time (minutes)",
                                 "cp:revision": "Revision number"}.get(tag, tag)
                        rep.findings[label] = m.group(1).strip()[:120]
    except zipfile.BadZipFile:
        rep.note = "Not a valid Office file (bad ZIP container)."


def _inspect_pdf(p: Path, rep: MetadataReport) -> None:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception:
        try:
            from PyPDF2 import PdfReader  # type: ignore
        except Exception:
            rep.note = ("PDF metadata reading needs the 'pypdf' package "
                        "(pip install pypdf). Without it PrivacyKit cannot "
                        "safely rewrite a PDF's cross-reference table.")
            _pdf_raw_peek(p, rep)
            return
    try:
        reader = PdfReader(str(p))
        meta = reader.metadata or {}
        for k, v in meta.items():
            rep.findings[str(k).lstrip("/")] = str(v)[:120]
        rep.strippable = True
    except Exception as exc:
        rep.note = f"Could not parse the PDF: {exc}"


def _pdf_raw_peek(p: Path, rep: MetadataReport) -> None:
    """Crude scan for an /Info dictionary when no PDF library is available."""
    import re
    try:
        blob = p.read_bytes()[:400_000]
        for key in (b"Author", b"Creator", b"Producer", b"Title", b"CreationDate"):
            m = re.search(rb"/" + key + rb"\s*\((.{0,120}?)\)", blob, re.S)
            if m:
                rep.findings[key.decode()] = m.group(1).decode("latin-1", "replace")
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Stripping
# ──────────────────────────────────────────────────────────────────────────────

def strip(path: str, output: Optional[str] = None,
          in_place: bool = False) -> tuple:
    """
    Remove metadata. Returns ``(ok, message, output_path)``.

    By default a cleaned copy is written alongside the original rather than
    overwriting it — the original may be the only copy, and a bug in a stripper
    that overwrites in place destroys data.
    """
    p = Path(path)
    if not p.is_file():
        return False, f"'{path}' is not a file.", ""

    ext = p.suffix.lower()
    if ext not in SUPPORTED_STRIP and ext != ".pdf":
        return False, f"Stripping '{ext}' files is not supported.", ""

    out = Path(output) if output else (p if in_place
                                       else p.with_name(f"{p.stem}_clean{p.suffix}"))
    try:
        if ext in (".jpg", ".jpeg"):
            cleaned = _strip_jpeg(p.read_bytes())
        elif ext == ".png":
            cleaned = _strip_png(p.read_bytes())
        elif ext in (".docx", ".xlsx", ".pptx"):
            return _strip_office(p, out)
        elif ext == ".pdf":
            return _strip_pdf(p, out)
        else:
            return False, "Unsupported file type.", ""
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", ""

    try:
        out.write_bytes(cleaned)
    except Exception as exc:
        return False, f"Could not write output: {exc}", ""

    saved = p.stat().st_size - len(cleaned)
    return True, (f"Metadata removed → {out.name} "
                  f"({saved:,} bytes of metadata stripped)."), str(out)


def _strip_jpeg(data: bytes) -> bytes:
    """Rebuild a JPEG without its metadata segments, leaving pixels untouched."""
    if data[:2] != b"\xFF\xD8":
        raise ValueError("not a JPEG")
    out = bytearray(b"\xFF\xD8")
    pos = 2
    # APP0 (JFIF) is kept: some decoders expect it. APP2 ICC profiles are kept
    # too, since dropping them changes how colours render.
    drop = {0xE1, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
            0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xFE}
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            out.append(data[pos])
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xDA:                     # image data — copy the rest verbatim
            out += data[pos:]
            break
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            out += data[pos:pos + 2]
            pos += 2
            continue
        if pos + 4 > len(data):
            out += data[pos:]
            break
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if marker not in drop:
            out += data[pos:pos + 2 + seg_len]
        pos += 2 + seg_len
    return bytes(out)


def _strip_png(data: bytes) -> bytes:
    """Rebuild a PNG without text/EXIF/time chunks."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    out = bytearray(data[:8])
    pos = 8
    drop = {"tEXt", "zTXt", "iTXt", "eXIf", "tIME", "pHYs"}
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8].decode("ascii", "replace")
        chunk = data[pos:pos + 12 + length]
        if ctype not in drop:
            out += chunk
        pos += 12 + length
        if ctype == "IEND":
            break
    return bytes(out)


def _strip_office(src: Path, out: Path) -> tuple:
    """Rebuild an Office file without its document-properties parts."""
    drop_prefixes = ("docProps/",)
    try:
        with zipfile.ZipFile(src) as zin:
            items = [(i, zin.read(i.filename)) for i in zin.infolist()]
        tmp = out.with_suffix(out.suffix + ".tmp")
        removed = 0
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for info, blob in items:
                if info.filename.startswith(drop_prefixes):
                    removed += 1
                    continue
                # Normalise timestamps too — the per-entry mtimes reveal when
                # the document was worked on.
                new_info = zipfile.ZipInfo(info.filename, date_time=(1980, 1, 1, 0, 0, 0))
                new_info.compress_type = zipfile.ZIP_DEFLATED
                new_info.external_attr = info.external_attr
                zout.writestr(new_info, blob)
        tmp.replace(out)
        return True, (f"Removed {removed} metadata part(s) and normalised "
                      f"timestamps → {out.name}"), str(out)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", ""


def _strip_pdf(src: Path, out: Path) -> tuple:
    try:
        from pypdf import PdfReader, PdfWriter  # type: ignore
    except Exception:
        try:
            from PyPDF2 import PdfReader, PdfWriter  # type: ignore
        except Exception:
            return False, ("Stripping PDF metadata needs the 'pypdf' package. "
                           "Install it with:  pip install pypdf\n"
                           "PrivacyKit will not hand-edit a PDF's structure — a "
                           "botched rewrite produces a file that will not open."), ""
    try:
        reader = PdfReader(str(src))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.add_metadata({})
        with open(out, "wb") as fh:
            writer.write(fh)
        return True, f"PDF metadata removed → {out.name}", str(out)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", ""


def scan_folder(folder: str, recursive: bool = True) -> List[MetadataReport]:
    """Inspect every supported file in a folder — the 'what am I about to share' check."""
    p = Path(folder)
    if not p.is_dir():
        return []
    it = p.rglob("*") if recursive else p.glob("*")
    out = []
    for f in it:
        if f.is_file() and f.suffix.lower() in SUPPORTED_READ:
            rep = inspect(str(f))
            if rep.findings:
                out.append(rep)
    return out
