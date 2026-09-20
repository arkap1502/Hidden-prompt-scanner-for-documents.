"""Detection engine: hidden-text heuristics + injection pattern matching."""
from __future__ import annotations

import re
import zipfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

from patterns import PATTERNS

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "\u2060": "WORD JOINER",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
}

# ---------------------------------------------------------------- helpers

def _excerpt(text: str, n: int = 160) -> str:
    t = re.sub(r"\s+", " ", text).strip()
    return t[:n] + ("…" if len(t) > n else "")


def count_zero_width(text: str) -> dict:
    counts = {}
    for ch, name in ZERO_WIDTH.items():
        c = text.count(ch)
        if c:
            counts[name] = c
    return counts


def find_injection_patterns(text: str, location: str) -> list[dict]:
    findings = []
    for pid, desc, rx, weight in PATTERNS:
        for m in rx.finditer(text):
            start = max(0, m.start() - 60)
            findings.append({
                "type": "prompt-injection-pattern",
                "pattern_id": pid,
                "location": location,
                "detail": desc,
                "excerpt": _excerpt(text[start:m.end() + 80]),
                "severity": "high" if weight >= 3 else ("medium" if weight == 2 else "low"),
                "weight": weight,
            })
    return findings


def score_risk(findings: list[dict]) -> tuple[str, int]:
    """Combine hiding-technique findings with pattern matches."""
    score = 0
    for f in findings:
        t = f.get("type", "")
        if t == "prompt-injection-pattern":
            score += f.get("weight", 1) * 2
        elif t.startswith("hidden-"):
            score += 3
        elif t in ("metadata-match", "annotation-match", "comment-match"):
            score += 2
        elif t == "zero-width":
            score += 2
        else:
            score += 1
    if score >= 8 or any(f.get("severity") == "high" and f["type"].startswith("hidden") for f in findings):
        return "HIGH", score
    if score >= 4:
        return "MEDIUM", score
    if score >= 1:
        return "LOW", score
    return "CLEAN", 0

# ---------------------------------------------------------------- plain text

def scan_text_content(text: str, location: str) -> list[dict]:
    findings: list[dict] = []
    zw = count_zero_width(text)
    if zw:
        total = sum(zw.values())
        findings.append({
            "type": "zero-width",
            "location": location,
            "detail": f"Zero-width characters hidden in text: {zw}",
            "excerpt": _excerpt(text.replace("\u200b", "·").replace("\u200c", "·")) ,
            "severity": "medium",
            "weight": 2,
            "count": total,
        })
    findings.extend(find_injection_patterns(text, location))
    # Suspicious: huge runs of whitespace hiding text far apart
    if re.search(r"\n\s{40,}|\s{200,}", text):
        findings.append({
            "type": "hidden-whitespace",
            "location": location,
            "detail": "Large whitespace run — text may be pushed off-screen",
            "excerpt": "whitespace run > 40 chars",
            "severity": "low",
            "weight": 1,
        })
    return findings

# ---------------------------------------------------------------- HTML

class _HiddenHTMLParser(HTMLParser):
    # Content of these tags is code, not document text — never flag it.
    _SKIP_TAGS = ("script", "style", "noscript")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.findings: list[dict] = []
        self.visible_chunks: list[str] = []
        self._hidden_stack: list[str] = []
        self._skip_depth = 0

    def _style_hides(self, attrs: dict) -> str | None:
        style = (attrs.get("style") or "").lower().replace(" ", "")
        if "display:none" in style:
            return "display:none"
        if "visibility:hidden" in style:
            return "visibility:hidden"
        if "font-size:0" in style or "font-size:1px" in style:
            return "tiny font in style"
        if "color:#fff" in style or "color:white" in style or "color:transparent" in style:
            return "white/transparent text"
        if "opacity:0" in style:
            return "opacity:0"
        if attrs.get("hidden") is not None:
            return "hidden attribute"
        tag_class = (attrs.get("class") or "").lower()
        if "hidden" in tag_class or "invisible" in tag_class or "offscreen" in tag_class:
            return f"suspicious class '{attrs.get('class')}'"
        return None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        reason = self._style_hides(d)
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
            reason = reason or f"<{tag}> block (code, skipped)"
        self._hidden_stack.append(reason or "")

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if self._hidden_stack:
            self._hidden_stack.pop()

    def handle_data(self, data):
        if self._skip_depth:
            return  # JS/CSS code — not scannable document text
        if not data.strip():
            return
        hidden_reason = next((r for r in reversed(self._hidden_stack) if r), "")
        loc = "html:hidden" if hidden_reason else "html:visible"
        if hidden_reason:
            self.findings.append({
                "type": "hidden-html-element",
                "location": loc,
                "detail": f"Text hidden via {hidden_reason}",
                "excerpt": _excerpt(data),
                "severity": "high",
                "weight": 3,
            })
            self.findings.extend(find_injection_patterns(data, loc + " (hidden)"))
        else:
            self.visible_chunks.append(data)

    def handle_comment(self, data):
        if not data.strip():
            return
        self.findings.append({
            "type": "comment-match",
            "location": "html:comment",
            "detail": "HTML comment found — often used to hide LLM instructions",
            "excerpt": _excerpt(data),
            "severity": "medium",
            "weight": 2,
        })
        self.findings.extend(find_injection_patterns(data, "html:comment"))


def scan_html_file(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    parser = _HiddenHTMLParser()
    parser.feed(raw)
    findings = list(parser.findings)
    visible = " ".join(parser.visible_chunks)
    findings.extend(find_injection_patterns(visible, f"{path.name}:visible"))
    zw = count_zero_width(raw)
    if zw:
        findings.append({
            "type": "zero-width", "location": f"{path.name}:html",
            "detail": f"Zero-width chars in HTML source: {zw}",
            "excerpt": f"{sum(zw.values())} zero-width chars",
            "severity": "medium", "weight": 2,
        })
    return findings

# ---------------------------------------------------------------- PDF

def _pdf_backend():
    """Return best available PDF library: ('pymupdf', mod) | ('pypdf', mod) | (None, None)."""
    try:
        import pymupdf  # modern import name (no deprecation warning)
        return "pymupdf", pymupdf
    except ImportError:
        pass
    try:
        import fitz  # PyMuPDF legacy alias
        return "pymupdf", fitz
    except ImportError:
        pass
    try:
        import pypdf
        return "pypdf", pypdf
    except ImportError:
        pass
    try:
        import PyPDF2
        return "pypdf", PyPDF2
    except ImportError:
        return None, None


def _is_white(color_int: int | None) -> bool:
    if color_int is None:
        return False
    try:
        r = (color_int >> 16) & 255
        g = (color_int >> 8) & 255
        b = color_int & 255
        return r > 245 and g > 245 and b > 245
    except TypeError:
        return False


def scan_pdf_file(path: Path) -> list[dict]:
    findings: list[dict] = []
    backend, mod = _pdf_backend()
    if backend is None:
        return [{
            "type": "skipped", "location": str(path),
            "detail": "No PDF library installed (pip install pymupdf or pypdf)",
            "excerpt": "", "severity": "low", "weight": 0,
        }]
    if backend == "pymupdf":
        return _scan_pdf_fitz(path, mod)
    return _scan_pdf_pypdf(path, mod)


def _scan_pdf_fitz(path: Path, fitz) -> list[dict]:
    findings: list[dict] = []
    doc = fitz.open(path)
    try:
        # metadata
        for k, v in (doc.metadata or {}).items():
            if v and isinstance(v, str):
                findings.extend(
                    {**f, "location": f"pdf:metadata:{k}"}
                    for f in find_injection_patterns(v, f"pdf:metadata:{k}")
                )
        for i, page in enumerate(doc):
            pageno = i + 1
            rect = page.rect
            d = page.get_text("dict")
            for block in d.get("blocks", []):
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = span.get("text", "")
                        if not text.strip():
                            continue
                        size = span.get("size", 12)
                        color = span.get("color")
                        alpha = span.get("alpha", 1)
                        bbox = span.get("bbox", (0, 0, 0, 0))
                        x0, y0, x1, y1 = bbox
                        off_page = x1 < 0 or y1 < 0 or x0 > rect.width or y0 > rect.height
                        hidden_reasons = []
                        if size is not None and size < 2:
                            hidden_reasons.append(f"tiny font {size:.1f}pt")
                        if _is_white(color):
                            hidden_reasons.append("white-on-white text")
                        if alpha == 0:
                            hidden_reasons.append("fully transparent text")
                        if off_page:
                            hidden_reasons.append("text outside page bounds")
                        loc = f"pdf:page{pageno}"
                        if hidden_reasons:
                            findings.append({
                                "type": "hidden-pdf-text",
                                "location": loc,
                                "detail": "Hidden PDF text: " + ", ".join(hidden_reasons),
                                "excerpt": _excerpt(text),
                                "severity": "high",
                                "weight": 3,
                            })
                        findings.extend(find_injection_patterns(text, loc))
                        zw = count_zero_width(text)
                        if zw:
                            findings.append({
                                "type": "zero-width", "location": loc,
                                "detail": f"Zero-width chars on page {pageno}: {zw}",
                                "excerpt": _excerpt(text[:120]),
                                "severity": "medium", "weight": 2,
                            })
            # annotations / hidden layers
            for annot in page.annots() or []:
                content = (annot.info or {}).get("content", "")
                if content and content.strip():
                    findings.append({
                        "type": "annotation-match",
                        "location": f"pdf:page{pageno}:annotation",
                        "detail": "PDF annotation/popup text (invisible unless opened)",
                        "excerpt": _excerpt(content),
                        "severity": "medium", "weight": 2,
                    })
                    findings.extend(find_injection_patterns(content, f"pdf:page{pageno}:annotation"))
        # embedded files
        try:
            for idx in range(doc.embfile_count()):
                info = doc.embfile_info(idx)
                findings.append({
                    "type": "embedded-file",
                    "location": f"pdf:embedded:{info.get('name', idx)}",
                    "detail": "PDF has embedded file — inspect separately",
                    "excerpt": str(info.get("name", "")),
                    "severity": "low", "weight": 1,
                })
        except Exception:
            pass
    finally:
        doc.close()
    return findings


def _scan_pdf_pypdf(path: Path, pypdf) -> list[dict]:
    findings: list[dict] = []
    reader = pypdf.PdfReader(str(path))
    try:
        meta = reader.metadata or {}
        for k, v in dict(meta).items():
            if v and isinstance(v, str):
                findings.extend(find_injection_patterns(str(v), f"pdf:metadata:{k}"))
    except Exception:
        pass
    for i, page in enumerate(reader.pages):
        pageno = i + 1
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        loc = f"pdf:page{pageno}"
        findings.extend(scan_text_content(text, loc))
        # annotations via raw objects
        try:
            annots = page.get("/Annots") or []
            for a in annots:
                obj = a.get_object()
                contents = str(obj.get("/Contents", ""))
                if contents and contents != "None":
                    findings.append({
                        "type": "annotation-match",
                        "location": f"{loc}:annotation",
                        "detail": "PDF annotation text",
                        "excerpt": _excerpt(contents),
                        "severity": "medium", "weight": 2,
                    })
                    findings.extend(find_injection_patterns(contents, f"{loc}:annotation"))
        except Exception:
            pass
    return findings

# ---------------------------------------------------------------- DOCX (stdlib zip+xml + optional python-docx styling)

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W_VAL = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val"


def _docx_parts(path: Path) -> dict[str, str]:
    """Read scannable XML parts. Headers/footers are enumerated dynamically
    (header1..N / footer1..N) instead of assuming only 1-2 exist."""
    core = ("word/document.xml", "word/comments.xml",
            "word/footnotes.xml", "word/endnotes.xml",
            "docProps/core.xml")
    parts: dict[str, str] = {}
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        wanted = [n for n in core if n in names]
        wanted += sorted(n for n in names
                         if re.fullmatch(r"word/(header|footer)\d+\.xml", n))
        for name in wanted:
            try:
                parts[name] = z.read(name).decode("utf-8", errors="replace")
            except KeyError:
                pass
    return parts


def _scan_docx_xml(path: Path) -> list[dict]:
    findings: list[dict] = []
    parts = _docx_parts(path)
    for part, xml in parts.items():
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            continue
        # hidden via w:vanish / w:color white / w:sz tiny / w:webHidden
        for r in root.iter():
            tag = r.tag.split("}")[-1]
            if tag != "r":
                continue
            rpr = r.find("w:rPr", NS)
            hidden_reason = ""
            if rpr is not None:
                if rpr.find("w:vanish", NS) is not None or rpr.find("w:webHidden", NS) is not None:
                    hidden_reason = "vanish/hidden flag"
                color = rpr.find("w:color", NS)
                if color is not None:
                    if (color.get(W_VAL) or "").lower() == "ffffff":
                        hidden_reason = (hidden_reason + "+white color").strip("+")
                sz = rpr.find("w:sz", NS)
                if sz is not None:
                    try:
                        half_pts = int(sz.get(W_VAL, "24"))
                        if half_pts <= 4:  # <= 2pt
                            hidden_reason = (hidden_reason + f"+tiny font {half_pts/2:.1f}pt").strip("+")
                    except ValueError:
                        pass
            texts = [t.text or "" for t in r.findall("w:t", NS)]
            run_text = "".join(texts)
            if not run_text.strip():
                continue
            loc = f"docx:{Path(part).name}"
            if hidden_reason:
                findings.append({
                    "type": "hidden-docx-text",
                    "location": loc,
                    "detail": f"Hidden Word text: {hidden_reason}",
                    "excerpt": _excerpt(run_text),
                    "severity": "high",
                    "weight": 3,
                })
            findings.extend(find_injection_patterns(run_text, loc))
            zw = count_zero_width(run_text)
            if zw:
                findings.append({
                    "type": "zero-width", "location": loc,
                    "detail": f"Zero-width chars in DOCX run: {zw}",
                    "excerpt": _excerpt(run_text[:120]),
                    "severity": "medium", "weight": 2,
                })
    return findings


def scan_docx_file(path: Path) -> list[dict]:
    try:
        return _scan_docx_xml(path)
    except zipfile.BadZipFile:
        return [{
            "type": "error", "location": str(path),
            "detail": "Not a valid DOCX (zip) file",
            "excerpt": "", "severity": "low", "weight": 0,
        }]

# ---------------------------------------------------------------- dispatcher

SUPPORTED = {".txt", ".md", ".markdown", ".html", ".htm", ".pdf", ".docx"}


def scan_file(path: Path) -> dict:
    path = Path(path)
    suffix = path.suffix.lower()
    findings: list[dict] = []
    if suffix == ".pdf":
        findings = scan_pdf_file(path)
    elif suffix == ".docx":
        findings = scan_docx_file(path)
    elif suffix in (".html", ".htm"):
        findings = scan_html_file(path)
    elif suffix in (".txt", ".md", ".markdown") or suffix == "":
        text = path.read_text(encoding="utf-8", errors="replace")
        findings = scan_text_content(text, f"{path.name}:body")
    else:
        findings = [{
            "type": "skipped", "location": str(path),
            "detail": f"Unsupported extension '{suffix}'",
            "excerpt": "", "severity": "low", "weight": 0,
        }]
    risk, score = score_risk(findings)
    return {
        "file": str(path),
        "file_type": suffix or "unknown",
        "risk": risk,
        "score": score,
        "findings": findings,
        "finding_count": len(findings),
    }
