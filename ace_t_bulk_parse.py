#!/usr/bin/env python3
import os, sys, io, re, json, csv, hashlib, mimetypes, subprocess, shutil
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict

import pandas as pd
from tqdm import tqdm
import chardet
from dateutil import tz
from unidecode import unidecode
from rapidfuzz import fuzz, process

# Optional libs
OCR_AVAIL = shutil.which("tesseract") is not None
OCRPDF_AVAIL = shutil.which("ocrmypdf") is not None
FFPROBE_AVAIL = shutil.which("ffprobe") is not None

try:
    import fitz  # PyMuPDF
except Exception as e:
    fitz = None

try:
    from PIL import Image, ExifTags
except Exception:
    Image, ExifTags = None, None

try:
    import pytesseract
except Exception:
    pytesseract = None

# --------------- Config ---------------
DEFAULT_IGNORE = {".DS_Store", "Thumbs.db"}
TEXT_EXT = {".txt", ".log", ".md", ".rst"}
CODE_EXT = {".py", ".json", ".jsonl", ".csv", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".html", ".xml", ".js", ".ts"}
PDF_EXT = {".pdf"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}
AUDIO_EXT = {".mp3", ".wav", ".m4a", ".flac", ".ogg", ".opus"}
VIDEO_EXT = {".mp4", ".mov", ".mkv", ".avi", ".webm"}
ARCHIVE_EXT = {".zip", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".rar"}

# --------------- Helpers ---------------
def sha256_path(p: Path, buf=1024 * 1024):
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            chunk = f.read(buf)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def md5_path(p: Path, buf=1024 * 1024):
    h = hashlib.md5()
    with p.open("rb") as f:
        while True:
            chunk = f.read(buf)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def guess_mime(p: Path):
    mt, _ = mimetypes.guess_type(str(p))
    return mt or "application/octet-stream"

def read_text_best_effort(p: Path, limit_mb=100):
    size_mb = p.stat().st_size / (1024 * 1024)
    if size_mb > limit_mb:
        return "", f"skipped_large_text>{size_mb:.2f}MB"
    raw = p.read_bytes()
    enc = chardet.detect(raw).get("encoding") or "utf-8"
    try:
        s = raw.decode(enc, errors="replace")
    except Exception as e:
        try:
            s = raw.decode("utf-8", errors="replace")
        except Exception as e2:
            return "", f"decode_error:{e2}"
    return s, f"decoded:{enc}"

def normalize_text(s: str):
    # simple normalization suitable for OSINT corpora
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = unidecode(s)
    return s.strip()

def pdf_extract_text(p: Path):
    route = []
    text = ""
    if fitz is not None:
        try:
            with fitz.open(str(p)) as doc:
                parts = []
                for page in doc:
                    parts.append(page.get_text("text"))
                text = "\n".join(parts).strip()
                route.append("pymupdf_text")
        except Exception as e:
            route.append(f"pymupdf_error:{e}")

    if not text and OCRPDF_AVAIL:
        # OCR to a temp searchable PDF then extract
        tmp_pdf = p.parent / f"__ocr_{p.name}"
        try:
            subprocess.run(
                ["ocrmypdf", "--sidecar", str(tmp_pdf.with_suffix(".txt")), "--skip-text", str(p), str(tmp_pdf)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if tmp_pdf.with_suffix(".txt").exists():
                text = tmp_pdf.with_suffix(".txt").read_text(errors="ignore")
                route.append("ocrmypdf_sidecar")
        except subprocess.CalledProcessError as e:
            route.append(f"ocrmypdf_error:{e}")
        finally:
            for q in [tmp_pdf, tmp_pdf.with_suffix(".txt")]:
                try:
                    if q.exists():
                        q.unlink()
                except Exception:
                    pass
    return normalize_text(text), "+".join(route) if route else "pdf_no_route"

def image_extract_text(p: Path):
    route = []
    exif_json = None
    if Image is not None:
        try:
            with Image.open(p) as im:
                # EXIF
                if hasattr(im, "_getexif") and im._getexif():
                    exd = {}
                    for tag, val in im._getexif().items():
                        tagname = ExifTags.TAGS.get(tag, str(tag))
                        exd[tagname] = str(val)
                    exif_json = exd
                    route.append("pil_exif")
        except Exception as e:
            route.append(f"pil_error:{e}")

    text = ""
    if OCR_AVAIL and pytesseract is not None:
        try:
            text = pytesseract.image_to_string(Image.open(p))
            route.append("tesseract")
        except Exception as e:
            route.append(f"tesseract_error:{e}")

    return normalize_text(text), exif_json, "+".join(route) if route else "image_no_route"

def ffprobe_meta(p: Path):
    if not FFPROBE_AVAIL:
        return None, "ffprobe_unavailable"
    cmd = [
        "ffprobe",
        "-v", "error",
        "-show_entries", "format=filename,format_name,duration,size,bit_rate",
        "-show_streams",
        "-of", "json",
        str(p),
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return json.loads(out.decode()), "ffprobe_json"
    except subprocess.CalledProcessError as e:
        return None, f"ffprobe_error:{e.output.decode(errors='ignore')}"

def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def safe_relpath(p: Path, root: Path):
    try:
        return str(p.relative_to(root))
    except Exception:
        return str(p)

# --------------- Core ---------------
def crawl(root: Path, outdir: Path, workers: int = 4):
    outdir.mkdir(parents=True, exist_ok=True)
    text_dir = outdir / "text_corpus"
    exif_dir = outdir / "exif"
    logs_dir = outdir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logf = (logs_dir / "run.log").open("a", encoding="utf-8")
    start_ts = datetime.now(tz=timezone.utc).isoformat()

    rows = []
    filelist = [p for p in root.rglob("*") if p.is_file() and p.name not in DEFAULT_IGNORE]

    for p in tqdm(filelist, desc="Scanning"):
        rel = safe_relpath(p, root)
        ext = p.suffix.lower()
        mime = guess_mime(p)
        size = p.stat().st_size
        mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=tz.tzlocal()).isoformat()
        atime = datetime.fromtimestamp(p.stat().st_atime, tz=tz.tzlocal()).isoformat()
        ctime = datetime.fromtimestamp(p.stat().st_ctime, tz=tz.tzlocal()).isoformat()

        sha256 = sha256_path(p)
        md5 = md5_path(p)

        text = ""
        parse_route = "none"
        error = ""

        try:
            if ext in TEXT_EXT or ext in CODE_EXT:
                s, route = read_text_best_effort(p)
                text = normalize_text(s)
                parse_route = route or "text"
            elif ext in PDF_EXT or mime == "application/pdf":
                text, route = pdf_extract_text(p)
                parse_route = route
            elif ext in IMAGE_EXT or (mime or "").startswith("image/"):
                text, exif_json, route = image_extract_text(p)
                parse_route = route
                if exif_json:
                    write_json(exif_dir / (Path(rel).with_suffix(".exif.json")), exif_json)
            elif ext in AUDIO_EXT or ext in VIDEO_EXT:
                meta, route = ffprobe_meta(p)
                parse_route = route
                if meta:
                    write_json(outdir / "av_meta" / (Path(rel).with_suffix(".ffprobe.json")), meta)
            else:
                # last chance plain decode
                s, route = read_text_best_effort(p)
                if s.strip():
                    text = normalize_text(s)
                    parse_route = f"fallback_text+{route}"
                else:
                    parse_route = "unparsed_binary"
        except Exception as e:
            error = f"{type(e).__name__}:{e}"

        text_len = len(text)
        if text_len:
            out_txt = text_dir / (Path(rel).with_suffix(".txt"))
            out_txt.parent.mkdir(parents=True, exist_ok=True)
            out_txt.write_text(text, encoding="utf-8")

        rows.append({
            "relpath": rel,
            "abspath": str(p),
            "ext": ext or "",
            "mime": mime,
            "size_bytes": size,
            "mtime_local": mtime,
            "atime_local": atime,
            "ctime_local": ctime,
            "sha256": sha256,
            "md5": md5,
            "text_len": text_len,
            "parse_route": parse_route,
            "error": error,
        })

    # Write manifests
    manifest_csv = outdir / "manifest.csv"
    manifest_jsonl = outdir / "manifest.jsonl"
    with manifest_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with manifest_jsonl.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Stats
    df = pd.DataFrame(rows)
    stats = {
        "started_utc": start_ts,
        "finished_utc": datetime.now(tz=timezone.utc).isoformat(),
        "files_total": int(df.shape[0]),
        "bytes_total": int(df["size_bytes"].sum() if not df.empty else 0),
        "text_docs": int((df["text_len"] > 0).sum() if not df.empty else 0),
        "unparsed": int((df["parse_route"] == "unparsed_binary").sum() if not df.empty else 0),
        "by_ext_top20": df["ext"].value_counts().head(20).to_dict() if not df.empty else {},
        "routes_top": df["parse_route"].value_counts().head(20).to_dict() if not df.empty else {},
        "errors": int((df["error"].astype(str).str.len() > 0).sum() if not df.empty else 0),
        "ocr_tools": {
            "tesseract": OCR_AVAIL,
            "ocrmypdf": OCRPDF_AVAIL
        },
        "av_tools": {
            "ffprobe": FFPROBE_AVAIL
        }
    }
    write_json(outdir / "global_stats.json", stats)

    # Derived CSVs
    if not df.empty:
        # counts by extension
        df["ext"] = df["ext"].fillna("")
        df_ext = df.groupby("ext").size().reset_index(name="count").sort_values("count", ascending=False)
        df_ext.to_csv(outdir / "extension_counts.csv", index=False)

        # by day
        dt_series = pd.to_datetime(df["mtime_local"], errors="coerce", utc=True)
        if dt_series.dtype == 'datetime64[ns]':
            by_day = dt_series.dt.date.value_counts().rename_axis("day").reset_index(name="count").sort_values("day")
            by_day.to_csv(outdir / "by_day.csv", index=False)
        else:
            # Create empty CSV if no valid dates
            pd.DataFrame(columns=["day", "count"]).to_csv(outdir / "by_day.csv", index=False)

        # by top directory
        df["topdir"] = df["relpath"].apply(lambda s: s.split(os.sep)[0] if os.sep in s else ".")
        by_dir = df.groupby("topdir").size().reset_index(name="count").sort_values("count", ascending=False)
        by_dir.to_csv(outdir / "by_dir.csv", index=False)

        # size histogram buckets
        bins = [0, 1<<10, 10<<10, 100<<10, 1<<20, 10<<20, 100<<20, 1<<30, 10<<30]
        labels = ["<1KB","1-10KB","10-100KB","100KB-1MB","1-10MB","10-100MB","100MB-1GB","1-10GB"]
        df["size_bucket"] = pd.cut(df["size_bytes"], bins=bins, labels=labels, include_lowest=True, right=False)
        df.groupby("size_bucket").size().reset_index(name="count").to_csv(outdir / "size_histogram.csv", index=False)

    logf.write(f"{datetime.now().isoformat()} Completed scan of {root}\n")
    logf.close()

def main():
    import argparse
    ap = argparse.ArgumentParser(description="ACE-T OSINT bulk cleaner and parser with OCR")
    ap.add_argument("--root", required=True, help="Root directory to crawl")
    ap.add_argument("--out", required=True, help="Output directory for parsed data and stats")
    ap.add_argument("--workers", type=int, default=4, help="Reserved argument for future parallelism")
    args = ap.parse_args()

    root = Path(args.root).expanduser()
    outdir = Path(args.out).expanduser()
    if not root.exists():
        print(f"Root not found: {root}")
        sys.exit(2)
    crawl(root, outdir, workers=args.workers)

if __name__ == "__main__":
    main()
