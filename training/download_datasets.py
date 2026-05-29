"""
Download the SpamAssassin public corpus and the Nazario phishing corpus.

SpamAssassin:  ham  → data/raw/legitimate/
               spam → data/raw/phishing/

Run:
    python training/download_datasets.py
"""
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

SPAMASSASSIN_BASE = "https://spamassassin.apache.org/old/publiccorpus"

ARCHIVES = [
    # (filename, dest_subdir, label)
    ("20021010_easy_ham.tar.bz2",   "legitimate", "ham"),
    ("20021010_hard_ham.tar.bz2",   "legitimate", "ham"),
    ("20030228_easy_ham.tar.bz2",   "legitimate", "ham"),
    ("20030228_easy_ham_2.tar.bz2", "legitimate", "ham"),
    ("20021010_spam.tar.bz2",       "phishing",   "spam"),
    ("20030228_spam.tar.bz2",       "phishing",   "spam"),
    ("20030228_spam_2.tar.bz2",     "phishing",   "spam"),
    ("20050311_spam_2.tar.bz2",     "phishing",   "spam"),
]

RAW_DIR = Path("data/raw")
CACHE_DIR = Path("data/.cache")


def _progress(block_num, block_size, total_size):
    downloaded = block_num * block_size
    pct = min(downloaded / total_size * 100, 100) if total_size > 0 else 0
    bar = "#" * int(pct / 2)
    sys.stdout.write(f"\r  [{bar:<50}] {pct:.1f}%")
    sys.stdout.flush()


def download_archive(filename: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = CACHE_DIR / filename
    if dest.exists():
        print(f"  Cached: {filename}")
        return dest
    url = f"{SPAMASSASSIN_BASE}/{filename}"
    print(f"  Downloading {filename} ...")
    urllib.request.urlretrieve(url, dest, reporthook=_progress)
    print()
    return dest


def extract_archive(archive_path: Path, dest_dir: Path, label: str):
    dest_dir.mkdir(parents=True, exist_ok=True)
    marker = CACHE_DIR / f".extracted_{archive_path.name}"
    if marker.exists():
        print(f"  Already extracted: {archive_path.name}")
        return

    print(f"  Extracting {archive_path.name} -> {dest_dir}")
    extracted = 0
    with tarfile.open(archive_path, "r:bz2") as tar:
        for member in tar.getmembers():
            if member.isfile():
                member.name = Path(member.name).name
                if not member.name or member.name.startswith("."):
                    continue
                tar.extract(member, path=dest_dir)
                extracted += 1
    marker.touch()
    count = len(list(dest_dir.iterdir()))
    print(f"  -> extracted {extracted} files ({count} total in {dest_dir})")


def main():
    print("=== Downloading SpamAssassin Public Corpus ===\n")
    for filename, subdir, label in ARCHIVES:
        dest_dir = RAW_DIR / subdir
        archive = download_archive(filename)
        extract_archive(archive, dest_dir, label)

    legit_count = len(list((RAW_DIR / "legitimate").rglob("*"))) if (RAW_DIR / "legitimate").exists() else 0
    phish_count = len(list((RAW_DIR / "phishing").rglob("*"))) if (RAW_DIR / "phishing").exists() else 0
    print(f"\nDone. Legitimate: {legit_count} files, Phishing/Spam: {phish_count} files")
    print("\nNow run:  python training/train.py")


if __name__ == "__main__":
    main()
