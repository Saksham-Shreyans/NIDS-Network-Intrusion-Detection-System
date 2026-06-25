import csv
import os
import threading
from collections import deque
from pathlib import Path
from typing import Dict, List

import pandas as pd


_locks: Dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()


def _get_lock(filepath: str) -> threading.Lock:
    with _locks_lock:
        if filepath not in _locks:
            _locks[filepath] = threading.Lock()
        return _locks[filepath]


def append_rows(
    filepath: Path,
    rows: List[Dict],
    fieldnames: List[str],
) -> None:
    if not rows:
        return

    filepath = Path(filepath)
    lock = _get_lock(str(filepath))

    with lock:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        file_exists = filepath.exists()

        if file_exists:
            # True append – no reading, no rewrite
            with open(filepath, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=fieldnames, extrasaction="ignore"
                )
                writer.writerows(rows)
        else:
            # Atomic initial creation with header
            tmp = Path(str(filepath) + ".tmp")
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=fieldnames, extrasaction="ignore"
                )
                writer.writeheader()
                writer.writerows(rows)
            os.replace(str(tmp), str(filepath))


def read_csv(filepath: Path) -> pd.DataFrame:
    filepath = Path(filepath)
    if not filepath.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(filepath, on_bad_lines="skip")
    except Exception:
        return pd.DataFrame()


def tail_rows(filepath: Path, n: int) -> List[Dict]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            dq = deque(reader, maxlen=n)
        return list(dq)
    except Exception:
        return []
