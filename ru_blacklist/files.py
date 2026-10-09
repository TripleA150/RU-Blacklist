import gzip
import os
import tempfile
from pathlib import Path


def write_atomic(path, lines):
    """Write lines to ``path`` via a temp file + rename, so readers never see a partial file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.writelines(f"{line}\n" for line in lines)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        os.unlink(tmp_name)
        raise


def open_text(path, encoding="latin-1"):
    """Open a plain or gzip-compressed text file for streaming reads."""
    path = str(path)
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding=encoding, errors="replace")
    return open(path, encoding=encoding, errors="replace")
