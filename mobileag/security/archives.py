"""Bounded archive validation; never trust a member's path or declared type."""
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_UPLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_MEMBERS = 20000


def validate_archive(path: str | Path) -> str:
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_UPLOAD:
        raise ValueError("Missing archive or upload size limit exceeded")
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_MEMBERS:
                raise ValueError("Archive member count outside limits")
            total = 0
            names = set()
            for member in members:
                name = PurePosixPath(member.filename)
                if (name.is_absolute() or '..' in name.parts or '\\' in member.filename
                        or ':' in member.filename or stat.S_ISLNK(member.external_attr >> 16)
                        or member.flag_bits & 1 or member.filename in names):
                    raise ValueError("Unsafe or unsupported archive member")
                names.add(member.filename)
                total += member.file_size
                if total > MAX_EXPANDED or member.file_size > MAX_UPLOAD:
                    raise ValueError("Archive expansion limit exceeded")
            if 'AndroidManifest.xml' in names:
                return 'android'
            if any(n.startswith('Payload/') and n.endswith('.app/Info.plist') for n in names):
                return 'ios'
            raise ValueError("Archive is not an APK or IPA")
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid ZIP application archive") from exc


def extract_archive(path: str | Path, destination: str | Path) -> None:
    validate_archive(path)
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive:
        budget = 0
        for member in archive.infolist():
            target = (root / member.filename).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Archive escapes extraction directory")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open('xb') as output:
                while chunk := source.read(65536):
                    budget += len(chunk)
                    if budget > MAX_EXPANDED:
                        raise ValueError("Archive expansion limit exceeded")
                    output.write(chunk)
