"""Bound ZIP inspection for model containers, including ZIP64."""
from contextlib import contextmanager
from pathlib import Path
import re
import stat
import struct
import zipfile
import zlib

MIB = 1024 * 1024
MAX_ENTRIES = 4096
MAX_DIRECTORY = 4 * MIB
MAX_MEMBER_SIZE = 1024 * MIB
MAX_EXPANDED_SIZE = 4096 * MIB
MAX_EXPANSION_RATIO = 200
MAX_MEMBER_READ = 8 * MIB
MAX_ARCHIVE_READ = 64 * MIB
MAX_ZIP_INPUT_READ = 72 * MIB
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
COMPRESSED_MAGIC = (*ZIP_MAGIC, b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c")


class ArchiveRejected(ValueError):
    """An untrusted archive exceeded policy or failed validation."""


class _BoundedInput:
    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_ZIP_INPUT_READ

    def read(self, size=-1):
        if size > self.remaining:
            raise ArchiveRejected("Чтение сжатого ZIP превысило лимит.")
        data = self.stream.read(self.remaining + 1 if size < 0 else size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ArchiveRejected("Чтение сжатого ZIP превысило лимит.")
        return data

    def seek(self, *args):
        return self.stream.seek(*args)

    def tell(self):
        return self.stream.tell()

    def seekable(self):
        return self.stream.seekable()


def archive_type(path: Path) -> str | None:
    with path.open("rb") as stream:
        signature = stream.read(6)
        if signature.startswith(ZIP_MAGIC) or zipfile.is_zipfile(stream):
            return "zip"
        if signature.startswith(COMPRESSED_MAGIC):
            return "compressed"
    return None


class BoundedZip:
    def __init__(self, archive: zipfile.ZipFile, directory_count: int):
        self.archive = archive
        self.entries = archive.infolist()
        self.read_bytes = 0
        if len(self.entries) != directory_count or len(self.entries) > MAX_ENTRIES:
            raise ArchiveRejected("Недопустимое число записей в ZIP.")
        expanded = 0
        names = set()
        for entry in self.entries:
            name = entry.orig_filename
            path_parts = re.split(r"[/\\]", name)
            if (not name or "\x00" in name or name[0] in "/\\" or re.match(r"^[A-Za-z]:", name)
                    or ".." in path_parts or name in names or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ArchiveRejected("ZIP содержит повторяющиеся, небезопасные имена или символические ссылки.")
            names.add(name)
            if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ArchiveRejected("ZIP использует шифрование или неподдерживаемый метод сжатия.")
            expanded += entry.file_size
            if entry.file_size > MAX_MEMBER_SIZE or expanded > MAX_EXPANDED_SIZE:
                raise ArchiveRejected("Заявленный размер ZIP после распаковки превышает лимит.")
            if (entry.file_size >= MIB
                    and entry.file_size > max(1, entry.compress_size) * MAX_EXPANSION_RATIO):
                raise ArchiveRejected("Коэффициент распаковки ZIP превышает лимит 200:1.")

    def read(self, entry: zipfile.ZipInfo, *, prefix: int | None = None) -> bytes:
        length = entry.file_size if prefix is None else min(entry.file_size, prefix)
        if length > MAX_MEMBER_READ or self.read_bytes + length > MAX_ARCHIVE_READ:
            raise ArchiveRejected("Объём читаемых данных ZIP превышает лимит распаковки сканера.")
        self.read_bytes += length
        with self.archive.open(entry) as stream:
            data = stream.read(length)
        if len(data) != length:
            raise ArchiveRejected("Размер записи ZIP расходится с фактически прочитанным.")
        if data.startswith(COMPRESSED_MAGIC):
            raise ArchiveRejected("Внутри читаемой записи обнаружен вложенный сжатый контейнер.")
        return data


@contextmanager
def open_bounded_zip(path: Path):
    try:
        with path.open("rb") as stream:
            # CPython reads only the bounded ZIP trailer here and resolves ZIP64.
            # ZipFile itself allocates the central directory during construction.
            directory = zipfile._EndRecData(stream)
            if directory is None:
                raise ArchiveRejected("Конец центрального каталога ZIP повреждён.")
            size = directory[zipfile._ECD_SIZE]
            count = directory[zipfile._ECD_ENTRIES_TOTAL]
            if size > MAX_DIRECTORY or count > MAX_ENTRIES:
                raise ArchiveRejected("Центральный каталог ZIP превышает лимит размера или числа записей.")
            with zipfile.ZipFile(_BoundedInput(stream)) as archive:
                yield BoundedZip(archive, count)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, struct.error, zlib.error) as exc:
        raise ArchiveRejected("Не удалось безопасно прочитать структуру ZIP.") from exc
