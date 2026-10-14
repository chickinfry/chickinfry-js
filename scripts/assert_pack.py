#!/usr/bin/env python3
"""Print the single npm tarball path after checking publish files and configuration."""

from pathlib import Path
import json
import sys
import tarfile


def is_realtime(path, is_directory=False):
    parts = path.split("/")
    basename = parts[-1] if is_directory else parts[-1].split(".", 1)[0]
    return any(part.casefold() == "realtime" for part in (*parts[:-1], basename))


def assert_pack(directory):
    tarballs = list(Path(directory).glob("*.tgz"))
    if len(tarballs) != 1:
        raise ValueError("Expected exactly one npm tarball.")
    tarball = tarballs[0]
    if tarball.is_symlink() or not tarball.is_file():
        raise ValueError("Expected a regular npm tarball file.")
    tarball = tarball.resolve()
    if "\n" in str(tarball) or "\r" in str(tarball):
        raise ValueError("Invalid npm tarball path.")
    files = set()
    with tarfile.open(tarball, mode="r:gz") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
                raise ValueError("Noncanonical npm package path.")
            in_dist = name.startswith("package/dist/")
            if in_dist and is_realtime(name, member.isdir()):
                raise ValueError("Unexpected npm package entry.")
            if member.isdir():
                if name not in ("package", "package/dist") and not in_dist:
                    raise ValueError("Unexpected npm package directory.")
                continue
            if not member.isfile():
                raise ValueError("Nonregular npm package entry.")
            if name not in ("package/package.json", "package/LICENSE", "package/README.md") and not in_dist:
                raise ValueError("Unexpected npm package file.")
            if name in files:
                raise ValueError("Duplicate npm package file.")
            if name == "package/package.json":
                manifest = json.load(archive.extractfile(member))
                if (not isinstance(manifest, dict)
                        or manifest.keys() & {"tag", "main", "module", "browser", "typesVersions"}
                        or manifest.get("publishConfig") != {"access": "public"}):
                    raise ValueError("Unexpected npm publish configuration.")
                exports = manifest.get("exports")
                if (not isinstance(exports, dict)
                        or not exports.keys() <= {".", "./auth", "./postgres", "./logging"}
                        or any(not isinstance(target, str) or not target.startswith("./dist/")
                               or not target.endswith(".js") or "\\" in target
                               or is_realtime(target)
                               or any(part in ("", ".", "..") for part in target.split("/")[1:])
                               for target in exports.values())):
                    raise ValueError("Unexpected npm package exports.")
            files.add(name)
    if "package/package.json" not in files:
        raise ValueError("Missing npm package.json.")
    return tarball


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Usage: assert_pack.py PACK_DIRECTORY")
        print(assert_pack(sys.argv[1]))
    except (OSError, ValueError, tarfile.TarError, EOFError):
        sys.exit("npm pack assertion failed.")
