#!/usr/bin/env python3
"""Print the single npm tarball path after checking publish files and configuration."""

from pathlib import Path
import json
import sys
import tarfile


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
                if (not isinstance(manifest, dict) or "tag" in manifest
                        or manifest.get("publishConfig") != {"access": "public"}):
                    raise ValueError("Unexpected npm publish configuration.")
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
