import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "assert_pack.py"


class PackAssertionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def pack(self, entries, filename="fixture.tgz", manifest=None):
        payload = json.dumps({"publishConfig": {"access": "public"}} if manifest is None else manifest).encode()
        with tarfile.open(self.directory / filename, "w:gz") as archive:
            for name, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                body = payload if kind == tarfile.REGTYPE else b""
                member.size = len(body)
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = "package/package.json"
                archive.addfile(member, io.BytesIO(body))

    def check_pack(self):
        return subprocess.run(
            [sys.executable, "-I", "-B", str(SCRIPT), str(self.directory)],
            capture_output=True, text=True, check=False,
        )

    def test_allowed_files(self):
        self.pack([(name, tarfile.REGTYPE) for name in (
            "package/package.json", "package/LICENSE", "package/README.md",
            "package/dist/index.js", "package/dist/auth/index.d.ts",
        )] + [(name, tarfile.DIRTYPE) for name in ("package/", "package/dist/", "package/dist/auth/")])
        result = self.check_pack()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str((self.directory / "fixture.tgz").resolve()))

    def test_outside_allowlist(self):
        self.pack([(name, tarfile.REGTYPE) for name in ("package/package.json", "package/src/fixture.js")])
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_missing_package_json(self):
        self.pack([("package/dist/index.js", tarfile.REGTYPE)])
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_publish_configuration_is_fixed(self):
        for manifest in (
            {"publishConfig": {"access": "public", "registry": "https://example.invalid/"}},
            {},
            {"publishConfig": None},
            {"publishConfig": {"access": "restricted"}},
            [],
        ):
            with self.subTest(manifest=manifest):
                self.pack([("package/package.json", tarfile.REGTYPE)], manifest=manifest)
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_top_level_tag_is_rejected(self):
        self.pack([("package/package.json", tarfile.REGTYPE)],
                  manifest={"publishConfig": {"access": "public"}, "tag": None})
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_tarball_count(self):
        self.assertNotEqual(self.check_pack().returncode, 0)
        self.pack([("package/package.json", tarfile.REGTYPE)], "first.tgz")
        self.pack([("package/package.json", tarfile.REGTYPE)], "second.tgz")
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_ambiguous_paths_and_entry_types(self):
        for name, kind in (
            ("package/dist/../src/fixture.js", tarfile.REGTYPE),
            ("package/dist\\fixture.js", tarfile.REGTYPE),
            ("/package/dist/fixture.js", tarfile.REGTYPE),
            ("package/dist//fixture.js", tarfile.REGTYPE),
            ("package/dist/link", tarfile.SYMTYPE),
            ("package/dist/link", tarfile.LNKTYPE),
            ("package/dist/pipe", tarfile.FIFOTYPE),
            ("package/package.json", tarfile.DIRTYPE),
        ):
            with self.subTest(name=name, kind=kind):
                self.pack([("package/package.json", tarfile.REGTYPE), (name, kind)])
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_duplicate_manifest(self):
        self.pack([("package/package.json", tarfile.REGTYPE)] * 2)
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_invalid_tarball_and_symlink(self):
        tarball = self.directory / "fixture.tgz"
        tarball.write_bytes(b"invalid archive")
        self.assertNotEqual(self.check_pack().returncode, 0)
        tarball.unlink()
        target = self.directory / "target"
        target.write_bytes(b"invalid archive")
        tarball.symlink_to(target)
        self.assertNotEqual(self.check_pack().returncode, 0)

    @unittest.skipUnless(os.environ.get("PUBLISH_WORKFLOW_PATH"), "Workflow patch is delivered separately.")
    def test_trusted_inline_assertion_matches_script(self):
        workflow = Path(os.environ["PUBLISH_WORKFLOW_PATH"]).read_text()
        start = '          tarball=$(python3 -I -B - "$RUNNER_TEMP/pack" <<\'PACK\'\n'
        self.assertEqual(workflow.count(start), 1)
        inline = workflow.split(start, 1)[1].split("          PACK\n", 1)[0]
        lines = inline.splitlines(keepends=True)
        self.assertTrue(all(line.startswith("          ") for line in lines))
        self.assertEqual("".join(line[10:] for line in lines), SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
