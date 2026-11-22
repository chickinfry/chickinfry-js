import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "assert_pack.py"


class PackAssertionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def pack(self, entries, filename="fixture.tgz", manifest=None, contents=None):
        payload = json.dumps({"publishConfig": {"access": "public"}, "exports": {".": "./dist/index.js"}}
                             if manifest is None else manifest).encode()
        with tarfile.open(self.directory / filename, "w:gz") as archive:
            for name, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                body = (contents or {}).get(name, payload) if kind == tarfile.REGTYPE else b""
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

    def test_realtime_entries_are_rejected(self):
        for name, kind in (
            ("package/dist/realtime/client.js", tarfile.REGTYPE),
            ("package/dist/Realtime/x.js", tarfile.REGTYPE),
            ("package/dist/realtime.js", tarfile.REGTYPE),
            ("package/dist/realtime.d.ts", tarfile.REGTYPE),
            ("package/dist/foo/realtime/x.js", tarfile.REGTYPE),
            ("package/dist/foo/Realtime.mjs", tarfile.REGTYPE),
            ("package/dist/realtime/", tarfile.DIRTYPE),
            ("package/dist/foo/REALTIME/", tarfile.DIRTYPE),
        ):
            with self.subTest(name=name):
                self.pack([("package/package.json", tarfile.REGTYPE), (name, kind)])
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_missing_package_json(self):
        self.pack([("package/dist/index.js", tarfile.REGTYPE)])
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_publish_configuration_is_fixed(self):
        for manifest in (
            {"exports": {".": "./dist/index.js"},
             "publishConfig": {"access": "public", "registry": "https://example.invalid/"}},
            {"exports": {".": "./dist/index.js"}},
            {"exports": {".": "./dist/index.js"}, "publishConfig": None},
            {"exports": {".": "./dist/index.js"}, "publishConfig": {"access": "restricted"}},
            *({"exports": {".": "./dist/index.js"}, "publishConfig": {"access": "public"},
               field: None} for field in ("main", "module", "browser", "typesVersions")),
            [],
        ):
            with self.subTest(manifest=manifest):
                self.pack([("package/package.json", tarfile.REGTYPE)], manifest=manifest)
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_top_level_tag_is_rejected(self):
        self.pack([("package/package.json", tarfile.REGTYPE)],
                  manifest={"publishConfig": {"access": "public"},
                            "exports": {".": "./dist/index.js"}, "tag": None})
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_allowed_exports(self):
        for exports in ({}, {
            ".": "./dist/index.js", "./auth": "./dist/auth/index.js",
            "./auth/runtime": "./dist/auth/host.js",
            "./logging": "./dist/logging.js",
        }):
            with self.subTest(exports=exports):
                self.pack([("package/package.json", tarfile.REGTYPE)],
                          manifest={"publishConfig": {"access": "public"}, "exports": exports})
                result = self.check_pack()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_provider_dependencies_and_postgres_export_are_rejected(self):
        for addition in (
            {"dependencies": {"pg": "8.23.0"}},
            {"devDependencies": {"@types/pg": "8.23.1"}},
            {"optionalDependencies": {"socket": "npm:pg-" + "cloud" + "flare@1.4.0"}},
            {"exports": {"./postgres": "./dist/postgres.js"}},
        ):
            with self.subTest(addition=addition):
                manifest = {"publishConfig": {"access": "public"}, "exports": {".": "./dist/index.js"}}
                self.pack([("package/package.json", tarfile.REGTYPE)], manifest=manifest | addition)
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_private_database_entries_and_provider_contents_are_rejected(self):
        for name, body in (
            ("package/dist/postgres.js", b"export {}"),
            ("package/dist/postgres.d.ts", b"export {}"),
            ("package/dist/orm.js", b'import adapter from "pg";'),
            ("package/dist/auth/host.d.ts", b'import type { Client } from "pg-' + b'cloud' + b'flare";'),
            ("package/README.md", b"Use Cloud" + b"flare-Workers for the database transport."),
        ):
            with self.subTest(name=name):
                self.pack([("package/package.json", tarfile.REGTYPE), (name, tarfile.REGTYPE)],
                          contents={name: body})
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_outside_exports_allowlist(self):
        self.pack([("package/package.json", tarfile.REGTYPE)],
                  manifest={"publishConfig": {"access": "public"},
                            "exports": {"./realtime": "./dist/realtime.js"}})
        self.assertNotEqual(self.check_pack().returncode, 0)

    def test_invalid_export_targets(self):
        for target in ("./src/index.js", "./dist/index.d.ts", {"import": "./dist/index.js"},
                       None, "./dist/../src/index.js", "./dist/..\\src/index.js",
                       "./dist/realtime/client.js", "./dist/Realtime/x.js",
                       "./dist/realtime.js", "./dist/realtime.d.ts",
                       "./dist/foo/realtime/x.js", "./dist/foo/Realtime.mjs",
                       "./dist/foo/Realtime.js"):
            with self.subTest(target=target):
                self.pack([("package/package.json", tarfile.REGTYPE)],
                          manifest={"publishConfig": {"access": "public"}, "exports": {".": target}})
                self.assertNotEqual(self.check_pack().returncode, 0)

    def test_exports_is_required_object(self):
        for manifest in (
            {"publishConfig": {"access": "public"}},
            {"publishConfig": {"access": "public"}, "exports": None},
            {"publishConfig": {"access": "public"}, "exports": []},
            {"publishConfig": {"access": "public"}, "exports": "./dist/index.js"},
        ):
            with self.subTest(manifest=manifest):
                self.pack([("package/package.json", tarfile.REGTYPE)], manifest=manifest)
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
        self.assertTrue(all(line == "\n" or line.startswith("          ") for line in lines))
        self.assertEqual("".join(line[10:] if line.startswith("          ") else line for line in lines),
                         SCRIPT.read_text())


@unittest.skipUnless(os.environ.get("PUBLISH_WORKFLOW_PATH"), "Workflow patch is delivered separately.")
class ReleaseSourceTest(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.environment = {
            "GITHUB_REPOSITORY": "example/package",
            "GITHUB_SHA": self.sha,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GH_TOKEN": "fixture-token",
        }
        self.run = {
            "head_sha": self.sha, "head_branch": "main", "event": "push",
            "status": "completed", "conclusion": "success",
        }
        workflow = Path(os.environ["PUBLISH_WORKFLOW_PATH"]).read_text()
        steps = workflow.split("\n  tag:\n", 1)[1].split("    steps:\n", 1)[1]
        self.assertTrue(steps.startswith("      - name: Verify release source before running code\n"))
        first = steps.split("\n      - ", 1)[0]
        self.assertIn(' /usr/bin/python3 -I -B - <<\'TRUST\'\n', first)
        self.assertIn('/usr/bin/env -i GH_TOKEN="$GH_TOKEN"', first)
        inline = first.split("<<'TRUST'\n", 1)[1].split("          TRUST", 1)[0]
        self.assertTrue(all(not line or line.startswith("          ") for line in inline.splitlines()))
        source = "\n".join(line[10:] for line in inline.splitlines()) + "\n"
        self.source = compile(source, str(os.environ["PUBLISH_WORKFLOW_PATH"]), "exec")

    def approval(self, status="identical", runs=None, error=None):
        responses = iter(({"status": status}, {"workflow_runs": [self.run] if runs is None else runs}))
        requests = []

        def open_api(request, timeout):
            requests.append(request.full_url)
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture-token")
            self.assertEqual(timeout, 30)
            if error:
                raise error
            return io.BytesIO(json.dumps(next(responses)).encode())

        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch("urllib.request.build_opener") as opener, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            opener.return_value.open.side_effect = open_api
            try:
                exec(self.source, {})
            except SystemExit as error:
                self.assertEqual(error.code, 1)
                return False, requests
        self.assertEqual(requests, [
            "https://api.github.com/repos/example/package/compare/main..." + self.sha,
            "https://api.github.com/repos/example/package/actions/workflows/ci.yml/runs?head_sha="
            + self.sha + "&event=push&per_page=100",
        ])
        return True, requests

    def test_main_head_with_successful_ci(self):
        self.assertTrue(self.approval("identical")[0])

    def test_older_or_unrelated_source_is_rejected(self):
        # An older main commit is rejected too, so a stale commit cannot be tagged later.
        for status in ("behind", "ahead", "diverged", "unknown"):
            with self.subTest(status=status):
                accepted, requests = self.approval(status)
                self.assertFalse(accepted)
                self.assertEqual(len(requests), 1)

    def test_missing_unsuccessful_or_unfinished_ci_is_rejected(self):
        for runs in ([], [dict(self.run, conclusion="failure")],
                     [dict(self.run, status="in_progress", conclusion=None)],
                     [dict(self.run, status="queued", conclusion=None)]):
            with self.subTest(runs=runs):
                self.assertFalse(self.approval(runs=runs)[0])

    def test_unrelated_ci_is_rejected(self):
        for field, value in (("head_sha", "b" * 40), ("head_branch", "feature"), ("event", "pull_request")):
            with self.subTest(field=field):
                self.assertFalse(self.approval(runs=[dict(self.run, **{field: value})])[0])

    def test_invalid_source_is_rejected_before_api_access(self):
        for field, value in (("GITHUB_REF", "refs/heads/feature"), ("GITHUB_REF", "refs/tags/v0.3.0"),
                             ("GITHUB_EVENT_NAME", "push"), ("GITHUB_SHA", "invalid"),
                             ("GITHUB_REPOSITORY", "example/../package")):
            with self.subTest(field=field, value=value):
                with mock.patch.dict(self.environment, {field: value}):
                    accepted, requests = self.approval()
                self.assertFalse(accepted)
                self.assertEqual(requests, [])

    def test_api_errors_are_rejected_without_retry(self):
        for error in (OSError("Unavailable API"), ValueError("Malformed API response")):
            with self.subTest(error=error):
                accepted, requests = self.approval(error=error)
                self.assertFalse(accepted)
                self.assertEqual(len(requests), 1)


MIRROR_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish-mirror.yml"


@unittest.skipUnless(MIRROR_WORKFLOW.is_file(), "The mirror publish workflow is not in this tree.")
class MirrorReleaseTagTest(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.digest = "b" * 64
        self.temporary = tempfile.TemporaryDirectory()
        self.environment = {
            "GITHUB_REPOSITORY": "chickinfry/chickinfry-js",
            "GITHUB_SHA": self.sha,
            "GITHUB_REF": "refs/tags/v0.5.0",
            "GITHUB_EVENT_NAME": "push",
            "GH_TOKEN": "fixture-token",
            "RUNNER_TEMP": self.temporary.name,
        }
        workflow = json.loads(MIRROR_WORKFLOW.read_text())
        sources = []
        for job in ("build", "publish"):
            run = workflow["jobs"][job]["steps"][0]["run"]
            sources.append(run.split("<<'TRUST'\n", 1)[1].split("\nTRUST\n", 1)[0] + "\n")
        self.assertEqual(sources[0], sources[1])
        self.source = compile(sources[0], str(MIRROR_WORKFLOW), "exec")

    def tearDown(self):
        self.temporary.cleanup()

    def tag(self, **changes):
        tag = {"tag": "v0.5.0", "object": {"sha": self.sha, "type": "commit"},
               "message": "Release v0.5.0\n\nnpm-tarball-sha256: " + self.digest + "\n"}
        tag.update(changes)
        return tag

    def verify(self, status="identical", ref=None, tag=None):
        responses = iter(({"status": status},
                          ref or {"object": {"type": "tag", "sha": "c" * 40}},
                          tag or self.tag()))

        def open_api(request, timeout):
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture-token")
            return io.BytesIO(json.dumps(next(responses)).encode())

        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch("urllib.request.build_opener") as opener, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            opener.return_value.open.side_effect = open_api
            try:
                exec(self.source, {})
            except SystemExit as error:
                self.assertEqual(error.code, 1)
                return None
        return (Path(self.temporary.name) / "expected.sha256").read_text().strip()

    def test_annotated_tag_on_main_head_yields_its_digest(self):
        self.assertEqual(self.verify(), self.digest)

    def test_rejected_release_tags(self):
        cases = {
            "older main commit": {"status": "behind"},
            "lightweight tag": {"ref": {"object": {"type": "commit", "sha": self.sha}}},
            "tag on another commit": {"tag": self.tag(object={"sha": "d" * 40, "type": "commit"})},
            "tag of a tag": {"tag": self.tag(object={"sha": self.sha, "type": "tag"})},
            "renamed tag": {"tag": self.tag(tag="v0.5.1")},
            "no digest": {"tag": self.tag(message="Release v0.5.0\n")},
            "two digests": {"tag": self.tag(message="npm-tarball-sha256: " + self.digest
                                            + "\nnpm-tarball-sha256: " + "e" * 64 + "\n")},
            "short digest": {"tag": self.tag(message="npm-tarball-sha256: " + "b" * 63 + "\n")},
        }
        for name, case in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(self.verify(**case))

    def test_wrong_source_is_rejected(self):
        for field, value in (("GITHUB_REPOSITORY", "example/package"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                             ("GITHUB_REF", "refs/tags/v0.5"), ("GITHUB_REF", "refs/heads/main")):
            with self.subTest(field=field, value=value), mock.patch.dict(self.environment, {field: value}):
                self.assertIsNone(self.verify())


if __name__ == "__main__":
    unittest.main()
