from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "fixtures/runtime-matrix.json"
VALIDATOR = ROOT / "scripts/validate-runtime-matrix.py"
GATE = ROOT / "scripts/check-runtime-matrix-evidence.py"
ALIGN_CHECKER = ROOT / "scripts/check-pt-load-alignment.py"
FIXTURE_CHECKER = ROOT / "scripts/check-runtime-fixture.py"
DOTNET = shutil.which("dotnet") or "/root/.dotnet/dotnet"

GATE_MODULE_SPEC = importlib.util.spec_from_file_location("runtime_matrix_gate", GATE)
assert GATE_MODULE_SPEC is not None and GATE_MODULE_SPEC.loader is not None
GATE_MODULE = importlib.util.module_from_spec(GATE_MODULE_SPEC)
GATE_MODULE_SPEC.loader.exec_module(GATE_MODULE)


class RuntimeMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(REGISTRY.read_text(encoding="utf-8"))

    def validate(self, data: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)

    def gate(
        self,
        runtime_root: Path,
        bionic_root: Path,
        fixture_manifest: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        checksum_path = runtime_root / "SHA256SUMS"
        files = sorted({
            path
            for artifact_root in (runtime_root, bionic_root)
            for path in artifact_root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.resolve() != checksum_path.resolve()
        })
        checksum_path.write_text(
            "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.resolve()}\n" for path in files),
            encoding="utf-8",
        )
        args = [sys.executable, str(GATE), "pr", str(runtime_root), str(bionic_root)]
        if fixture_manifest is not None:
            args.append(str(fixture_manifest))
        return subprocess.run(
            args,
            cwd=ROOT,
            env={**os.environ, "PATH": f"{Path(DOTNET).parent}:{os.environ.get('PATH', '')}"},
            capture_output=True,
            text=True,
        )

    def test_registry_covers_reviewed_interactions(self) -> None:
        result = self.validate(self.data)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_image_digest_and_interactions_are_required(self) -> None:
        data = copy.deepcopy(self.data)
        next(cell for cell in data["cells"] if cell["id"] == "glibc.older.ubuntu-22.04-arm64")[
            "imageDigest"
        ] = "latest"
        self.assertNotEqual(self.validate(data).returncode, 0)
        data = copy.deepcopy(self.data)
        next(cell for cell in data["cells"] if cell["id"] == "musl.1.2.5.alpine-3.22.2")[
            "interactions"
        ] = []
        self.assertNotEqual(self.validate(data).returncode, 0)

    def test_musl_recheck_uses_pinned_runtime_after_test_symlink_cleanup(self) -> None:
        root = Path("/tmp/runtime-matrix-artifacts/nightly")
        binary = root / "fixtures/musl-1.2.4-4k"
        self.assertEqual(
            GATE_MODULE.runtime_execution_argv(binary, "Version 1.2.4", root),
            [
                str(root / "package-locks/musl-1.2.4/prefix/lib/libc.so"),
                str(binary),
            ],
        )
        self.assertEqual(
            GATE_MODULE.runtime_execution_argv(
                root / "fixtures/glibc-4k", "glibc 2.39", root
            ),
            [str(root / "fixtures/glibc-4k")],
        )

    def test_page_probe_is_required_but_runtime_claim_is_optional(self) -> None:
        data = copy.deepcopy(self.data)
        cell = next(cell for cell in data["cells"] if cell["id"] == "kernel-page.16k.native-aarch64")
        self.assertTrue(cell["probeRequired"])
        self.assertFalse(cell["claimRequired"])
        self.assertFalse(cell["required"])
        cell["claimRequired"] = True
        self.assertNotEqual(self.validate(data).returncode, 0)

    def test_alignment_checker_checks_every_load_and_rejects_malformed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "readelf.txt"
            report.write_text(
                "LOAD 0x0 0x0 0x0 0x1000 0x1000 R E 0x1000\n"
                "LOAD 0x1000 0x1000 0x1000 0x1000 0x1000 RW 0x1000\n",
                encoding="utf-8",
            )
            valid = subprocess.run(
                [sys.executable, str(ALIGN_CHECKER), str(report), "0x1000"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("validated_pt_load_count=2", valid.stdout)

            wrong_alignment = subprocess.run(
                [sys.executable, str(ALIGN_CHECKER), str(report), "0x4000"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(wrong_alignment.returncode, 0)
            report.write_text("LOAD row with malformed fields\n", encoding="utf-8")
            malformed = subprocess.run(
                [sys.executable, str(ALIGN_CHECKER), str(report), "0x1000"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(malformed.returncode, 0)

    def test_runtime_fixture_checker_requires_arch_loader_and_dependency(self) -> None:
        report_text = """\
Class:                             ELF64
Data:                              2's complement, little endian
Type:                              DYN (Position-Independent Executable file)
Machine:                           AArch64
 LOAD 0x000000 0x000000 0x000000 0x1000 0x1000 R E 0x1000
 LOAD 0x001000 0x001000 0x001000 0x1000 0x1000 RW 0x1000
DYNAMIC 0x001000 0x001000 0x000100 0x000100 RW 0x8
      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]
Dynamic section at offset 0xf00 contains 1 entry:
 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
"""
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "readelf.txt"
            report.write_text(report_text, encoding="utf-8")
            args = [
                sys.executable,
                str(FIXTURE_CHECKER),
                str(report),
                "0x1000",
                "/lib/ld-linux-aarch64.so.1",
                "libc.so.6",
            ]
            valid = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("validated_needed=libc.so.6", valid.stdout)

            wrong_loader = subprocess.run(
                [*args[:-2], "/lib/ld-musl-aarch64.so.1", "libc.so.6"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(wrong_loader.returncode, 0)

            wrong_dependency = subprocess.run(
                [*args[:-1], "libc.so"], capture_output=True, text=True
            )
            self.assertNotEqual(wrong_dependency.returncode, 0)

    def make_core_evidence(self, root: Path) -> None:
        cells = root / "cells"
        cells.mkdir(parents=True)
        selected = ",".join(self.data["tiers"]["pr"])
        claim_cells = "glibc.current.native-arm64,bionic.termux.locked"
        registry_hash = hashlib.sha256(REGISTRY.read_bytes()).hexdigest()
        fixtures = root / "fixtures"
        fixtures.mkdir()
        source = fixtures / "probe.c"
        source.write_text(
            '#include <unistd.h>\n'
            'int main(void){static const char m[]="runtime-matrix-fixture-ok\\n"; '
            'return write(1,m,sizeof(m)-1)==(ssize_t)(sizeof(m)-1)?0:71;}\n',
            encoding="utf-8",
        )
        (root / "run-manifest.txt").write_text(
            "tier=pr\n"
            "execution=native AArch64; emulation=false\n"
            "host_page_size=4096\n"
            f"selected_cells={selected}\n"
            f"validated_claim_cells={claim_cells}\n"
            f"runtime_registry_sha256={registry_hash}\n",
            encoding="utf-8",
        )
        with (root / "run-manifest.txt").open("a", encoding="utf-8") as stream:
            stream.write(
                "host_arch=aarch64\n"
                "host_os_id=ubuntu\n"
                "host_os_version=24.04\n"
                "host_kernel=Linux test\n"
                "covering_rationale=native current glibc plus bionic baseline\n"
            )
        for cell_id, alignment in (
            ("glibc.current.native-arm64", "0x1000"),
            ("glibc.current.native-arm64-16k", "0x4000"),
        ):
            cell = cells / cell_id
            cell.mkdir(parents=True, exist_ok=True)
            fixture_name = {
                "glibc.current.native-arm64": "glibc-4k",
                "glibc.current.native-arm64-16k": "glibc-16k-align",
            }[cell_id]
            binary = fixtures / fixture_name
            subprocess.run(
                [
                    "gcc",
                    "-O2",
                    "-fPIE",
                    "-pie",
                    "-Wl,--build-id=none",
                    f"-Wl,-z,max-page-size={int(alignment, 16)}",
                    str(source),
                    "-o",
                    str(binary),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            readelf_path = cell / "readelf.txt"
            readelf_output = subprocess.run(
                ["readelf", "-hW", "-lW", "-dW", str(binary)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            readelf_path.write_text(readelf_output, encoding="utf-8")
            identity = subprocess.run(
                [
                    sys.executable,
                    str(FIXTURE_CHECKER),
                    str(readelf_path),
                    alignment,
                    "/lib/ld-linux-aarch64.so.1",
                    "libc.so.6",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            (cell / "fixture-identity.txt").write_text(identity, encoding="utf-8")
            alignment_output = subprocess.run(
                [sys.executable, str(ALIGN_CHECKER), str(readelf_path), alignment],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            (cell / "pt-load-alignment.txt").write_text(alignment_output, encoding="utf-8")
            direct = subprocess.run([str(binary)], capture_output=True, check=False, timeout=20)
            self.assertEqual(direct.returncode, 0)
            (cell / "stdout").write_bytes(direct.stdout)
            (cell / "stderr").write_bytes(direct.stderr)
            (cell / "status.txt").write_text("direct=0\nvalidate=0\ncopy=0\n", encoding="utf-8")
            (cell / "oracle.log").write_bytes(
                b"direct=0\nvalidate=0\ncopy=0\n" + direct.stdout
            )
            source_bytes = binary.read_bytes()
            (cell / "parser-copy").write_bytes(source_bytes)
            os.chmod(cell / "parser-copy", binary.stat().st_mode & 0o777)
            copied = subprocess.run(
                [str(cell / "parser-copy")], capture_output=True, check=False, timeout=20
            )
            self.assertEqual(copied.returncode, 0)
            (cell / "copy.stdout").write_bytes(copied.stdout)
            (cell / "copy.stderr").write_bytes(copied.stderr)
            digest = hashlib.sha256(source_bytes).hexdigest()
            (cell / "source.sha256").write_text(
                f"{digest}  {binary.name}\n", encoding="utf-8"
            )
            (cell / "copy.sha256").write_text(f"{digest}  parser-copy\n", encoding="utf-8")
            (cell / "validator.stdout").write_text(
                "Validated AArch64 ET_DYN PieExecutable\n", encoding="utf-8"
            )
            (cell / "validator.stderr").touch()
            (cell / "toolchain-lock.txt").write_text(
                "".join(
                    f"{hashlib.sha256(Path(shutil.which(tool)).read_bytes()).hexdigest()}  {shutil.which(tool)}\n"
                    for tool in ("gcc", "ld", "readelf")
                ),
                encoding="utf-8",
            )
            (cell / "environment.txt").write_text(
                "host_arch=aarch64\nhost_kernel=Linux test\nhost_page_size=4096\n"
                "host_os_id=ubuntu\nhost_os_version=24.04\n"
                "glibc=glibc 2.39\nloader=/lib/ld-linux-aarch64.so.1\n"
                "compiler=gcc (Ubuntu 13.3.0) 13.3.0\ncli_version=8.0.424\n",
                encoding="utf-8",
            )
            (cell / "result.json").write_text(
                json.dumps(
                    {
                        "status": "validated",
                        "directStatus": 0,
                        "validatorStatus": 0,
                        "copyStatus": 0,
                        "streamsMatch": True,
                        "application": "UrProtect CLI validate --no-analysis --copy",
                        "applicationBuildSha256": "sha256:" + hashlib.sha256(
                            (ROOT / "src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll").read_bytes()
                        ).hexdigest(),
                        "sdkVersion": subprocess.run(
                            [DOTNET, "--version"],
                            check=True,
                            capture_output=True,
                            text=True,
                        ).stdout.strip(),
                    }
                ),
                encoding="utf-8",
            )

        (cells / "kernel-page.16k.native-aarch64.result.txt").write_text(
            "probe=completed\n"
            "status=environment-unavailable\n"
            "claim=unknown\n"
            "observed_page_size=4096\n",
            encoding="utf-8",
        )

    def make_bionic_evidence(self, root: Path, *, emulated: bool = False) -> None:
        root.mkdir(parents=True)
        (root / "host-context").mkdir()
        manifest = json.loads((ROOT / "fixtures/manifest.json").read_text(encoding="utf-8"))
        manifest = copy.deepcopy(manifest)
        case = next(item for item in manifest["cases"] if item["id"] == "c-termux-bionic-pie")
        packages = copy.deepcopy(case["host"]["compilerPackages"])
        lock_path = root / "compiler-package-lock.json"
        lock_path.write_text(
            json.dumps(packages, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        fixture_bytes = b"controlled bionic HostContext shared object fixture"
        fixture_digest = hashlib.sha256(fixture_bytes).hexdigest()
        (root / "host-context/build").mkdir(parents=True, exist_ok=True)
        (root / "host-context/build/host-context-entry-fixture.so").write_bytes(fixture_bytes)
        (root / "host-context/entry-fixture.sha256").write_text(
            f"{fixture_digest}  fixture.so\n", encoding="utf-8"
        )
        (root / "host-context/build-and-test.log").write_text(
            "HostContext runtime self-test: PASS\n", encoding="utf-8"
        )
        (root / "host-context/result.txt").write_text(
            "status=validated\nentry=urp_entry\n", encoding="utf-8"
        )
        (root / "host-context/entry-fixture-readelf.txt").write_text(
            "Class: ELF64\nType: DYN (Shared object file)\n"
            "Machine: AArch64\nSymbol: urp_entry\n",
            encoding="utf-8",
        )
        (root / "provenance.txt").write_text(
            "execution=native-arm64-bionic-container\n", encoding="utf-8"
        )
        (root / "baseline.status").write_text("0\n", encoding="utf-8")
        (root / "baseline.stdout").write_text("baseline\n", encoding="utf-8")
        (root / "linker.status").write_text("0\n", encoding="utf-8")
        (root / "linker.stdout").write_text(
            "This is /system/bin/linker64, the helper program for dynamic executables.\n",
            encoding="utf-8",
        )
        sums = "".join(
            f"{package['sha256']}  apt-archives/{Path(package['filename']).name}\n"
            for package in packages
        )
        (root / "package-sha256sums.txt").write_text(sums, encoding="utf-8")
        verification = "".join(
            f"apt-archives/{Path(package['filename']).name}: OK\n"
            for package in packages
        )
        (root / "package-hash-verification.txt").write_text(verification, encoding="utf-8")
        (root / "apt-archives").mkdir()
        for package in packages:
            archive_path = root / "apt-archives" / Path(package["filename"]).name
            archive_path.write_bytes(b"locked package" + package["name"].encode())
            package["sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        case["host"]["compilerPackages"] = packages
        fixture_manifest_path = root / "fixture-manifest.json"
        fixture_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        lock_path.write_text(json.dumps(packages, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (root / "package-sha256sums.txt").write_text(
            "".join(
                f"{package['sha256']}  apt-archives/{Path(package['filename']).name}\n"
                for package in packages
            ),
            encoding="utf-8",
        )
        (root / "package-hash-verification.txt").write_text(
            "".join(
                f"apt-archives/{Path(package['filename']).name}: OK\n"
                for package in packages
            ),
            encoding="utf-8",
        )
        document = {
            "schemaVersion": 1,
            "case": "c-termux-bionic-pie",
            "image": case["host"]["image"],
            "compilerPackages": packages,
            "compilerPackage": case["host"]["compilerPackage"],
            "termuxSourceCommit": case["host"]["sourceCommit"],
            "packageRepository": case["host"]["packageRepository"],
            "status": "validated",
            "execution": "native-arm64-bionic-container",
            "androidRuntime": False,
            "emulation": emulated,
            "packageInputsReproducible": True,
            "packageProvenance": "version-and-sha256-locked-package-set",
            "packageLockSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            "clangVersion": "21.1.8-3",
            "hostKernel": "Linux host",
            "containerKernel": "Linux container",
            "hostPageSize": 4096,
            "containerPageSize": 4096,
            "linker": "/system/bin/linker64",
            "baselineStatus": 0,
            "directLinkerStatus": 0,
            "directLinkerMode": "identity",
            "handoffStatus": "validated-host-context-v2-adapter-self-test",
            "hostContextAdapterOracle": {
                "status": "validated",
                "abi": "HostContext-v1",
                "frame": "HostContext-v2",
                "sealedImage": True,
                "entryDispatch": "urp_entry",
                "executableTemporaryPath": False,
                "fixtureSha256": fixture_digest,
            },
        }
        (root / "result.json").write_text(json.dumps(document), encoding="utf-8")
        self._fixture_manifest_path = fixture_manifest_path

    def test_pr_evidence_gate_consumes_bionic_and_native_page_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_core_evidence(root)
            bionic = root / "bionic"
            self.make_bionic_evidence(bionic)
            result = self.gate(root, bionic, self._fixture_manifest_path)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unavailable_page_probe_cannot_claim_16k_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_core_evidence(root)
            probe = root / "cells/kernel-page.16k.native-aarch64.result.txt"
            probe.write_text(
                "probe=completed\n"
                "status=environment-unavailable\n"
                "claim=validated\n"
                "observed_page_size=4096\n",
                encoding="utf-8",
            )
            bionic = root / "bionic"
            self.make_bionic_evidence(bionic)
            result = self.gate(root, bionic, self._fixture_manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown", result.stderr)

    def test_bionic_emulation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_core_evidence(root)
            bionic = root / "bionic"
            self.make_bionic_evidence(bionic, emulated=True)
            result = self.gate(root, bionic, self._fixture_manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("emulation", result.stderr)

    def test_missing_native_runtime_output_or_execution_fails_evidence_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_core_evidence(root)
            bionic = root / "bionic"
            self.make_bionic_evidence(bionic)
            native = root / "cells/glibc.current.native-arm64"
            (native / "environment.txt").write_text("placeholder\n", encoding="utf-8")
            result = self.gate(root, bionic, self._fixture_manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("native AArch64", result.stderr)

    def test_bionic_package_archives_are_hash_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_core_evidence(root)
            bionic = root / "bionic"
            self.make_bionic_evidence(bionic)
            package = json.loads((bionic / "compiler-package-lock.json").read_text())[0]
            archive = bionic / "apt-archives" / Path(package["filename"]).name
            archive.write_bytes(b"tampered")
            result = self.gate(root, bionic, self._fixture_manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match the lock", result.stderr)

    def test_musl_product_smoke_checks_noop_and_packed_streams(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            smoke = root / "musl-1.2.4-smoke"
            for relative in (
                "build/fixture",
                "no-op-copy",
                "packed-fixture",
                "native-launcher/urprotect-launcher",
                "musl-launcher-toolchain.txt",
                "packed-report.json",
                "readelf.txt",
                "packed-file.txt",
                "packed-readelf.txt",
            ):
                path = smoke / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact\n")
            for status in ("baseline", "output", "packed"):
                (smoke / f"{status}.status").write_text("0\n", encoding="utf-8")
            for output in ("baseline", "output", "packed"):
                (smoke / f"{output}.stdout").write_bytes(b"fixture-output\n")
                (smoke / f"{output}.stderr").touch()
            (smoke / "validator.stdout").write_text("validated\n", encoding="utf-8")
            (smoke / "validator.stderr").touch()
            (smoke / "musl-launcher-toolchain.txt").write_text(
                "musl_source_build=1.2.4\n"
                "musl_toolchain_root=/toolchain\n"
                "musl_base_specs=/toolchain/lib/musl-gcc.specs\n"
                "musl_static_pie_specs=/artifacts/musl-static-pie.specs\n",
                encoding="utf-8",
            )
            GATE_MODULE.check_musl_product_smoke(root)

            (smoke / "packed.stdout").write_bytes(b"tampered\n")
            with self.assertRaises(SystemExit):
                GATE_MODULE.check_musl_product_smoke(root)


if __name__ == "__main__":
    unittest.main()
