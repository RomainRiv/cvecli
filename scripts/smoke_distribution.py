"""Check the built wheel with fresh runtime dependencies, outside the source tree."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "dist").resolve()
    wheels = list(directory.glob("cvecli-*.whl"))
    if len(wheels) != 1:
        raise SystemExit(
            f"Expected one cvecli wheel in {directory}, found {len(wheels)}"
        )
    wheel = wheels[0]
    with tempfile.TemporaryDirectory() as temporary:
        # Neither the project's lockfile nor its development dependencies may
        # mask broken requirements in the artifact users actually install.
        for extra in ("", "[build]"):
            prefix = [
                "uv",
                "run",
                "--isolated",
                "--no-project",
                "--with",
                str(wheel) + extra,
            ]

            def run(*args: str, expected: int = 0) -> subprocess.CompletedProcess:
                result = subprocess.run(
                    [*prefix, *args], cwd=temporary, capture_output=True, text=True
                )
                if result.returncode != expected:
                    raise SystemExit(
                        f"{args}: expected exit {expected}, got {result.returncode}\n"
                        f"{result.stdout}\n{result.stderr}"
                    )
                return result

            expected_version = wheel.name.split("-")[1]
            version = run("cvecli", "--version").stdout.strip()
            if version != expected_version:
                raise SystemExit(f"Expected version {expected_version}, got {version}")
            run("cvecli", "--help")
            for command in ("search", "get", "products", "status", "update"):
                run("cvecli", command, "--help")
            invalid = run(
                "cvecli", "search", "--limit", "invalid", "--json", expected=2
            )
            assert json.loads(invalid.stdout)["errors"][0]["code"] == "invalid_request"
            if extra:
                for command in (
                    "download-json",
                    "extract-parquet",
                    "enrich-nvd",
                    "create-manifest",
                ):
                    run("cvecli-build", command, "--help")
            print(f"Verified {wheel.name}{extra} with isolated runtime dependencies")


if __name__ == "__main__":
    main()
