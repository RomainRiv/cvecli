#!/usr/bin/env python3
"""Generate CLI documentation using Typer's built-in docs generator.

Usage:
    python scripts/generate_cli_docs.py
    # Or via justfile:
    just docs-generate
"""

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent
CLI_DOCS_DIR = PROJECT_ROOT / "docs" / "cli"


def main() -> None:
    """Generate CLI documentation using Typer."""
    print("Generating CLI documentation...")

    CLI_DOCS_DIR.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "typer",
            "src/cvecli/cli/main.py",
            "utils",
            "docs",
            "--name",
            "cvecli",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Error generating CLI docs: {result.stderr}")
        sys.exit(1)

    output_file = CLI_DOCS_DIR / "commands.md"
    output_file.write_text(result.stdout)
    print(f"Generated: {output_file}")


if __name__ == "__main__":
    main()
