"""The small user-facing reference CLI."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
import polars as pl
import requests
import typer
from typer.core import TyperGroup

from cvecli import __version__
from cvecli.core.config import Config
from cvecli.services.artifact_fetcher import ArtifactFetcher
from cvecli.services.search import CVESearchService, ReferenceError, SearchRequest
from cvecli.exceptions import ChecksumMismatchError, ManifestIncompatibleError


def render(response: dict, as_json: bool) -> None:
    """Render once, from the same data for humans and machines."""
    if as_json:
        print(json.dumps(response, ensure_ascii=False, indent=2))
        return
    database = response.get("database", {})
    if database:
        print(
            f"Database: {database.get('release') or 'local'}; built {database.get('built_at') or 'unknown'}"
        )
        print("CVE records only; absence of a match does not establish safety.")
    if "ready" in response:
        print("Ready" if response["ready"] else "Not ready: run 'cvecli update'.")
        print(f"Directory: {response['directory']}")
        print(f"Records: {response.get('records', 'unknown')}")
        if response["missing_tables"]:
            print("Missing: " + ", ".join(response["missing_tables"]))
    if "status" in response:
        print(f"{response['status']}: {response.get('tag', '')}")
    for record in response.get("results", []):
        if "id" not in record:
            print(
                f"{record.get('vendor') or '?'} / {record.get('product') or '?'} — {record['record_count']} records"
            )
            continue
        print(f"\n{record['id']}  {record.get('title') or '(no title)'}")
        print(
            f"State: {record['state']}; published: {record.get('published') or 'unknown'}"
        )
        metric = record.get("cvss")
        if metric:
            print(
                f"CVSS {metric['version']}: {metric['score']} ({metric['severity'] or 'unlabeled'}; {metric['source']})"
            )
        print(record.get("description") or "No description recorded.")
        if record.get("description_truncated"):
            print("[Excerpt; use get for the full record.]")
        if record.get("matched_fields"):
            print("Matched: " + ", ".join(record["matched_fields"]))
        # Detailed evidence is displayed without invented affected/fixed conclusions.
        for field in ("descriptions", "products", "metrics", "references", "cwes"):
            if field in record:
                print(f"{field}: {json.dumps(record[field], ensure_ascii=False)}")
    if "total" in response:
        print(
            f"\n{len(response['results'])} of {response['total']} records (offset {response['offset']})."
        )
        if response.get("next_offset") is not None:
            print(f"Next page: --offset {response['next_offset']}")
    for error in response.get("errors", []):
        print(
            f"{error['code']}: {error.get('id', '')} {error['message']}",
            file=sys.stderr,
        )


class ReferenceGroup(TyperGroup):
    """Handle parsing and operational errors before rendering any output."""

    def main(
        self,
        args=None,
        prog_name=None,
        complete_var=None,
        standalone_mode=True,
        windows_expand_args=True,
        **kwargs,
    ):
        arguments = list(args if args is not None else sys.argv[1:])
        as_json = "--json" in arguments
        kwargs.pop("standalone_mode", None)
        try:
            result = super().main(
                args=arguments,
                prog_name=prog_name,
                complete_var=complete_var,
                standalone_mode=False,
                windows_expand_args=windows_expand_args,
                **kwargs,
            )
            if isinstance(result, int) and result:
                raise SystemExit(result)
            return result
        except click.exceptions.Exit:
            raise
        except (
            ReferenceError,
            click.ClickException,
            OSError,
            ValueError,
            requests.RequestException,
            pl.exceptions.PolarsError,
            ChecksumMismatchError,
            ManifestIncompatibleError,
        ) as error:
            if isinstance(error, ReferenceError):
                code = error.code
            elif isinstance(error, click.ClickException):
                code = "invalid_request"
            else:
                code = "unavailable"
            render(
                {
                    "schema_version": 1,
                    "results": [],
                    "errors": [{"code": code, "message": str(error)}],
                },
                as_json,
            )
            raise SystemExit(2 if code == "invalid_request" else 1) from None


app = typer.Typer(
    cls=ReferenceGroup,
    help="Search local CVE records and inspect their evidence.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


def version_callback(value: bool) -> None:
    if value:
        print(__version__)
        raise typer.Exit()


@app.callback()
def callback(
    version: bool = typer.Option(
        False, "--version", callback=version_callback, is_eager=True
    )
) -> None:
    pass


def service(data_dir: Optional[Path]) -> CVESearchService:
    return CVESearchService(Config(data_dir=data_dir))


@app.command()
def search(
    query: str = typer.Argument(
        "", help="Words to find across titles, descriptions, vendors and products."
    ),
    product: Optional[str] = typer.Option(
        None, help="Exact product name, ignoring case."
    ),
    vendor: Optional[str] = typer.Option(
        None, help="Exact vendor name, ignoring case."
    ),
    purl: Optional[str] = typer.Option(
        None, help="Package identity; any version is reported, not evaluated."
    ),
    cwe: Optional[str] = typer.Option(None, help="CWE ID, e.g. CWE-79."),
    min_score: Optional[float] = typer.Option(
        None, help="Minimum selected CVSS score (0–10)."
    ),
    after: Optional[str] = typer.Option(None, help="Published on or after YYYY-MM-DD."),
    before: Optional[str] = typer.Option(
        None, help="Published on or before YYYY-MM-DD."
    ),
    state: str = typer.Option("published", help="published, rejected, or all."),
    limit: int = typer.Option(20, help="Records per page (1–100)."),
    offset: int = typer.Option(
        0, help="Records to skip; keep the same query and snapshot."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit a single JSON response."),
    data_dir: Optional[Path] = typer.Option(None, help="Database storage root."),
) -> None:
    """Find candidate CVE records. This does not assess installed software."""
    request = SearchRequest(
        query,
        product,
        vendor,
        purl,
        cwe,
        min_score,
        after,
        before,
        state,
        limit,
        offset,
    )
    render(service(data_dir).search(request), as_json)


@app.command()
def get(
    ids: list[str] = typer.Argument(
        ..., help="One or more CVE-YYYY-NNNN IDs (maximum 100)."
    ),
    as_json: bool = typer.Option(False, "--json"),
    data_dir: Optional[Path] = typer.Option(None),
) -> None:
    """Read full descriptions, product version entries, metrics and references."""
    response = service(data_dir).get(ids)
    render(response, as_json)
    if response["errors"]:
        raise typer.Exit(1)


@app.command()
def products(
    query: str = typer.Argument(...),
    limit: int = typer.Option(20),
    offset: int = typer.Option(0),
    as_json: bool = typer.Option(False, "--json"),
    data_dir: Optional[Path] = typer.Option(None),
) -> None:
    """Discover recorded vendor/product names for exact search filters."""
    render(service(data_dir).products(query, limit, offset), as_json)


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json"),
    data_dir: Optional[Path] = typer.Option(None),
) -> None:
    """Inspect local readiness and coverage, without a network request."""
    response = service(data_dir).status()
    render(response, as_json)
    if not response["ready"]:
        raise typer.Exit(1)


@app.command()
def update(
    force: bool = typer.Option(False, help="Download even if current."),
    tag: Optional[str] = typer.Option(None, help="Pin a release tag."),
    as_json: bool = typer.Option(False, "--json"),
    data_dir: Optional[Path] = typer.Option(None),
) -> None:
    """Download and verify a prebuilt database, retaining one previous snapshot."""
    config = Config(data_dir=data_dir)
    response = ArtifactFetcher(config, quiet=True).update(tag=tag, force=force)
    response["schema_version"] = 1
    response["database"] = CVESearchService(config).metadata()
    response["errors"] = []
    render(response, as_json)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
