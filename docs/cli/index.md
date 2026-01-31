# CLI Reference

Complete command-line reference for cvecli.

!!! info "Auto-generated"
    The [commands](commands.md) page is automatically generated from the CLI source code using Typer.
    Run `just docs-generate` to regenerate.

## Quick Reference

| Command | Description |
|---------|-------------|
| `cvecli search` | Search CVEs by product, vendor, CWE, CPE, PURL |
| `cvecli get` | Get details for specific CVE(s) |
| `cvecli stats` | Show database statistics |
| `cvecli products` | Search product/vendor names |
| `cvecli db update` | Update CVE database from pre-built files |
| `cvecli db status` | Show database status |
| `cvecli db build` | Advanced commands for building from source |

## Common Examples

```bash
# Search for CVEs
cvecli search "linux kernel"
cvecli search "apache" --severity critical
cvecli search --purl "pkg:pypi/django"

# Get CVE details
cvecli get CVE-2024-1234
cvecli get CVE-2024-1234 --detailed --format json

# Database management
cvecli db update
cvecli db status
```

See [Commands](commands.md) for the complete reference.
