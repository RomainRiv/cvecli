# Commands

| Command | Purpose |
|---|---|
| `cvecli update` | Verify and install a prebuilt database |
| `cvecli status` | Inspect local readiness and coverage, offline |
| `cvecli search [words]` | Find candidate CVE records |
| `cvecli get ID...` | Read full evidence for up to 100 CVEs |
| `cvecli products words` | Discover recorded names for exact filters |

All commands support `--json` and `--data-dir`. Search and product discovery
support `--limit` and `--offset`. CPE lookup uses `search --cpe NAME`, optionally
with `--version VERSION`, and includes affected/unaffected/unknown evidence. See [generated command help](commands.md).
