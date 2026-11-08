# Storage configuration

`Config.data_dir` is the stable storage root. `Config.database_dir` resolves the
snapshot once; a new reader resolves the current snapshot. Flat databases work too.

Defaults use `~/Library/Application Support/cvecli` on macOS, `LOCALAPPDATA/cvecli`
on Windows, and `XDG_DATA_HOME/cvecli` (or `~/.local/share/cvecli`) elsewhere.
`CVE_DATA_DIR` overrides storage. Build downloads use `CVE_DOWNLOAD_DIR` or the
storage root's `download` directory. No directories are created by read-only commands.

::: cvecli.core.config.Config
