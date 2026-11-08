"""Compatibility wrapper for source checkouts; installed builds use cvecli-build."""

from cvecli.cli.build import main

if __name__ == "__main__":
    main()
