# Justfile for cvecli project
# Run 'just --list' to see all available recipes

# Default recipe (runs when you just type 'just')
default:
    @just --list

# Install the package in development mode with dev dependencies
install:
    uv pip install -e ".[dev]"

# Install all dependencies
sync:
    uv sync --all-extras

# Generate test fixtures
generate-fixtures:
    uv run python tests/fixtures/generate_fixtures.py

# Run tests with pytest
test: generate-fixtures
    uv run pytest tests/ -v

# Run only unit tests
test-unit: generate-fixtures
    uv run pytest tests/unit/ -v -m unit

# Run only integration tests
test-integration: generate-fixtures
    uv run pytest tests/integration/ -v -m integration

# Run fast tests (exclude slow and requires_real_data)
test-fast: generate-fixtures
    uv run pytest tests/ -v -m "not slow and not requires_real_data"

# Run tests with coverage report
test-cov: generate-fixtures
    uv run pytest tests/ -v --cov=src/cvecli --cov-report=term-missing --cov-report=html

# Format code with Black
format:
    uv run black src/ tests/ examples/

# Check code formatting without making changes
format-check:
    uv run black --check src/ tests/ examples/

# Run type checking with mypy
typecheck:
    uv run mypy src/cvecli

# Run type checking with ty
ty:
    uv run ty check src/cvecli

# Lint code with ruff
lint:
    uv run ruff check src/ tests/

# Lint and fix code with ruff
lint-fix:
    uv run ruff check --fix src/ tests/

# Run all checks (format check, type check, and lint)
check: format-check typecheck ty lint

# Build the package
build:
    uv build

# Clean build artifacts and cache files
clean:
    rm -rf build/
    rm -rf dist/
    rm -rf src/*.egg-info
    rm -rf .pytest_cache
    rm -rf htmlcov
    rm -rf .coverage
    rm -rf .mypy_cache
    find . -type d -name __pycache__ -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete

# Run the CLI (example usage)
run *ARGS:
    uv run cvecli {{ARGS}}

# Full CI pipeline (format, check, test)
ci: format-check typecheck ty lint test

# Prepare for release (format, check, test, build)
release: format check test build
    @echo "Package ready for release in dist/"

# ============================================================================
# Documentation commands
# ============================================================================

# Generate CLI documentation from source using Typer
docs-generate:
    uv run python scripts/generate_cli_docs.py

# Build documentation site (includes CLI generation)
docs-build: docs-generate
    uv run mkdocs build

# Serve documentation locally with live reload
docs-serve: docs-generate
    uv run mkdocs serve --open

# Clean generated documentation files
docs-clean:
    rm -rf site/
    rm -f docs/cli/commands.md

