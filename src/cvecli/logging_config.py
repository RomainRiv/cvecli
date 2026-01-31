"""Logging configuration for cvecli.

This module provides a centralized logging setup that can be used
throughout the cvecli package. It supports different log levels
and formats for development vs production use.

Usage:
    from cvecli.logging_config import get_logger

    logger = get_logger(__name__)
    logger.info("Processing CVE data")
    logger.debug("Loaded %d records", count)
"""

import logging
import os
import sys
from typing import Optional

# Default log level from environment or INFO
DEFAULT_LOG_LEVEL = os.environ.get("CVECLI_LOG_LEVEL", "WARNING").upper()

# Log format for console output
CONSOLE_FORMAT = "%(levelname)s: %(message)s"

# Detailed format for file output or debug mode
DETAILED_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Date format for detailed logs
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Track if logging has been configured
_logging_configured = False


def configure_logging(
    level: Optional[str] = None,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Configure logging for the cvecli package.

    This should be called once at application startup, typically
    from the CLI entry point.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               If None, uses CVECLI_LOG_LEVEL env var or default.
        verbose: If True, set level to DEBUG.
        quiet: If True, set level to ERROR (suppresses most output).

    Note:
        verbose takes precedence over quiet if both are True.
    """
    global _logging_configured

    # Determine log level
    if verbose:
        log_level = logging.DEBUG
    elif quiet:
        log_level = logging.ERROR
    elif level:
        log_level = getattr(logging, level.upper(), logging.WARNING)
    else:
        log_level = getattr(logging, DEFAULT_LOG_LEVEL, logging.WARNING)

    # Choose format based on level
    log_format = DETAILED_FORMAT if log_level == logging.DEBUG else CONSOLE_FORMAT

    # Configure root logger for cvecli namespace
    cvecli_logger = logging.getLogger("cvecli")
    cvecli_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    cvecli_logger.handlers.clear()

    # Create console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format, datefmt=DATE_FORMAT))

    cvecli_logger.addHandler(console_handler)

    # Prevent propagation to root logger
    cvecli_logger.propagate = False

    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a logger for the given module name.

    Args:
        name: Module name, typically __name__.

    Returns:
        Configured logger instance.

    Example:
        logger = get_logger(__name__)
        logger.info("Starting extraction")
    """
    # Ensure logging is configured
    if not _logging_configured:
        configure_logging()

    # All cvecli loggers should be children of the cvecli logger
    if not name.startswith("cvecli"):
        name = f"cvecli.{name}"

    return logging.getLogger(name)


def set_log_level(level: str) -> None:
    """Change the log level for all cvecli loggers.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    log_level = getattr(logging, level.upper(), logging.WARNING)
    cvecli_logger = logging.getLogger("cvecli")
    cvecli_logger.setLevel(log_level)

    for handler in cvecli_logger.handlers:
        handler.setLevel(log_level)
