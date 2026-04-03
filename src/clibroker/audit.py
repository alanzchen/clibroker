"""Structured audit logging using structlog."""

from __future__ import annotations

import structlog


def configure_logging() -> None:
    """Configure structlog for JSON-formatted audit output."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_audit_logger() -> structlog.stdlib.BoundLogger:
    """Return a named audit logger."""
    return structlog.get_logger("clibroker.audit")
