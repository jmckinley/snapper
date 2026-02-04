"""Data modules for Snapper."""

from app.data.integration_templates import (
    INTEGRATION_TEMPLATES,
    INTEGRATION_CATEGORIES,
    get_templates_by_category,
    get_template,
)

__all__ = [
    "INTEGRATION_TEMPLATES",
    "INTEGRATION_CATEGORIES",
    "get_templates_by_category",
    "get_template",
]
