"""MCP Server Catalog model.

Stores metadata fetched from public MCP registries (Smithery, NPM,
awesome-mcp-servers) for auto-generating rule packs and enhancing
traffic discovery.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class MCPServerCatalog(Base):
    """A known MCP server from a public registry."""

    __tablename__ = "mcp_server_catalog"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    normalized_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Lowercase, hyphenated name for deduplication",
    )

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    tools: Mapped[Optional[list]] = mapped_column(
        JSONB,
        default=list,
        nullable=True,
        comment="List of tool names or tool definitions from the registry",
    )

    repository: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    homepage: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Registry source: smithery | npm | awesome-mcp-servers",
    )

    # Sync tracking
    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_mcp_catalog_source_name", "source", "normalized_name"),
    )

    def __repr__(self) -> str:
        return f"<MCPServerCatalog(name={self.name}, source={self.source})>"
