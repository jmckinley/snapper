"""MCP Server Catalog model.

Stores metadata fetched from public MCP registries (Smithery, NPM,
awesome-mcp-servers, PulseMCP, Glama) for auto-generating rule packs
and enhancing traffic discovery.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
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
        comment="Registry source: smithery | npm | awesome-mcp-servers | pulsemcp | glama",
    )

    # Enrichment columns (Part A catalog upgrade)
    trust_tier: Mapped[str] = mapped_column(
        String(20),
        server_default="unknown",
        nullable=False,
        comment="curated | verified | community | unknown",
    )

    security_metadata: Mapped[dict] = mapped_column(
        JSONB,
        server_default="{}",
        nullable=False,
        comment="Auth options, license info, security grades",
    )

    auth_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="open | oauth | api_key | unknown",
    )

    popularity_score: Mapped[int] = mapped_column(
        Integer,
        server_default="0",
        nullable=False,
        comment="Normalized 0-100 from visitor stats",
    )

    tools_count: Mapped[int] = mapped_column(
        Integer,
        server_default="0",
        nullable=False,
        comment="Count of known tools",
    )

    categories: Mapped[list] = mapped_column(
        JSONB,
        server_default="[]",
        nullable=False,
        comment="Category tags",
    )

    is_official: Mapped[bool] = mapped_column(
        Boolean,
        server_default="false",
        nullable=False,
        comment="First-party server flag",
    )

    security_category: Mapped[str] = mapped_column(
        String(30),
        server_default="general",
        nullable=False,
        index=True,
        comment="Security category for rule template selection",
    )

    pulsemcp_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="PulseMCP ID for incremental sync",
    )

    glama_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Glama ID for cross-reference",
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
        Index("ix_mcp_catalog_trust_tier", "trust_tier"),
        Index("ix_mcp_catalog_popularity", popularity_score.desc()),
    )

    def __repr__(self) -> str:
        return f"<MCPServerCatalog(name={self.name}, source={self.source}, trust={self.trust_tier})>"


class MCPCatalogSyncState(Base):
    """Tracks sync state per catalog source for incremental updates."""

    __tablename__ = "mcp_catalog_sync_state"

    source: Mapped[str] = mapped_column(
        String(50),
        primary_key=True,
    )

    last_synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_cursor: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Pagination cursor for incremental sync",
    )

    entries_count: Mapped[int] = mapped_column(
        Integer,
        server_default="0",
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<MCPCatalogSyncState(source={self.source}, entries={self.entries_count})>"
