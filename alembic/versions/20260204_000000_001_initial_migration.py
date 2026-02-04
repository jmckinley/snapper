"""Initial database schema for OpenClaw Rules Manager.

Revision ID: 001
Revises:
Create Date: 2026-02-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create agents table
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("trust_level", sa.String(50), nullable=False, server_default="untrusted"),
        sa.Column("allowed_origins", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("require_localhost_only", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("rate_limit_max_requests", sa.Integer(), nullable=True),
        sa.Column("rate_limit_window_seconds", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_rule_evaluation_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agents_external_id", "agents", ["external_id"], unique=True)
    op.create_index("ix_agents_status", "agents", ["status"])
    op.create_index("ix_agents_status_trust", "agents", ["status", "trust_level"])
    op.create_index("ix_agents_active", "agents", ["is_deleted", "status"])

    # Create rules table
    op.create_table(
        "rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_type", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False, server_default="deny"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("parameters", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("tags", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("source", sa.String(100), nullable=True),
        sa.Column("source_reference", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_rules_agent_id", "rules", ["agent_id"])
    op.create_index("ix_rules_rule_type", "rules", ["rule_type"])
    op.create_index("ix_rules_priority", "rules", ["priority"])
    op.create_index("ix_rules_is_active", "rules", ["is_active"])
    op.create_index("ix_rules_agent_type", "rules", ["agent_id", "rule_type"])
    op.create_index("ix_rules_active_priority", "rules", ["is_active", "priority"])
    op.create_index("ix_rules_evaluation", "rules", ["is_active", "is_deleted", "agent_id", "priority"])

    # Create users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", sa.String(20), nullable=False, server_default="viewer"),
        sa.Column("permissions", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_password_change", sa.DateTime(timezone=True), nullable=True),
        sa.Column("require_password_change", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("preferences", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_active", "users", ["is_active", "role"])

    # Create audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("request_id", sa.String(100), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("origin", sa.String(500), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("endpoint", sa.String(500), nullable=True),
        sa.Column("method", sa.String(10), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("old_value", postgresql.JSONB(), nullable=True),
        sa.Column("new_value", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_severity", "audit_logs", ["severity"])
    op.create_index("ix_audit_logs_agent_id", "audit_logs", ["agent_id"])
    op.create_index("ix_audit_logs_rule_id", "audit_logs", ["rule_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_agent_action", "audit_logs", ["agent_id", "action"])
    op.create_index("ix_audit_logs_severity_time", "audit_logs", ["severity", "created_at"])

    # Create policy_violations table
    op.create_table(
        "policy_violations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("violation_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("audit_log_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("context", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("request_id", sa.String(100), nullable=True),
        sa.Column("is_resolved", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_violations_type", "policy_violations", ["violation_type"])
    op.create_index("ix_violations_severity", "policy_violations", ["severity"])
    op.create_index("ix_violations_agent_id", "policy_violations", ["agent_id"])
    op.create_index("ix_violations_unresolved", "policy_violations", ["is_resolved", "severity"])

    # Create alerts table
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("violation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("notification_channels", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("notification_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_acknowledged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_type", "alerts", ["alert_type"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_unacknowledged", "alerts", ["is_acknowledged", "severity"])

    # Create security_issues table
    op.create_table(
        "security_issues",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("affected_components", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("affected_versions", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("mitigation_rules", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False, server_default="{}"),
        sa.Column("auto_generate_rules", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("mitigation_notes", sa.Text(), nullable=True),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("source_url", sa.String(1000), nullable=True),
        sa.Column("references", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("mitigated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_issues_cve_id", "security_issues", ["cve_id"], unique=True)
    op.create_index("ix_security_issues_severity", "security_issues", ["severity"])
    op.create_index("ix_security_issues_status", "security_issues", ["status"])
    op.create_index("ix_security_issues_active", "security_issues", ["status", "severity"])

    # Create malicious_skills table
    op.create_table(
        "malicious_skills",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("skill_id", sa.String(255), nullable=False),
        sa.Column("skill_name", sa.String(255), nullable=False),
        sa.Column("author", sa.String(255), nullable=True),
        sa.Column("repository_url", sa.String(1000), nullable=True),
        sa.Column("threat_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("analysis_notes", sa.Text(), nullable=True),
        sa.Column("indicators", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("is_blocked", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("reported_by", sa.String(255), nullable=True),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_malicious_skills_skill_id", "malicious_skills", ["skill_id"], unique=True)
    op.create_index("ix_malicious_skills_threat_type", "malicious_skills", ["threat_type"])
    op.create_index("ix_malicious_skills_severity", "malicious_skills", ["severity"])
    op.create_index("ix_malicious_skills_blocked", "malicious_skills", ["is_blocked", "severity"])

    # Create security_recommendations table
    op.create_table(
        "security_recommendations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("impact_score", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("recommended_rules", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("is_one_click", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_applied", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_dismissed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_rule_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recommendations_agent_id", "security_recommendations", ["agent_id"])
    op.create_index("ix_recommendations_severity", "security_recommendations", ["severity"])
    op.create_index("ix_recommendations_pending", "security_recommendations", ["is_applied", "is_dismissed", "severity"])


def downgrade() -> None:
    op.drop_table("security_recommendations")
    op.drop_table("malicious_skills")
    op.drop_table("security_issues")
    op.drop_table("alerts")
    op.drop_table("policy_violations")
    op.drop_table("audit_logs")
    op.drop_table("users")
    op.drop_table("rules")
    op.drop_table("agents")
