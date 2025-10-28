"""Initial database schema for scan history tracking.

Revision ID: 001
Revises:
Create Date: 2024-01-15 12:00:00

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial schema."""
    # Create scan_records table
    op.create_table(
        "scan_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", sa.String(100), unique=True, nullable=False),
        sa.Column("scan_timestamp", sa.DateTime(), nullable=False),
        sa.Column("scan_duration", sa.Float(), nullable=False),
        sa.Column("scanner_version", sa.String(50)),
        sa.Column("target_type", sa.String(20)),
        sa.Column("target_path", sa.Text()),
        sa.Column("repository_url", sa.Text()),
        sa.Column("repository_name", sa.String(200)),
        sa.Column("branch", sa.String(100)),
        sa.Column("commit_hash", sa.String(40)),
        sa.Column("files_scanned", sa.Integer(), default=0),
        sa.Column("total_lines_scanned", sa.Integer(), default=0),
        sa.Column("languages_detected", sa.JSON()),
        sa.Column("ai_analysis_enabled", sa.Boolean(), default=False),
        sa.Column("patterns_used", sa.JSON()),
        sa.Column("total_vulnerabilities", sa.Integer(), default=0),
        sa.Column("critical_count", sa.Integer(), default=0),
        sa.Column("high_count", sa.Integer(), default=0),
        sa.Column("medium_count", sa.Integer(), default=0),
        sa.Column("low_count", sa.Integer(), default=0),
        sa.Column("user_id", sa.String(100)),
        sa.Column("user_email", sa.String(200)),
    )
    op.create_index("ix_scan_records_scan_id", "scan_records", ["scan_id"])

    # Create vulnerability_records table
    op.create_table(
        "vulnerability_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vulnerability_type", sa.String(100), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity"),
            nullable=False,
        ),
        sa.Column(
            "confidence",
            sa.Enum("HIGH", "MEDIUM", "LOW", name="confidence"),
            nullable=False,
        ),
        sa.Column("cwe_id", sa.String(20)),
        sa.Column("owasp_category", sa.String(50)),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text()),
        sa.Column("explanation", sa.Text()),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_number", sa.Integer()),
        sa.Column("column_number", sa.Integer()),
        sa.Column("end_line_number", sa.Integer()),
        sa.Column("end_column_number", sa.Integer()),
        sa.Column("code_snippet", sa.Text()),
        sa.Column("ai_analyzed", sa.Boolean(), default=False),
        sa.Column("false_positive_probability", sa.Float()),
        sa.Column("ai_confidence", sa.Float()),
        sa.Column("references", sa.JSON()),
        sa.Column("status", sa.String(20), default="open"),
        sa.Column("fixed_at", sa.DateTime()),
        sa.Column("fixed_in_commit", sa.String(40)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime()),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_records.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_vulnerability_records_scan_id", "vulnerability_records", ["scan_id"])
    op.create_index("ix_vulnerability_records_severity", "vulnerability_records", ["severity"])
    op.create_index("ix_vulnerability_records_cwe_id", "vulnerability_records", ["cwe_id"])

    # Create scan_comparisons table
    op.create_table(
        "scan_comparisons",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("baseline_scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("current_scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("comparison_timestamp", sa.DateTime(), nullable=False),
        sa.Column("new_vulnerabilities", sa.Integer(), default=0),
        sa.Column("fixed_vulnerabilities", sa.Integer(), default=0),
        sa.Column("persistent_vulnerabilities", sa.Integer(), default=0),
        sa.Column("severity_increased", sa.Integer(), default=0),
        sa.Column("severity_decreased", sa.Integer(), default=0),
        sa.Column("changes_detail", sa.JSON()),
        sa.Column("overall_trend", sa.String(20)),
        sa.Column("risk_score_change", sa.Float()),
        sa.ForeignKeyConstraint(["baseline_scan_id"], ["scan_records.id"]),
        sa.ForeignKeyConstraint(["current_scan_id"], ["scan_records.id"]),
    )

    # Create pattern_usage table
    op.create_table(
        "pattern_usage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pattern_name", sa.String(100), nullable=False),
        sa.Column("pattern_category", sa.String(50)),
        sa.Column("cwe_id", sa.String(20)),
        sa.Column("times_triggered", sa.Integer(), default=0),
        sa.Column("true_positives", sa.Integer(), default=0),
        sa.Column("false_positives", sa.Integer(), default=0),
        sa.Column("accuracy_rate", sa.Float()),
        sa.Column("avg_severity", sa.Float()),
        sa.Column("first_used", sa.DateTime()),
        sa.Column("last_used", sa.DateTime()),
        sa.Column("stats_period_start", sa.DateTime()),
        sa.Column("stats_period_end", sa.DateTime()),
    )
    op.create_index("ix_pattern_usage_pattern_name", "pattern_usage", ["pattern_name"])
    op.create_index("ix_pattern_usage_cwe_id", "pattern_usage", ["cwe_id"])

    # Create llm_usage_metrics table
    op.create_table(
        "llm_usage_metrics",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("total_requests", sa.Integer(), default=0),
        sa.Column("successful_requests", sa.Integer(), default=0),
        sa.Column("failed_requests", sa.Integer(), default=0),
        sa.Column("prompt_tokens", sa.Integer(), default=0),
        sa.Column("completion_tokens", sa.Integer(), default=0),
        sa.Column("total_tokens", sa.Integer(), default=0),
        sa.Column("estimated_cost", sa.Float(), default=0.0),
        sa.Column("cost_per_vulnerability", sa.Float()),
        sa.Column("avg_response_time", sa.Float()),
        sa.Column("total_api_time", sa.Float()),
        sa.Column("cache_hits", sa.Integer(), default=0),
        sa.Column("cache_misses", sa.Integer(), default=0),
        sa.Column("cache_hit_rate", sa.Float()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_records.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_llm_usage_metrics_scan_id", "llm_usage_metrics", ["scan_id"])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table("llm_usage_metrics")
    op.drop_table("pattern_usage")
    op.drop_table("scan_comparisons")
    op.drop_table("vulnerability_records")
    op.drop_table("scan_records")
    op.execute("DROP TYPE IF EXISTS severity")
    op.execute("DROP TYPE IF EXISTS confidence")
