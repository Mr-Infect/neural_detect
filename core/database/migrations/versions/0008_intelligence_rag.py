"""Phase 7 threat intelligence provenance, ATT&CK and retrieval records."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0008_intelligence_rag"
down_revision = "0007_soc_agents"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "intelligence_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_name", sa.String(160), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("source_object_id", sa.String(512), nullable=False),
        sa.Column("object_type", sa.String(80), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("source_modified_at", sa.DateTime(timezone=True)),
        sa.Column("source_version", sa.String(128)),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("raw_object", sa.JSON(), nullable=False),
    )
    op.create_index("ix_intelligence_documents_tenant_id", "intelligence_documents", ["tenant_id"])
    op.create_index("ix_intelligence_documents_object_type", "intelligence_documents", ["object_type"])
    op.create_index("ix_intelligence_documents_active", "intelligence_documents", ["active"])
    op.create_index("ix_intel_doc_tenant_source_id", "intelligence_documents", ["tenant_id", "source_object_id"])
    op.create_index("ix_intel_doc_tenant_hash", "intelligence_documents", ["tenant_id", "content_hash"])

    op.create_table(
        "intelligence_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("intelligence_documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("point_id", sa.String(36), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("document_id", "ordinal", name="uq_intel_chunk_document_ordinal"),
    )
    op.create_index("ix_intelligence_chunks_document_id", "intelligence_chunks", ["document_id"])
    op.create_index("ix_intelligence_chunks_tenant_id", "intelligence_chunks", ["tenant_id"])

    op.create_table(
        "threat_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("intelligence_documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("stix_id", sa.String(512), nullable=False),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized_value", sa.Text(), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Integer()),
        sa.Column("valid_from", sa.DateTime(timezone=True)),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.Column("labels", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("related_objects", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("provenance", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.UniqueConstraint("tenant_id", "stix_id", name="uq_threat_indicator_tenant_stix"),
    )
    op.create_index("ix_threat_indicators_document_id", "threat_indicators", ["document_id"])
    op.create_index("ix_threat_indicators_tenant_id", "threat_indicators", ["tenant_id"])
    op.create_index("ix_threat_indicators_indicator_type", "threat_indicators", ["indicator_type"])
    op.create_index("ix_threat_indicator_lookup", "threat_indicators", ["tenant_id", "indicator_type", "normalized_value"])

    op.create_table(
        "attack_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("attack_domain", sa.String(40), nullable=False, server_default="enterprise-attack"),
        sa.Column("technique_id", sa.String(32), nullable=False),
        sa.Column("stix_id", sa.String(512), nullable=False, unique=True),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("tactics", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("platforms", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("data_sources", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("external_url", sa.Text()),
        sa.Column("source_version", sa.String(128)),
        sa.Column("source_modified_at", sa.DateTime(timezone=True)),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("attack_domain", "technique_id", name="uq_attack_technique_domain_id"),
    )
    op.create_index("ix_attack_techniques_name", "attack_techniques", ["name"])

    op.create_table(
        "intelligence_sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_name", sa.String(160), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="running"),
        sa.Column("source_version", sa.String(128)),
        sa.Column("bundle_hash", sa.String(64)),
        sa.Column("objects_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("documents_written", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("indicators_written", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("techniques_written", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_intelligence_sync_runs_tenant_id", "intelligence_sync_runs", ["tenant_id"])
    op.create_index("ix_intelligence_sync_runs_status", "intelligence_sync_runs", ["status"])

    op.create_table(
        "intelligence_dataset_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("dataset", sa.String(80), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("dataset", "version", "content_hash", name="uq_intel_dataset_version_hash"),
    )
    op.create_index("ix_intelligence_dataset_versions_current", "intelligence_dataset_versions", ["current"])


def downgrade():
    op.drop_table("intelligence_dataset_versions")
    op.drop_table("intelligence_sync_runs")
    op.drop_table("attack_techniques")
    op.drop_table("threat_indicators")
    op.drop_table("intelligence_chunks")
    op.drop_table("intelligence_documents")
