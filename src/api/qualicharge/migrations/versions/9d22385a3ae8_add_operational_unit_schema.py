"""add operational unit schema

Revision ID: 9d22385a3ae8
Revises: 3386c644d6ba
Create Date: 2024-05-15 13:39:40.102631

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

# revision identifiers, used by Alembic.
revision: str = "9d22385a3ae8"
down_revision: Union[str, None] = "3386c644d6ba"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "operationalunit",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sqlmodel.sql.sqltypes.GUID(), nullable=False),
        sa.Column("code", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column(
            "type",
            sa.Enum("CHARGING", "MOBILITY", name="operationalunittypeenum"),
            nullable=False,
        ),
        sa.CheckConstraint("created_at <= updated_at", name="pre-creation-update"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_operationalunit_code"), "operationalunit", ["code"], unique=True
    )
    op.add_column(
        "station",
        sa.Column("operational_unit_id", sqlmodel.sql.sqltypes.GUID(), nullable=True),
    )
    op.create_foreign_key(
        None, "station", "operationalunit", ["operational_unit_id"], ["id"]
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, "station", type_="foreignkey")
    op.drop_column("station", "operational_unit_id")
    op.drop_index(op.f("ix_operationalunit_code"), table_name="operationalunit")
    op.drop_table("operationalunit")
    # ### end Alembic commands ###
