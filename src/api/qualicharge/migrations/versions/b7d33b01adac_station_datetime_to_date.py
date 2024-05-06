"""station datetime to date

Revision ID: b7d33b01adac
Revises: 2664a0b4ce11
Create Date: 2024-04-25 14:12:56.953852

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7d33b01adac"
down_revision: Union[str, None] = "2664a0b4ce11"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column(
        "station",
        "date_maj",
        existing_type=postgresql.TIMESTAMP(),
        type_=sa.Date(),
        existing_nullable=False,
    )
    op.alter_column(
        "station",
        "date_mise_en_service",
        existing_type=postgresql.TIMESTAMP(),
        type_=sa.Date(),
        existing_nullable=True,
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column(
        "station",
        "date_mise_en_service",
        existing_type=sa.Date(),
        type_=postgresql.TIMESTAMP(),
        existing_nullable=True,
    )
    op.alter_column(
        "station",
        "date_maj",
        existing_type=sa.Date(),
        type_=postgresql.TIMESTAMP(),
        existing_nullable=False,
    )
    # ### end Alembic commands ###