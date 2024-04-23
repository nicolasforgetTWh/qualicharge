"""add location address unique constraint

Revision ID: 8580168c2cef
Revises: da896549e09c
Create Date: 2024-04-29 17:23:43.423327

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "8580168c2cef"
down_revision: Union[str, None] = "da896549e09c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, "localisation", ["adresse_station"])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, "localisation", type_="unique")
    # ### end Alembic commands ###
