"""make user email unique

Revision ID: 3418dcb45915
Revises: 7568f5ff860e
Create Date: 2024-05-20 18:44:04.586287

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3418dcb45915"
down_revision: Union[str, None] = "7568f5ff860e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, "user", ["email"])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, "user", type_="unique")
    # ### end Alembic commands ###