"""add account lockout

Revision ID: 91234abcde56
Revises: 47765d95ab04
Create Date: 2024-05-22 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '91234abcde56'
down_revision: Union[str, None] = '47765d95ab04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add columns
    op.add_column('users', sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('last_failed_login', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))

    # Remove server_default for failed_login_attempts if we want it to be just an integer column without default on DB level,
    # but keeping it is safer for migrations. I'll leave it or alter it to drop default.
    # Typically it is fine to leave it.
    pass


def downgrade() -> None:
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'last_failed_login')
    op.drop_column('users', 'failed_login_attempts')
    pass
