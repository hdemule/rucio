# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Add the RBAC limit permission tables"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import create_check_constraint, create_foreign_key, create_primary_key, create_table, drop_table

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '1b1ef522977a'
down_revision = '65f9a0e66066'

LOCAL_LIMIT_TABLE = 'role_local_limit_permission_map'
GLOBAL_LIMIT_TABLE = 'role_global_limit_permission_map'


def upgrade():
    """
    Upgrade the database to this revision.

    Create the tables of the limits of the roles on RSEs, like the account limits.
    A local limit caps the usage of an account on one RSE, a global one its usage summed over the
    RSEs an expression matches. A limit is always given, -1 for no cap.
    """
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        for table, target in ((LOCAL_LIMIT_TABLE, sa.Column('rse_id', GUID())),
                              (GLOBAL_LIMIT_TABLE, sa.Column('rse_expression', sa.String(3000)))):
            prefix = table.upper()
            create_table(table,
                         sa.Column('role', sa.String(255)),
                         target,
                         sa.Column('bytes', sa.BigInteger, nullable=False),
                         sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                         sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
            create_primary_key(f'{prefix}_PK', table, ['role', target.name])
            create_foreign_key(f'{prefix}_ROLE_FK', table, 'roles', ['role'], ['role'], onupdate='CASCADE', ondelete='CASCADE')
            create_check_constraint(f'{prefix}_ROLE_NN', table, 'role is not null')
            create_check_constraint(f'{prefix}_{target.name.upper()}_NN', table, f'{target.name} is not null')
            create_check_constraint(f'{prefix}_BYTES_NN', table, 'bytes is not null')
            create_check_constraint(f'{prefix}_BYTES_CHK', table, 'bytes >= -1')
            create_check_constraint(f'{prefix}_CREATED_NN', table, 'created_at is not null')
            create_check_constraint(f'{prefix}_UPDATED_NN', table, 'updated_at is not null')
        create_foreign_key(f'{LOCAL_LIMIT_TABLE.upper()}_RSE_ID_FK', LOCAL_LIMIT_TABLE, 'rses', ['rse_id'], ['id'])


def downgrade():
    """Downgrade the database to the previous revision."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table(GLOBAL_LIMIT_TABLE)
        drop_table(LOCAL_LIMIT_TABLE)
