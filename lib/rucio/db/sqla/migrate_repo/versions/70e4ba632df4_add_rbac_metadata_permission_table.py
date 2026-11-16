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

"""Add the RBAC metadata permission table"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import create_check_constraint, create_foreign_key, create_primary_key, create_table, drop_table

from rucio.common.schema import get_schema_value

# Alembic revision identifiers
revision = '70e4ba632df4'
down_revision = '3155781dc874'

TABLE = 'role_metadata_permission_map'
PREFIX = TABLE.upper()

# The columns storing the operations a permission grants.
# Spelled out rather than taken from `MetadataOperationType`, so that this revision does not depend on later code.
OPERATION_COLUMNS = ('can_read', 'can_write')

# Intentionally shorter than did_keys.key (255): with 255, the primary key (role, did_pattern, meta_key) would be
# 786 characters, i.e. 3144 bytes in utf8mb4, over the 3072 bytes MySQL (InnoDB) allows for an index.
META_KEY_LENGTH = 128

# The reserved value of `meta_key` naming no key at all, which may only grant READ.
# Spelled out rather than taken from `rucio.db.sqla.constants`, so that this revision does not depend on later code.
NO_KEY = ':none:'


def _did_pattern_length() -> int:
    # a scope, a ':' and a name, like the DID patterns of `role_did_permission_map`
    return get_schema_value('SCOPE_LENGTH') + 1 + get_schema_value('NAME_LENGTH')


def upgrade():
    """
    Upgrade the database to this revision.

    Create the table of the permissions of the roles on metadata keys. A row grants operations on one
    metadata key of the DIDs a DID pattern matches, overriding for that key what the DID permissions of
    the role grant, even when it grants no operation. The key '*' stands for every key, ':none:' for no
    key at all, which may only grant READ.
    """
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table(TABLE,
                     sa.Column('role', sa.String(255)),
                     sa.Column('did_pattern', sa.String(_did_pattern_length())),
                     sa.Column('meta_key', sa.String(META_KEY_LENGTH)),
                     *(sa.Column(column, sa.Boolean, nullable=False, default=False) for column in OPERATION_COLUMNS),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key(f'{PREFIX}_PK', TABLE, ['role', 'did_pattern', 'meta_key'])
        create_foreign_key(f'{PREFIX}_ROLE_FK', TABLE, 'roles', ['role'], ['role'], onupdate='CASCADE', ondelete='CASCADE')
        for column in ('role', 'did_pattern', 'meta_key', *OPERATION_COLUMNS):
            create_check_constraint(f'{PREFIX}_{column.upper()}_NN', TABLE, f'{column} is not null')
        create_check_constraint(f'{PREFIX}_CREATED_NN', TABLE, 'created_at is not null')
        create_check_constraint(f'{PREFIX}_UPDATED_NN', TABLE, 'updated_at is not null')
        # an expression rather than text, so that each database compares the boolean its own way (0 on Oracle)
        create_check_constraint(f'{PREFIX}_NO_KEY_CHK', TABLE, sa.or_(sa.column('meta_key') != NO_KEY, sa.column('can_write') == sa.false()))


def downgrade():
    """
    Downgrade the database to the previous revision.

    The metadata permissions have no equivalent in the previous revision and are dropped.
    """
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table(TABLE)
