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

"""Rename the RBAC scope permission table for type-specific permission tables, and add the limit permission tables"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import create_check_constraint, create_foreign_key, create_primary_key, create_table, drop_constraint, drop_table, execute, rename_table

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '65f9a0e66066'
down_revision = '6a6d3e225f46'

OLD_TABLE = 'role_permission_map'
NEW_TABLE = 'role_scope_permission_map'
LOCAL_LIMIT_TABLE = 'role_local_limit_permission_map'
GLOBAL_LIMIT_TABLE = 'role_global_limit_permission_map'

# The check constraints of the table, as {suffix: condition}
CHECK_CONSTRAINTS = {
    'ROLE_NN': 'role is not null',
    'SCOPE_PATTERN_NN': 'scope_pattern is not null',
    'OPERATION_NN': 'operation is not null',
    'CREATED_NN': 'created_at is not null',
    'UPDATED_NN': 'updated_at is not null',
}


def _rename(old_table: str, new_table: str) -> None:
    """
    Rename the permission table together with its constraints and its operation enum.

    Every type of permission a role can be granted has its own `role_<type>_permission_map` table(s),
    so the scope permission table is renamed accordingly. The rows are kept as they are.
    """
    dialect = context.get_context().dialect.name
    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    old_prefix, new_prefix = old_table.upper(), new_table.upper()

    if dialect in ['oracle', 'postgresql']:
        rename_table(old_table, new_table, schema=schema[:-1] or None)
        for suffix in ['PK', 'ROLE_FK', *CHECK_CONSTRAINTS]:
            execute(f'ALTER TABLE {schema}{new_table} RENAME CONSTRAINT "{old_prefix}_{suffix}" TO "{new_prefix}_{suffix}"')

        if dialect == 'oracle':
            # The operation enum is a check constraint, and the index backing the primary key keeps its own name
            execute(f'ALTER TABLE {schema}{new_table} RENAME CONSTRAINT "{old_prefix}_OPERATION_CHK" TO "{new_prefix}_OPERATION_CHK"')
            execute(f'ALTER INDEX {schema}"{old_prefix}_PK" RENAME TO "{new_prefix}_PK"')
        else:
            # The operation enum is a native type, created unqualified like it is dropped in the previous revision
            execute(f'ALTER TYPE "{old_prefix}_OPERATION_CHK" RENAME TO "{new_prefix}_OPERATION_CHK"')

    elif dialect == 'mysql':
        # MySQL can neither rename foreign keys nor check constraints, so they are recreated.
        # The primary key is always named PRIMARY and the operation enum is a native column type.
        drop_constraint(f'{old_prefix}_ROLE_FK', old_table, type_='foreignkey')
        for suffix in CHECK_CONSTRAINTS:
            execute(f'ALTER TABLE {schema}{old_table} DROP CHECK {old_prefix}_{suffix}')

        rename_table(old_table, new_table, schema=schema[:-1] or None)

        create_foreign_key(f'{new_prefix}_ROLE_FK', new_table, 'roles', ['role'], ['role'], onupdate='CASCADE', ondelete='CASCADE')
        for suffix, condition in CHECK_CONSTRAINTS.items():
            create_check_constraint(f'{new_prefix}_{suffix}', new_table, condition)


def _create_limit_tables() -> None:
    """
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
                         sa.Column('bytes', sa.BigInteger),
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


def _drop_limit_tables() -> None:
    """Drop the tables of the limits of the roles on RSEs."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table(GLOBAL_LIMIT_TABLE)
        drop_table(LOCAL_LIMIT_TABLE)


def upgrade():
    """Upgrade the database to this revision."""
    _rename(OLD_TABLE, NEW_TABLE)
    _create_limit_tables()


def downgrade():
    """Downgrade the database to the previous revision."""
    _drop_limit_tables()
    _rename(NEW_TABLE, OLD_TABLE)
