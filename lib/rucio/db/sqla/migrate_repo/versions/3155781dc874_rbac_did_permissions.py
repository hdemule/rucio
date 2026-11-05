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

"""Turn the RBAC scope permissions into DID permissions, storing their operations as one boolean column each"""    # noqa: D400, D415

import datetime
from typing import Optional

import sqlalchemy as sa
from alembic import context
from alembic.op import bulk_insert, create_check_constraint, create_foreign_key, create_primary_key, create_table, drop_table, execute, get_bind

from rucio.common.schema import get_schema_value

# Alembic revision identifiers
revision = '3155781dc874'
down_revision = '1b1ef522977a'

OLD_TABLE = 'role_scope_permission_map'
OLD_PREFIX = OLD_TABLE.upper()
NEW_TABLE = 'role_did_permission_map'
NEW_PREFIX = NEW_TABLE.upper()

# The operations a permission grants and, since this revision, the column storing each of them.
# Spelled out rather than taken from `DidOperationType`, so that this revision does not depend on later code.
OPERATION_COLUMNS = {'read': 'can_read', 'write': 'can_write', 'delete': 'can_delete'}

# The enum (a native type on PostgreSQL, a check constraint elsewhere) of the operation column of the previous revision
OPERATION_ENUM = f'{OLD_PREFIX}_OPERATION_CHK'

# The name part of a DID pattern matching every DID of the scopes its scope part matches, e.g. 'data*:*'
WHOLE_SCOPE_SUFFIX = ':*'


def _schema() -> Optional[str]:
    return context.get_context().version_table_schema or None


def _scope_pattern_length() -> int:
    return get_schema_value('SCOPE_LENGTH')


def _did_pattern_length() -> int:
    # a scope, a ':' and a name, see `DidPermissionHandler`
    return get_schema_value('SCOPE_LENGTH') + 1 + get_schema_value('NAME_LENGTH')


def _timestamps() -> list[sa.Column]:
    return [sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
            sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)]


def _create_common_constraints(table: str, prefix: str, pattern_column: str, primary_key: list[str]) -> None:
    create_primary_key(f'{prefix}_PK', table, primary_key)
    create_foreign_key(f'{prefix}_ROLE_FK', table, 'roles', ['role'], ['role'], onupdate='CASCADE', ondelete='CASCADE')
    create_check_constraint(f'{prefix}_ROLE_NN', table, 'role is not null')
    create_check_constraint(f'{prefix}_{pattern_column.upper()}_NN', table, f'{pattern_column} is not null')
    create_check_constraint(f'{prefix}_CREATED_NN', table, 'created_at is not null')
    create_check_constraint(f'{prefix}_UPDATED_NN', table, 'updated_at is not null')


def upgrade():
    """
    Upgrade the database to this revision.

    The scope permissions (`role_scope_permission_map`) become DID permissions (`role_did_permission_map`).
    A DID pattern is stored with a scope part and a name part, so every permission is kept on the DID
    pattern matching every DID of the scopes its scope pattern matched: 'data' becomes 'data:*',
    'data*' becomes 'data*:*' and '*' becomes '*:*'.
    A scope permission used to be one row per operation it grants on a scope pattern. It becomes one row
    per DID pattern, with a boolean column per operation. The rows of a role on a scope pattern are merged
    into one, which keeps the earliest creation and the latest update of the rows it replaces.
    """
    dialect = context.get_context().dialect.name
    if dialect not in ['oracle', 'mysql', 'postgresql']:
        return

    old = sa.table(OLD_TABLE,
                   sa.Column('role', sa.String(255)),
                   sa.Column('scope_pattern', sa.String(_scope_pattern_length())),
                   sa.Column('operation', sa.String(6)),
                   *_timestamps(),
                   schema=_schema())
    merged: dict[tuple[str, str], dict] = {}
    for row in get_bind().execute(sa.select(old.c.role, old.c.scope_pattern, old.c.operation, old.c.created_at, old.c.updated_at)):
        permission = merged.setdefault((row.role, row.scope_pattern), {
            'role': row.role, 'did_pattern': row.scope_pattern + WHOLE_SCOPE_SUFFIX, **dict.fromkeys(OPERATION_COLUMNS.values(), False),
            'created_at': row.created_at, 'updated_at': row.updated_at})
        permission[OPERATION_COLUMNS[row.operation]] = True
        permission['created_at'] = min(permission['created_at'], row.created_at)
        permission['updated_at'] = max(permission['updated_at'], row.updated_at)

    operation_enum = None
    if dialect == 'postgresql':
        # The enumerated type is not removed together with the table it belongs to. It is looked up rather than
        # named, since it lives in the schema of the table or in the default one, depending on how the table was created.
        schema = _schema()
        operation_enum = get_bind().execute(
            sa.text("SELECT atttypid::regtype::text FROM pg_attribute WHERE attrelid = CAST(:table AS regclass) AND attname = 'operation'"),
            {'table': f'{schema}.{OLD_TABLE}' if schema else OLD_TABLE}).scalar_one()

    drop_table(OLD_TABLE)
    if operation_enum:
        execute(f'DROP TYPE {operation_enum}')

    new = create_table(NEW_TABLE,
                       sa.Column('role', sa.String(255)),
                       sa.Column('did_pattern', sa.String(_did_pattern_length())),
                       *(sa.Column(column, sa.Boolean, nullable=False, default=False) for column in OPERATION_COLUMNS.values()),
                       *_timestamps())
    _create_common_constraints(NEW_TABLE, NEW_PREFIX, 'did_pattern', ['role', 'did_pattern'])
    for column in OPERATION_COLUMNS.values():
        create_check_constraint(f'{NEW_PREFIX}_{column.upper()}_NN', NEW_TABLE, f'{column} is not null')

    if merged:
        bulk_insert(new, list(merged.values()))


def downgrade():
    """
    Downgrade the database to the previous revision.

    Each DID permission is split back into one scope permission row per operation it grants, on the scope
    pattern of the DID patterns matching whole scopes: 'data:*' becomes 'data', 'data*:*' becomes 'data*'.
    The DID patterns naming DIDs within a scope ('data:raw*', 'data:raw1') have no scope permission
    equivalent, and are dropped together with the permissions granting no operation.
    """
    dialect = context.get_context().dialect.name
    if dialect not in ['oracle', 'mysql', 'postgresql']:
        return

    new = sa.table(NEW_TABLE,
                   sa.Column('role', sa.String(255)),
                   sa.Column('did_pattern', sa.String(_did_pattern_length())),
                   *(sa.Column(column, sa.Boolean) for column in OPERATION_COLUMNS.values()),
                   *_timestamps(),
                   schema=_schema())
    rows = [{'role': row.role, 'scope_pattern': row.did_pattern[:-len(WHOLE_SCOPE_SUFFIX)], 'operation': operation,
             'created_at': row.created_at, 'updated_at': row.updated_at}
            for row in get_bind().execute(sa.select(new))
            if row.did_pattern.endswith(WHOLE_SCOPE_SUFFIX) and len(row.did_pattern) - len(WHOLE_SCOPE_SUFFIX) <= _scope_pattern_length()
            for operation, column in OPERATION_COLUMNS.items() if getattr(row, column)]

    drop_table(NEW_TABLE)

    old = create_table(OLD_TABLE,
                       sa.Column('role', sa.String(255)),
                       sa.Column('scope_pattern', sa.String(_scope_pattern_length())),
                       sa.Column('operation', sa.Enum(*OPERATION_COLUMNS, name=OPERATION_ENUM, create_constraint=True)),
                       *_timestamps())
    _create_common_constraints(OLD_TABLE, OLD_PREFIX, 'scope_pattern', ['role', 'scope_pattern', 'operation'])
    create_check_constraint(f'{OLD_PREFIX}_OPERATION_NN', OLD_TABLE, 'operation is not null')

    if rows:
        bulk_insert(old, rows)
