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

"""Add Role-Based Access Control tables"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import bulk_insert, create_check_constraint, create_foreign_key, create_primary_key, create_table, drop_table

from rucio.common.schema import get_schema_value

# Alembic revision identifiers
revision = '6a6d3e225f46'
down_revision = '1bd076539b6e'

DID_PERMISSION_TABLE = 'role_did_permission_map'
DID_PERMISSION_PREFIX = DID_PERMISSION_TABLE.upper()

# The operations a DID permission grants, one boolean column each.
# Spelled out rather than taken from `DidOperationType`, so that this revision does not depend on later code.
OPERATION_COLUMNS = ('can_read', 'can_write', 'can_delete')


def _did_pattern_length() -> int:
    # a scope, a ':' and a name, see `RoleDidPermissionAssociation`
    return get_schema_value('SCOPE_LENGTH') + 1 + get_schema_value('NAME_LENGTH')


def upgrade():
    """
    Upgrade the database to this revision.

    Create the roles, their assignments to accounts and their DID permissions. A DID permission grants
    operations on the DIDs a DID pattern matches, with one boolean column per operation.
    """
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        roles = create_table('roles',
                             sa.Column('role', sa.String(64)),
                             sa.Column('description', sa.Text),
                             sa.Column('assignable', sa.Boolean, nullable=False, default=True),
                             sa.Column('locked', sa.Boolean, nullable=False, default=True),
                             sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                             sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('ROLES_PK', 'roles', ['role'])
        create_check_constraint('ROLES_ROLE_NN', 'roles', 'role is not null')
        create_check_constraint('ROLES_ASSIGNABLE_NN', 'roles', 'assignable is not null')
        create_check_constraint('ROLES_LOCKED_NN', 'roles', 'locked is not null')
        create_check_constraint('ROLES_CREATED_NN', 'roles', 'created_at is not null')
        create_check_constraint('ROLES_UPDATED_NN', 'roles', 'updated_at is not null')

        # The built-in admin role, locked and not assignable. Spelled out rather than imported, so that this
        # revision always creates the same row whatever the reserved roles of the code are later on.
        now = datetime.datetime.utcnow()
        bulk_insert(roles, [{'role': 'admin', 'description': 'Rucio administrator.', 'assignable': False, 'locked': True,
                             'created_at': now, 'updated_at': now}])

        create_table('account_role_map',
                     sa.Column('account', sa.String(get_schema_value('ACCOUNT_LENGTH'))),
                     sa.Column('role', sa.String(64)),
                     sa.Column('activates_at', sa.DateTime, nullable=False, default=datetime.datetime.utcnow),
                     sa.Column('expires_at', sa.DateTime, default=None),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('ACCOUNT_ROLE_MAP_PK', 'account_role_map', ['account', 'role'])
        create_foreign_key('ACCOUNT_ROLE_MAP_ACCOUNT_FK', 'account_role_map', 'accounts', ['account'], ['account'], ondelete='CASCADE')
        create_foreign_key('ACCOUNT_ROLE_MAP_ROLE_FK', 'account_role_map', 'roles', ['role'], ['role'])
        create_check_constraint('ACCOUNT_ROLE_MAP_ACCOUNT_NN', 'account_role_map', 'account is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_ROLE_NN', 'account_role_map', 'role is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_ACTIVATES_NN', 'account_role_map', 'activates_at is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_EXPIRES_CHK', 'account_role_map', 'expires_at is null or activates_at < expires_at')
        create_check_constraint('ACCOUNT_ROLE_MAP_CREATED_NN', 'account_role_map', 'created_at is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_UPDATED_NN', 'account_role_map', 'updated_at is not null')

        create_table(DID_PERMISSION_TABLE,
                     sa.Column('role', sa.String(64)),
                     sa.Column('did_pattern', sa.String(_did_pattern_length())),
                     *(sa.Column(column, sa.Boolean, nullable=False, default=False) for column in OPERATION_COLUMNS),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key(f'{DID_PERMISSION_PREFIX}_PK', DID_PERMISSION_TABLE, ['role', 'did_pattern'])
        create_foreign_key(f'{DID_PERMISSION_PREFIX}_ROLE_FK', DID_PERMISSION_TABLE, 'roles', ['role'], ['role'], ondelete='CASCADE')
        for column in ('role', 'did_pattern', *OPERATION_COLUMNS):
            create_check_constraint(f'{DID_PERMISSION_PREFIX}_{column.upper()}_NN', DID_PERMISSION_TABLE, f'{column} is not null')
        create_check_constraint(f'{DID_PERMISSION_PREFIX}_CREATED_NN', DID_PERMISSION_TABLE, 'created_at is not null')
        create_check_constraint(f'{DID_PERMISSION_PREFIX}_UPDATED_NN', DID_PERMISSION_TABLE, 'updated_at is not null')


def downgrade():
    """Downgrade the database to the previous revision."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table(DID_PERMISSION_TABLE)
        drop_table('account_role_map')
        drop_table('roles')
