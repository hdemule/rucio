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

"""Add Rule-Based Access Control tables"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import create_check_constraint, create_foreign_key, create_primary_key, create_table, drop_table, execute

from rucio.common.schema import get_schema_value
from rucio.db.sqla.constants import DatabaseOperationType

# Alembic revision identifiers
revision = '5e5da3fb86c1'
down_revision = '3b943000da18'


def upgrade():
    """Upgrade the database to this revision."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('roles',
                     sa.Column('role', sa.String(255)),
                     sa.Column('description', sa.Text),
                     sa.Column('assignment_disabled', sa.Boolean, default=False),
                     sa.Column('internal_role_flag', sa.Boolean, default=False),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('ROLES_PK', 'roles', ['role'])
        create_check_constraint('ROLES_ROLE_NN', 'roles', 'role is not null')
        create_check_constraint('ROLES_ASSIGNMENT_DISABLED_NN', 'roles', 'assignment_disabled is not null')
        create_check_constraint('ROLES_INTERNAL_ROLE_FLAG_NN', 'roles', 'internal_role_flag is not null')
        create_check_constraint('ROLES_CREATED_NN', 'roles', 'created_at is not null')
        create_check_constraint('ROLES_UPDATED_NN', 'roles', 'updated_at is not null')

        create_table('account_role_map',
                     sa.Column('account', sa.String(get_schema_value('ACCOUNT_LENGTH'))),
                     sa.Column('role', sa.String(255)),
                     sa.Column('expires_at', sa.DateTime, default=None),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('ACCOUNT_ROLE_MAP_PK', 'account_role_map', ['account', 'role'])
        create_foreign_key('ACCOUNT_ROLE_MAP_ACCOUNT_FK', 'account_role_map', 'accounts', ['account'], ['account'], onupdate='CASCADE', ondelete='CASCADE')
        create_foreign_key('ACCOUNT_ROLE_MAP_ROLE_FK', 'account_role_map', 'roles', ['role'], ['role'], onupdate='CASCADE', ondelete='RESTRICT')
        create_check_constraint('ACCOUNT_ROLE_MAP_ACCOUNT_NN', 'account_role_map', 'account is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_ROLE_NN', 'account_role_map', 'role is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_CREATED_NN', 'account_role_map', 'created_at is not null')
        create_check_constraint('ACCOUNT_ROLE_MAP_UPDATED_NN', 'account_role_map', 'updated_at is not null')

        create_table('role_permission_map',
                     sa.Column('role', sa.String(255)),
                     sa.Column('scope_pattern', sa.String(get_schema_value('SCOPE_LENGTH'))),
                     sa.Column('operation', sa.Enum(DatabaseOperationType,
                                                    name='ROLE_PERMISSION_MAP_OPERATION_CHK',
                                                    create_constraint=True,
                                                    values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('ROLE_PERMISSION_MAP_PK', 'role_permission_map', ['role', 'scope_pattern', 'operation'])
        create_foreign_key('ROLE_PERMISSION_MAP_ROLE_FK', 'role_permission_map', 'roles', ['role'], ['role'], onupdate='CASCADE', ondelete='CASCADE')
        create_check_constraint('ROLE_PERMISSION_MAP_ROLE_NN', 'role_permission_map', 'role is not null')
        create_check_constraint('ROLE_PERMISSION_MAP_SCOPE_PATTERN_NN', 'role_permission_map', 'scope_pattern is not null')
        create_check_constraint('ROLE_PERMISSION_MAP_OPERATION_NN', 'role_permission_map', 'operation is not null')
        create_check_constraint('ROLE_PERMISSION_MAP_CREATED_NN', 'role_permission_map', 'created_at is not null')
        create_check_constraint('ROLE_PERMISSION_MAP_UPDATED_NN', 'role_permission_map', 'updated_at is not null')


def downgrade():
    """Downgrade the database to the previous revision."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('role_permission_map')
        drop_table('account_role_map')
        drop_table('roles')

    if context.get_context().dialect.name == 'postgresql':
        # The enumerated type is not removed together with the table it belongs to
        execute('DROP TYPE "ROLE_PERMISSION_MAP_OPERATION_CHK"')
