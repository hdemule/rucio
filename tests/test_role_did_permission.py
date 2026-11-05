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

from typing import Optional

import pytest

from rucio.common.exception import Duplicate, InputValidationError
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import role as core_role
from rucio.db.sqla.constants import DidOperationType, RolePermissionType


@pytest.fixture
def role_factory(db_session):
    """Create roles for the test, and delete them, with their permissions and assignments, afterwards."""
    created = []

    def _make_role(*accounts):
        role = 'did-perm-%s' % generate_uuid()
        core_role.add_role(role, session=db_session)
        created.append(role)
        for account in accounts:
            core_role.add_account_role(account, role, session=db_session)
        return role

    yield _make_role
    for role in created:
        core_role.delete_role(role, force=True, session=db_session)


@pytest.mark.parametrize(('did_pattern', 'stored'), [
    ('data*:*', 'data*:*'),
    ('*:*', '*:*'),
    ('data:*', 'data:*'),
    ('data:raw*', 'data:raw*'),
    ('data:raw1', 'data:raw1'),
    ('  data:raw*  ', 'data:raw*'),
    # without name part, a pattern stands for the whole scope(s)
    ('data', 'data:*'),
    ('data*', 'data*:*'),
    ('*', '*:*'),
])
def test_valid_did_pattern(did_pattern, stored):
    """ROLE DID PERMISSION (CORE): A DID pattern is stored with a scope part and a name part, the '*' name part being added to a pattern without one."""
    assert core_role._validate_did_pattern(did_pattern) == stored


@pytest.mark.parametrize('did_pattern', [
    '', '  ', '*data', 'da*ta', 'data**', '*data:*', 'data*:raw1', 'data*:raw*', '*:raw1', '*:raw*', ':raw1', ':*', 'data:', 'data:*raw',
    'data:ra*w', 'data:raw**', 'data:raw:1', 'x' * 26, 'data:' + 'x' * 251, 42,
])
def test_invalid_did_pattern(did_pattern):
    """ROLE DID PERMISSION (CORE): A '*' only closes a part, a wildcard scope part is only followed by the '*' name part, and the parts fit a scope and a name."""
    with pytest.raises(InputValidationError):
        core_role._validate_did_pattern(did_pattern)


@pytest.mark.parametrize(('scope', 'name', 'did_pattern', 'matches'), [
    # the '*' name part matches the whole scope(s) and every DID in them
    ('data', None, 'data:*', True),
    ('data', 'raw1', 'data:*', True),
    ('data18', 'raw1', 'data*:*', True),
    ('data18', None, 'data*:*', True),
    ('mc', 'raw1', 'data*:*', False),
    ('mc', None, '*:*', True),
    ('data18', 'raw1', 'data:*', False),
    # any other name part matches DIDs of its scope only, never the whole scope
    ('data', 'raw1', 'data:raw1', True),
    ('data', 'raw12', 'data:raw1', False),
    ('data', 'raw12', 'data:raw*', True),
    ('data', 'calib', 'data:raw*', False),
    ('data', None, 'data:raw*', False),
    ('data', None, 'data:raw1', False),
    ('data18', 'raw1', 'data:raw*', False),
])
def test_did_pattern_matches(scope, name: Optional[str], did_pattern, matches):
    """ROLE DID PERMISSION (CORE): A DID pattern matches by prefix on a trailing '*', the '*' name part covering whole scopes."""
    assert core_role._did_pattern_matches(InternalScope(scope), name, did_pattern) is matches


def test_did_permission_operations_share_one_row(role_factory, db_session):
    """ROLE DID PERMISSION (CORE): The operations granted on a DID pattern are added and removed one by one, a duplicate being refused."""
    role = role_factory()
    for operation in (DidOperationType.READ, DidOperationType.WRITE):
        core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operation': operation}, session=db_session)
    with pytest.raises(Duplicate):
        core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operation': 'read'}, session=db_session)
    assert core_role.list_role_permissions(role, session=db_session) == [
        {'type': 'did', 'did_pattern': 'data:raw*', 'operation': 'read'},
        {'type': 'did', 'did_pattern': 'data:raw*', 'operation': 'write'},
    ]

    core_role.delete_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operation': 'read'}, session=db_session)
    assert core_role.list_role_permissions(role, session=db_session) == [{'type': 'did', 'did_pattern': 'data:raw*', 'operation': 'write'}]


def test_did_permission_request_on_name_pattern(random_account, role_factory, db_session):
    """ROLE DID PERMISSION (CORE): A permission on a name pattern grants the DIDs it matches, not the whole scope."""
    role = role_factory(random_account)
    scope = InternalScope('mock')
    core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'mock:rbac_%s*' % role[-8:], 'operation': 'write'}, session=db_session)

    def granted(name: Optional[str]) -> bool:
        request = core_role.DidPermissionRequest(operation=DidOperationType.WRITE, scope=scope, name=name)
        return core_role.has_permission(random_account, request, session=db_session)

    assert granted('rbac_%s_file' % role[-8:])
    assert not granted('other_file')
    assert not granted(None)
