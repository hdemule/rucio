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

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from rucio.common.exception import RoleReserved
from rucio.common.utils import generate_uuid
from rucio.core import role as core_role
from rucio.db.sqla import models
from rucio.db.sqla.constants import RoleOperationType
from rucio.tests.common import auth, headers

pytestmark = pytest.mark.noparallel(reason='synchronises the roles shared by the whole instance with a policy package')

RESERVED_ROLE_DESCRIPTION = 'Reserved for testing.'


@pytest.fixture
def reserved_role(monkeypatch, db_session):
    """Reserve a new role for the test, set it up, and remove it again afterwards."""
    role = 'reserved-%s' % generate_uuid()
    monkeypatch.setattr(core_role, 'RESERVED_ROLES', {role: RESERVED_ROLE_DESCRIPTION})
    assert core_role.setup_reserved_roles(session=db_session) == [role]
    yield role
    db_session.execute(delete(models.Roles).where(models.Roles.role == role))
    db_session.commit()


def _get_role(role, session):
    return next(entry for entry in core_role.list_roles(session=session) if entry['role'] == role)


def test_admin_is_reserved():
    """ROLE (CORE): The admin role is reserved."""
    assert core_role.is_reserved_role('admin')


def test_setup_reserved_roles(reserved_role, db_session):
    """ROLE (CORE): A reserved role is created locked, not assignable, with its description, and only once."""
    assert _get_role(reserved_role, db_session) == {'role': reserved_role, 'description': RESERVED_ROLE_DESCRIPTION, 'assignable': False, 'locked': True, 'reserved': True}
    assert core_role.setup_reserved_roles(session=db_session) == []


def test_add_reserved_role(db_session):
    """ROLE (CORE): A reserved role cannot be added."""
    with pytest.raises(RoleReserved):
        core_role.add_role('admin', session=db_session)


@pytest.mark.parametrize('force', [False, True])
def test_delete_reserved_role(reserved_role, db_session, force):
    """ROLE (CORE): A reserved role cannot be deleted, even forced."""
    with pytest.raises(RoleReserved):
        core_role.delete_role(reserved_role, force=force, session=db_session)
    assert _get_role(reserved_role, db_session)


@pytest.mark.parametrize('changes', [{'description': 'changed'}, {'locked': False}, {'locked': True}, {'description': 'changed', 'assignable': True}])
@pytest.mark.parametrize('force', [False, True])
def test_update_reserved_role(reserved_role, db_session, changes, force):
    """ROLE (CORE): A reserved role cannot have anything but its assignable state changed, even forced."""
    before = _get_role(reserved_role, db_session)
    with pytest.raises(RoleReserved):
        core_role.update_role(reserved_role, force=force, session=db_session, **changes)
    assert _get_role(reserved_role, db_session) == before


def test_update_reserved_role_assignable(reserved_role, db_session):
    """ROLE (CORE): A reserved role can have its assignable state changed, and stays locked."""
    updated = core_role.update_role(reserved_role, assignable=True, session=db_session)
    assert updated['assignable'] is True
    assert updated['locked'] is True


@pytest.mark.parametrize('force', [False, True])
def test_add_reserved_role_permission(reserved_role, db_session, force):
    """ROLE (CORE): A reserved role cannot be granted a permission, even forced."""
    with pytest.raises(RoleReserved):
        core_role.add_role_permission(reserved_role, 'user.*', RoleOperationType.READ, force=force, session=db_session)
    assert core_role.list_role_permissions(reserved_role, session=db_session) == []


@pytest.mark.parametrize('force', [False, True])
def test_delete_reserved_role_permission(reserved_role, db_session, force):
    """ROLE (CORE): A reserved role cannot have a permission removed, even forced."""
    with pytest.raises(RoleReserved):
        core_role.delete_role_permission(reserved_role, 'user.*', RoleOperationType.READ, force=force, session=db_session)


def test_list_account_roles_reserved_role(reserved_role, db_session, root_account):
    """ROLE (CORE): A reserved role is flagged as such among the roles of an account."""
    core_role.add_account_role(root_account, reserved_role, force=True, session=db_session)
    try:
        entries = [entry for entry in core_role.list_account_roles(root_account, session=db_session) if entry['role'] == reserved_role]
        assert [entry['reserved'] for entry in entries] == [True]
    finally:
        core_role.delete_account_role(root_account, reserved_role, force=True, session=db_session)


@pytest.mark.parametrize('expires_at, valid', [
    (None, True),
    (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1), True),
    (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1), False),
])
def test_has_account_valid_role(reserved_role, db_session, root_account, expires_at, valid):
    """ROLE (CORE): An account only holds a role through an assignment which has not expired yet."""
    assert not core_role.has_account_valid_role(root_account, reserved_role, session=db_session)
    core_role.add_account_role(root_account, reserved_role, expires_at=expires_at, force=True, session=db_session)
    try:
        assert core_role.has_account_valid_role(root_account, reserved_role, session=db_session) is valid
    finally:
        core_role.delete_account_role(root_account, reserved_role, force=True, session=db_session)


def _policy_package_roles(session):
    """The roles currently known to Rucio, so that a synchronisation leaves the other roles alone."""
    return {entry['role']: {'description': entry['description']} for entry in core_role.list_roles(session=session)}


def test_sync_roles_from_policy_package_reserved_role(reserved_role, db_session, monkeypatch, capsys):
    """ROLE (CORE): Synchronising with a policy package which redefines a reserved role leaves it untouched."""
    before = _get_role(reserved_role, db_session)
    roles = _policy_package_roles(db_session)
    roles[reserved_role] = {'description': 'redefined by the policy package'}
    monkeypatch.setattr(core_role.permission, 'get_roles', lambda vo: roles)

    core_role.sync_roles_from_policy_package_dry_run(session=db_session)
    assert "Role '%s' is reserved, so it would be left untouched." % reserved_role in capsys.readouterr().out

    core_role.sync_roles_from_policy_package(session=db_session)
    assert "Role '%s' is reserved, so it is left untouched." % reserved_role in capsys.readouterr().out
    assert _get_role(reserved_role, db_session) == before


def test_sync_roles_from_policy_package_missing_reserved_role(reserved_role, db_session, monkeypatch, capsys):
    """ROLE (CORE): Synchronising with a policy package which does not define a reserved role keeps it."""
    roles = _policy_package_roles(db_session)
    roles.pop(reserved_role)
    monkeypatch.setattr(core_role.permission, 'get_roles', lambda vo: roles)

    core_role.sync_roles_from_policy_package_dry_run(session=db_session)
    assert "Role '%s' is not defined by the policy package but is reserved, so it would be left untouched." % reserved_role in capsys.readouterr().out

    core_role.sync_roles_from_policy_package(session=db_session)
    assert "Role '%s' is not defined by the policy package but is reserved, so it is left untouched." % reserved_role in capsys.readouterr().out
    assert _get_role(reserved_role, db_session)


def test_add_reserved_role_rest(rest_client, auth_token):
    """ROLE (REST): Adding a reserved role is refused with 403."""
    response = rest_client.post('/roles/admin', headers=headers(auth(auth_token)), json={})
    assert response.status_code == 403
