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
from rucio.core import permission
from rucio.core import role as core_role
from rucio.db.sqla import models
from rucio.db.sqla.constants import DidOperationType, RolePermissionType
from rucio.tests.common import auth, headers

pytestmark = pytest.mark.noparallel(reason='alters the roles shared by the whole instance')

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
        core_role.add_role_permission(reserved_role, RolePermissionType.DID, {'did_pattern': 'user.*', 'operations': [DidOperationType.READ]}, force=force, session=db_session)
    assert core_role.list_role_permissions(reserved_role, session=db_session) == []


@pytest.mark.parametrize('force', [False, True])
def test_delete_reserved_role_permission(reserved_role, db_session, force):
    """ROLE (CORE): A reserved role cannot have a permission removed, even forced."""
    with pytest.raises(RoleReserved):
        core_role.delete_role_permission(reserved_role, RolePermissionType.DID, {'did_pattern': 'user.*'}, force=force, session=db_session)


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
    core_role.add_account_role(root_account, reserved_role, expires_at=expires_at, activates_at=None if expires_at is None else expires_at - timedelta(days=1), force=True, session=db_session)
    try:
        assert core_role.has_account_valid_role(root_account, reserved_role, session=db_session) is valid
    finally:
        core_role.delete_account_role(root_account, reserved_role, force=True, session=db_session)


def test_add_reserved_role_rest(rest_client, auth_token):
    """ROLE (REST): Adding a reserved role is refused with 403."""
    response = rest_client.post('/roles/admin', headers=headers(auth(auth_token)), json={})
    assert response.status_code == 403


@pytest.fixture
def policy_role(db_session):
    """Add a new role for the test, and remove it again afterwards together with its account assignments."""
    role = 'policy-%s' % generate_uuid()
    core_role.add_role(role, session=db_session)
    yield role
    db_session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role))
    db_session.execute(delete(models.Roles).where(models.Roles.role == role))
    db_session.commit()


@pytest.mark.parametrize('rbac, expected', [(True, []), (False, [{'scope': None}])])
def test_unfiltered_listing_yields_every_item(db_session, root_account, monkeypatch, rbac, expected):
    """ROLE (CORE): Without RBAC, a listing is not filtered: every item is yielded, even one whose scope would be refused."""
    monkeypatch.setattr(permission.generic, '_use_roles', lambda: rbac)
    items = [{'scope': None}]
    assert list(permission.filter_scopes(items, root_account, 'list_scopes', session=db_session)) == expected
    assert permission.scope_filter(root_account, 'list_scopes', session=db_session)(None) is bool(expected)


def _assign_expired(account, role, session):
    """Assign a role to an account through an assignment which expired yesterday."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    core_role.add_account_role(account, role, activates_at=now - timedelta(days=2), expires_at=now - timedelta(days=1), force=True, session=session)


def _held_roles(account, session):
    return {entry['role'] for entry in core_role.list_account_roles(account, session=session)}


@pytest.mark.parametrize('dry_run', [False, True])
def test_clean_expired_account_roles(policy_role, reserved_role, random_account_factory, vo, db_session, dry_run):
    """ROLE (CORE): Cleaning removes the expired assignments of every account of the VO, whatever the role, but keeps the valid ones; a dry run only reports them."""
    first, second = random_account_factory(), random_account_factory()
    valid_role = 'valid-%s' % generate_uuid()
    core_role.add_role(valid_role, session=db_session)
    try:
        _assign_expired(first, policy_role, db_session)
        _assign_expired(second, reserved_role, db_session)
        core_role.add_account_role(second, valid_role, session=db_session)

        report = core_role.clean_expired_account_roles(vo=vo, dry_run=dry_run, session=db_session)

        assert report['dry_run'] is dry_run
        removed = {(entry['account'], entry['role']) for entry in report['removed']}
        assert {(first.external, policy_role), (second.external, reserved_role)} <= removed
        assert all(role != valid_role for _, role in removed)
        if dry_run:
            assert _held_roles(first, db_session) == {policy_role}
            assert _held_roles(second, db_session) == {reserved_role, valid_role}
        else:
            assert _held_roles(first, db_session) == set()
            assert _held_roles(second, db_session) == {valid_role}
    finally:
        db_session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role.in_([valid_role, reserved_role])))
        db_session.execute(delete(models.Roles).where(models.Roles.role == valid_role))
        db_session.commit()


def test_clean_expired_account_roles_other_vo(policy_role, random_account, db_session):
    """ROLE (CORE): Cleaning the expired assignments of another VO leaves those of the account's VO alone."""
    _assign_expired(random_account, policy_role, db_session)
    report = core_role.clean_expired_account_roles(vo='zzz', session=db_session)
    assert all(entry['account'] != random_account.external for entry in report['removed'])
    assert _held_roles(random_account, db_session) == {policy_role}


def test_clean_expired_account_roles_route():
    """ROLE (REST): DELETE /roles/accounts/expired cleans, while a GET there still reaches an account named 'expired'."""
    from rucio.web.rest.flaskapi.v1.roles import make_doc
    adapter = make_doc().url_map.bind('localhost')
    assert adapter.match('/roles/accounts/expired', method='DELETE')[0] == 'roles.expired_account_roles'
    assert adapter.match('/roles/accounts/expired', method='GET') == ('roles.account_roles', {'account': 'expired'})
