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

import sys
import types
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from rucio.common.exception import ErrorLoadingPolicyPackage, RoleReserved
from rucio.common.utils import generate_uuid
from rucio.core import permission
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


@pytest.mark.parametrize('definition, expected', [
    ({'description': 'no filter disabled'}, frozenset()),
    ({'disable-filters': []}, frozenset()),
    ({'disable-filters': ['list_scopes', ' list_content ']}, frozenset({'list_scopes', 'list_content'})),
])
def test_parse_roles_disable_filters(definition, expected):
    """ROLE (CORE): A policy package role disables no filter, unless it names them in its 'disable-filters'."""
    roles = permission._parse_roles([dict(definition, name='data-scientist')], 'policy.role')
    assert roles['data-scientist']['disable_filters'] == expected


@pytest.mark.parametrize('disable_filters', ['list_scopes', [''], ['list_scopes', 42], {'list_scopes': True}])
def test_parse_roles_invalid_disable_filters(disable_filters):
    """ROLE (CORE): A policy package role whose 'disable-filters' is not a list of filter names is refused."""
    with pytest.raises(ErrorLoadingPolicyPackage):
        permission._parse_roles([{'name': 'data-scientist', 'disable-filters': disable_filters}], 'policy.role')


@pytest.fixture
def policy_role_module(monkeypatch):
    """Serve a fake policy package with an empty role module, and an empty role cache, for the test."""
    role_module = types.ModuleType('fake_policy.role')
    monkeypatch.setitem(sys.modules, 'fake_policy', types.ModuleType('fake_policy'))
    monkeypatch.setitem(sys.modules, 'fake_policy.role', role_module)
    monkeypatch.setattr(permission, '_get_policy_package_name', lambda vo: 'fake_policy')
    monkeypatch.setattr(permission, 'role_definitions', {})
    monkeypatch.setattr(permission, 'disabled_filters', {})
    return role_module


@pytest.mark.parametrize('attribute, getter', [
    ('disable_filters_for_all_roles', permission.get_disabled_filters_for_all_roles),
    ('disable_filters_for_all_accounts', permission.get_disabled_filters_for_all_accounts),
])
@pytest.mark.parametrize('attributes, expected', [
    ({}, frozenset()),
    ({'disable_filters': []}, frozenset()),
    ({'disable_filters': ['list_scopes', ' get_scopes ']}, frozenset({'list_scopes', 'get_scopes'})),
    ({'roles': [{'name': 'data-scientist'}], 'disable_filters': ['list_scopes']}, frozenset({'list_scopes'})),
])
def test_load_disabled_filters_for_all(policy_role_module, vo, attribute, getter, attributes, expected):
    """ROLE (CORE): A policy package disables no filter for all roles or all accounts, unless its role module names them in the matching attribute, with or without roles."""
    for name, value in attributes.items():
        setattr(policy_role_module, attribute if name == 'disable_filters' else name, value)
    assert getter(vo=vo) == expected


def test_load_disabled_filters_for_all_are_independent(policy_role_module, vo):
    """ROLE (CORE): The filters disabled for all roles and for all accounts are loaded separately."""
    policy_role_module.disable_filters_for_all_roles = ['list_scopes']
    policy_role_module.disable_filters_for_all_accounts = ['get_scopes']
    assert permission.get_disabled_filters_for_all_roles(vo=vo) == frozenset({'list_scopes'})
    assert permission.get_disabled_filters_for_all_accounts(vo=vo) == frozenset({'get_scopes'})


@pytest.mark.parametrize('attribute', ['disable_filters_for_all_roles', 'disable_filters_for_all_accounts'])
@pytest.mark.parametrize('disable_filters', ['list_scopes', [''], ['list_scopes', 42], {'list_scopes': True}])
def test_load_invalid_disabled_filters_for_all(policy_role_module, vo, attribute, disable_filters):
    """ROLE (CORE): A policy package whose filters disabled for all roles or all accounts are not a list of filter names is refused."""
    setattr(policy_role_module, attribute, disable_filters)
    with pytest.raises(ErrorLoadingPolicyPackage):
        permission.get_roles(vo=vo)


def _stub_disabled_filters(monkeypatch, roles=None, all_roles=frozenset(), all_accounts=frozenset()):
    """Stub the filters the policy package disables for some roles, for all roles and for all accounts."""
    monkeypatch.setattr(core_role.permission, 'get_roles', lambda vo: roles or {})
    monkeypatch.setattr(core_role.permission, 'get_disabled_filters_for_all_roles', lambda vo: all_roles)
    monkeypatch.setattr(core_role.permission, 'get_disabled_filters_for_all_accounts', lambda vo: all_accounts)


@pytest.fixture
def policy_role(db_session):
    """Add a new role for the test, and remove it again afterwards together with its account assignments."""
    role = 'policy-%s' % generate_uuid()
    core_role.add_role(role, session=db_session)
    yield role
    db_session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role))
    db_session.execute(delete(models.Roles).where(models.Roles.role == role))
    db_session.commit()


@pytest.mark.parametrize('disable_filters, expires_at, disabled', [
    (frozenset({'list_scopes'}), None, True),
    (frozenset({'list_scopes'}), datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1), True),
    (frozenset({'list_scopes'}), datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1), False),
    (frozenset({'list_content'}), None, False),
    (frozenset(), None, False),
])
def test_is_filter_disabled(policy_role, db_session, root_account, monkeypatch, disable_filters, expires_at, disabled):
    """ROLE (CORE): A filter is only disabled by a role which disables it and which the account holds through an assignment which has not expired yet."""
    _stub_disabled_filters(monkeypatch, roles={policy_role: {'description': None, 'disable_filters': disable_filters}})
    assert not core_role.is_filter_disabled(root_account, 'list_scopes', session=db_session)

    core_role.add_account_role(root_account, policy_role, expires_at=expires_at, session=db_session)
    assert core_role.is_filter_disabled(root_account, 'list_scopes', session=db_session) is disabled


def test_is_filter_disabled_reserved_role(reserved_role, db_session, random_account, monkeypatch):
    """ROLE (CORE): A reserved role never disables a filter, even if the policy package says so for it or for all roles."""
    _stub_disabled_filters(monkeypatch, roles={reserved_role: {'description': None, 'disable_filters': frozenset({'list_scopes'})}}, all_roles=frozenset({'list_scopes'}))
    core_role.add_account_role(random_account, reserved_role, force=True, session=db_session)
    try:
        assert not core_role.is_filter_disabled(random_account, 'list_scopes', session=db_session)
    finally:
        core_role.delete_account_role(random_account, reserved_role, force=True, session=db_session)


@pytest.mark.parametrize('disabled_filters, expires_at, disabled', [
    (frozenset({'list_scopes'}), None, True),
    (frozenset({'list_scopes'}), datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1), True),
    (frozenset({'list_scopes'}), datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1), False),
    (frozenset({'list_content'}), None, False),
    (frozenset(), None, False),
])
def test_is_filter_disabled_for_all_roles(policy_role, random_account, db_session, monkeypatch, disabled_filters, expires_at, disabled):
    """ROLE (CORE): A filter disabled for all roles is disabled for every account holding a role which does not disable it itself, but not for an account holding no role."""
    _stub_disabled_filters(monkeypatch, roles={policy_role: {'description': None, 'disable_filters': frozenset()}}, all_roles=disabled_filters)
    assert not core_role.is_filter_disabled(random_account, 'list_scopes', session=db_session)

    core_role.add_account_role(random_account, policy_role, expires_at=expires_at, session=db_session)
    assert core_role.is_filter_disabled(random_account, 'list_scopes', session=db_session) is disabled


@pytest.mark.parametrize('disabled_filters, disabled', [
    (frozenset({'list_scopes'}), True),
    (frozenset({'list_content'}), False),
    (frozenset(), False),
])
def test_is_filter_disabled_for_all_accounts(random_account, db_session, monkeypatch, disabled_filters, disabled):
    """ROLE (CORE): A filter disabled for all accounts is disabled for every account, even for an account holding no role at all."""
    _stub_disabled_filters(monkeypatch, all_accounts=disabled_filters)
    assert not core_role.list_account_roles(random_account, session=db_session)
    assert core_role.is_filter_disabled(random_account, 'list_scopes', session=db_session) is disabled


@pytest.mark.parametrize('skip_filtering, expected', [(False, []), (True, [{'scope': None}])])
def test_filter_iterable_by_scope_access_skip_filtering(db_session, root_account, skip_filtering, expected):
    """ROLE (CORE): Skipping the filtering yields every item, even one whose scope would be refused."""
    items = [{'scope': None}]
    assert list(core_role.filter_iterable_by_scope_access(items, account=root_account, session=db_session, skip_filtering=skip_filtering)) == expected
    can_access = core_role.scope_access_checker(account=root_account, session=db_session, skip_filtering=skip_filtering)
    assert can_access(None) is bool(expected)
