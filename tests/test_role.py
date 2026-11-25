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

from rucio.common.constants import ADMIN_ROLE
from rucio.common.exception import (
    AccountNotFound,
    Duplicate,
    ErrorLoadingPolicyPackage,
    InputValidationError,
    RoleAssignmentDisabled,
    RoleAssignmentNotFound,
    RoleInUse,
    RoleLocked,
    RoleNotFound,
    RoleReserved,
)
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid
from rucio.core import permission
from rucio.core import role as core_role
from rucio.core.permission import generic
from rucio.db.sqla import models
from rucio.db.sqla.constants import DidOperationType, RolePermissionType
from rucio.tests.common import auth, headers

pytestmark = pytest.mark.noparallel(reason='synchronises the roles shared by the whole instance with a policy package')

RESERVED_ROLE_DESCRIPTION = 'Reserved for testing.'


# the function reading the RBAC flag, kept before the `rbac` fixture replaces it in every test
IS_RBAC_ENABLED = core_role.is_rbac_enabled


@pytest.fixture(autouse=True)
def rbac(request, monkeypatch):
    """
    Switch RBAC on for the test, whatever the configuration of the instance, or off for a test parametrised
    with `@pytest.mark.parametrize('rbac', [False], indirect=True)`. The flag is restored once the test is over.
    """
    enabled = getattr(request, 'param', True)
    monkeypatch.setattr(core_role, 'is_rbac_enabled', lambda: enabled)
    return enabled


@pytest.fixture
def reserved_role(monkeypatch, db_session):
    """Reserve a new role for the test, create it as the migration would, and remove it again afterwards together with its account assignments."""
    role = 'reserved-%s' % generate_uuid()
    monkeypatch.setattr(core_role, 'RESERVED_ROLES', [role])
    db_session.add(models.Roles(role=role, description=RESERVED_ROLE_DESCRIPTION, assignable=False, locked=True))
    db_session.commit()
    yield role
    # a failing test may leave the transaction aborted, which would make the cleaning fail too
    db_session.rollback()
    db_session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role))
    db_session.execute(delete(models.Roles).where(models.Roles.role == role))
    db_session.commit()


def _get_role(role, session):
    return next(entry for entry in core_role.list_roles(session=session) if entry['role'] == role)


def test_admin_is_reserved():
    """ROLE (CORE): The admin role is reserved."""
    assert core_role.is_reserved_role('admin')


def test_admin_role_exists(db_session):
    """ROLE (CORE): The admin role comes with the schema, locked, not assignable, and with the description the migration gives it."""
    admin = _get_role('admin', db_session)
    assert (admin['description'], admin['assignable'], admin['locked'], admin['reserved']) == ('Rucio administrator.', False, True, True)


def test_add_reserved_role(db_session):
    """ROLE (CORE): A reserved role cannot be added."""
    with pytest.raises(RoleReserved):
        core_role.add_role('admin', session=db_session)


def test_add_duplicate_role(policy_role, db_session):
    """ROLE (CORE): A role which already exists cannot be added again."""
    with pytest.raises(Duplicate):
        core_role.add_role(policy_role, session=db_session)


def test_update_locked_role(policy_role, db_session):
    """ROLE (CORE): A locked role can only have its description or assignable state changed when forced, but can always be unlocked."""
    core_role.update_role(policy_role, locked=True, session=db_session)
    for changes in ({'description': 'changed'}, {'assignable': False}):
        with pytest.raises(RoleLocked):
            core_role.update_role(policy_role, session=db_session, **changes)
    assert _get_role(policy_role, db_session)['description'] is None

    assert core_role.update_role(policy_role, description='changed', force=True, session=db_session)['description'] == 'changed'
    assert core_role.update_role(policy_role, locked=False, session=db_session)['locked'] is False
    assert core_role.update_role(policy_role, assignable=False, session=db_session)['assignable'] is False


def test_delete_locked_role(policy_role, db_session):
    """ROLE (CORE): A locked role can only be deleted when forced."""
    core_role.update_role(policy_role, locked=True, session=db_session)
    with pytest.raises(RoleLocked):
        core_role.delete_role(policy_role, session=db_session)
    assert _get_role(policy_role, db_session)

    core_role.delete_role(policy_role, force=True, session=db_session)
    assert all(entry['role'] != policy_role for entry in core_role.list_roles(session=db_session))


def test_delete_role_in_use(policy_role, random_account, db_session):
    """ROLE (CORE): A role still assigned to an account can only be deleted when forced, which also removes its assignments."""
    core_role.add_account_role(random_account, policy_role, session=db_session)
    with pytest.raises(RoleInUse):
        core_role.delete_role(policy_role, session=db_session)
    assert _held_roles(random_account, db_session) == {policy_role}

    core_role.delete_role(policy_role, force=True, session=db_session)
    assert _held_roles(random_account, db_session) == set()
    assert all(entry['role'] != policy_role for entry in core_role.list_roles(session=db_session))


def test_account_role_not_assignable(policy_role, random_account, db_session):
    """ROLE (CORE): A role which is not assignable can only be assigned to, or removed from, an account when forced."""
    core_role.update_role(policy_role, assignable=False, session=db_session)
    with pytest.raises(RoleAssignmentDisabled):
        core_role.add_account_role(random_account, policy_role, session=db_session)
    assert _held_roles(random_account, db_session) == set()

    core_role.add_account_role(random_account, policy_role, force=True, session=db_session)
    with pytest.raises(RoleAssignmentDisabled):
        core_role.delete_account_role(random_account, policy_role, session=db_session)
    assert _held_roles(random_account, db_session) == {policy_role}

    core_role.delete_account_role(random_account, policy_role, force=True, session=db_session)
    assert _held_roles(random_account, db_session) == set()


def test_account_role_not_found(policy_role, random_account, db_session):
    """ROLE (CORE): A role which is not assigned to an account can neither be removed from it nor have its dates set."""
    with pytest.raises(RoleAssignmentNotFound):
        core_role.delete_account_role(random_account, policy_role, session=db_session)
    with pytest.raises(RoleAssignmentNotFound):
        core_role.set_account_role_dates(random_account, policy_role, expires_at=None, session=db_session)


@pytest.mark.parametrize('dates', [
    {'activates_at': 'not a date'},
    {'expires_at': 'not a date'},
    {'expires_at': 42},
])
def test_account_role_invalid_date(policy_role, random_account, db_session, dates):
    """ROLE (CORE): A date of a role assignment which is not a date Rucio understands is refused, when assigning the role and when setting its dates."""
    with pytest.raises(InputValidationError):
        core_role.add_account_role(random_account, policy_role, session=db_session, **dates)
    assert _held_roles(random_account, db_session) == set()

    core_role.add_account_role(random_account, policy_role, session=db_session)
    with pytest.raises(InputValidationError):
        core_role.set_account_role_dates(random_account, policy_role, session=db_session, **dates)


def test_account_role_expires_before_activation(policy_role, random_account, db_session):
    """ROLE (CORE): A role assignment must activate before it expires, when assigning the role and when setting its dates one at a time, but its whole period can be moved at once."""
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    for expires_at in (now - timedelta(days=1), now):
        with pytest.raises(InputValidationError):
            core_role.add_account_role(random_account, policy_role, activates_at=now, expires_at=expires_at, session=db_session)
    assert _held_roles(random_account, db_session) == set()

    core_role.add_account_role(random_account, policy_role, activates_at=now, expires_at=now + timedelta(days=1), session=db_session)
    with pytest.raises(InputValidationError):
        core_role.set_account_role_expires_at(random_account, policy_role, now - timedelta(days=1), session=db_session)
    with pytest.raises(InputValidationError):
        core_role.set_account_role_activates_at(random_account, policy_role, now + timedelta(days=2), session=db_session)

    later = {'activates_at': now + timedelta(days=2), 'expires_at': now + timedelta(days=3)}
    assert core_role.set_account_role_dates(random_account, policy_role, session=db_session, **later) == later


@pytest.fixture
def admin_role_holder(random_account, db_session):
    """An account holding the admin role, but not the 'admin' account attribute, which loses the role again afterwards."""
    core_role.add_account_role(random_account, ADMIN_ROLE, force=True, session=db_session)
    yield random_account
    # a failing test may leave the transaction aborted, which would make the cleaning fail too
    db_session.rollback()
    core_role.delete_account_role(random_account, ADMIN_ROLE, force=True, session=db_session)


@pytest.mark.parametrize('rbac', [True, False], indirect=True)
def test_admin_role_holder_is_admin(admin_role_holder, random_account_factory, db_session, rbac):
    """ROLE (CORE): An account holding the admin role is an admin of the generic policy with RBAC, but not without it; an account holding no role never is."""
    assert generic._is_admin(admin_role_holder, db_session) is rbac
    assert not generic._is_admin(random_account_factory(), db_session)


def test_perm_list_account_roles(random_account_factory, db_session):
    """ROLE (CORE): In the generic policy, an account can list its own roles, but not those of another account."""
    account, other = random_account_factory(), random_account_factory()
    assert generic.perm_list_account_roles(account, {'account': account}, db_session)
    assert not generic.perm_list_account_roles(account, {'account': other}, db_session)


def test_perm_list_role_permissions(policy_role, random_account, db_session):
    """ROLE (CORE): In the generic policy, an account can list the permissions of a role only while it holds it."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert not generic.perm_list_role_permissions(random_account, {'role': policy_role}, db_session)

    core_role.add_account_role(random_account, policy_role, activates_at=now - timedelta(days=2), expires_at=now - timedelta(days=1), session=db_session)
    assert not generic.perm_list_role_permissions(random_account, {'role': policy_role}, db_session)

    core_role.set_account_role_expires_at(random_account, policy_role, None, session=db_session)
    assert generic.perm_list_role_permissions(random_account, {'role': policy_role}, db_session)


@pytest.mark.parametrize('file_config_mock', [{'removes': [('rbac', 'enabled')]}], indirect=True)
@pytest.mark.parametrize('caches_mock', [{'caches_to_mock': ['rucio.core.config.REGION']}], indirect=True)
@pytest.mark.parametrize('core_config_mock, enabled', [
    ({'table_content': []}, False),
    ({'table_content': [('rbac', 'enabled', 'True')]}, True),
    ({'table_content': [('rbac', 'enabled', 'False')]}, False),
], indirect=['core_config_mock'])
def test_is_rbac_enabled_from_config_table(file_config_mock, core_config_mock, caches_mock, enabled):
    """ROLE (CORE): Without an 'enabled' option in the configuration file, RBAC is enabled by the config table only, and off by default."""
    assert IS_RBAC_ENABLED() is enabled


@pytest.mark.parametrize('file_config_mock', [{'overrides': [('rbac', 'enabled', 'True')]}], indirect=True)
@pytest.mark.parametrize('caches_mock', [{'caches_to_mock': ['rucio.core.config.REGION']}], indirect=True)
@pytest.mark.parametrize('core_config_mock', [{'table_content': []}], indirect=True)
def test_is_rbac_enabled_from_config_file(file_config_mock, core_config_mock, caches_mock):
    """ROLE (CORE): RBAC can be enabled in the configuration file, without any config table entry."""
    assert IS_RBAC_ENABLED() is True


def test_unknown_role(db_session):
    """ROLE (CORE): A role which does not exist can neither be updated nor deleted, and has no accounts to list."""
    role = 'missing-%s' % generate_uuid()
    with pytest.raises(RoleNotFound):
        core_role.update_role(role, description='changed', session=db_session)
    with pytest.raises(RoleNotFound):
        core_role.delete_role(role, session=db_session)
    with pytest.raises(RoleNotFound):
        core_role.list_role_accounts(role, session=db_session)


def test_list_role_accounts(policy_role, random_account_factory, db_session):
    """ROLE (CORE): The accounts of a role are listed with the dates of their assignment."""
    assert core_role.list_role_accounts(policy_role, session=db_session) == []
    first, second = random_account_factory(), random_account_factory()
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) + timedelta(days=1)
    core_role.add_account_role(first, policy_role, session=db_session)
    core_role.add_account_role(second, policy_role, expires_at=expires_at, session=db_session)

    entries = {entry['account']: entry for entry in core_role.list_role_accounts(policy_role, session=db_session)}
    assert set(entries) == {first, second}
    assert entries[first]['expires_at'] is None
    assert entries[second]['expires_at'] == expires_at


def test_add_account_role_errors(policy_role, random_account, vo, db_session):
    """ROLE (CORE): A role cannot be assigned to an account which does not exist, nor can a role which does not exist, nor twice the same role."""
    with pytest.raises(AccountNotFound):
        core_role.add_account_role(InternalAccount('missing%s' % generate_uuid()[:8], vo=vo), policy_role, session=db_session)
    with pytest.raises(RoleNotFound):
        core_role.add_account_role(random_account, 'missing-%s' % generate_uuid(), session=db_session)
    assert _held_roles(random_account, db_session) == set()

    core_role.add_account_role(random_account, policy_role, session=db_session)
    with pytest.raises(Duplicate):
        core_role.add_account_role(random_account, policy_role, session=db_session)
    assert _held_roles(random_account, db_session) == {policy_role}


@pytest.mark.parametrize('description', [42, ['description'], {'text': 'description'}])
def test_add_role_invalid_description(db_session, description):
    """ROLE (CORE): A role description which is not a string is refused, and the role is not added."""
    role = 'invalid-%s' % generate_uuid()
    with pytest.raises(InputValidationError):
        core_role.add_role(role, description=description, session=db_session)
    assert all(entry['role'] != role for entry in core_role.list_roles(session=db_session))


def test_empty_date_clears_it(policy_role, random_account, db_session):
    """ROLE (CORE): An empty date string means no date: the assignment does not expire, or it is active from now on."""
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    core_role.add_account_role(random_account, policy_role, activates_at=now - timedelta(days=2), expires_at=now + timedelta(days=1), session=db_session)

    assert core_role.set_account_role_expires_at(random_account, policy_role, '', session=db_session) is None
    assert core_role.set_account_role_expires_at(random_account, policy_role, '  ', session=db_session) is None
    before = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    activates_at = core_role.set_account_role_activates_at(random_account, policy_role, '', session=db_session)
    assert before <= activates_at <= datetime.now(timezone.utc).replace(tzinfo=None)


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


def _policy_package_roles(session):
    """The roles currently known to Rucio, so that a synchronisation leaves the other roles alone."""
    return {entry['role']: {'description': entry['description']} for entry in core_role.list_roles(session=session)}


def test_sync_roles_from_policy_package_reserved_role(reserved_role, db_session, monkeypatch, capsys):
    """ROLE (CORE): Synchronising with a policy package which redefines a reserved role leaves it untouched."""
    before = _get_role(reserved_role, db_session)
    roles = _policy_package_roles(db_session)
    roles[reserved_role] = {'description': 'redefined by the policy package'}
    monkeypatch.setattr(core_role.permission, 'get_roles', lambda: roles)

    core_role.sync_roles_from_policy_package_dry_run(session=db_session)
    assert "Role '%s' is reserved, so it would be left untouched." % reserved_role in capsys.readouterr().out

    core_role.sync_roles_from_policy_package(session=db_session)
    assert "Role '%s' is reserved, so it is left untouched." % reserved_role in capsys.readouterr().out
    assert _get_role(reserved_role, db_session) == before


def test_sync_roles_from_policy_package_missing_reserved_role(reserved_role, db_session, monkeypatch, capsys):
    """ROLE (CORE): Synchronising with a policy package which does not define a reserved role keeps it."""
    roles = _policy_package_roles(db_session)
    roles.pop(reserved_role)
    monkeypatch.setattr(core_role.permission, 'get_roles', lambda: roles)

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
    ({'disable_filters': []}, frozenset()),
    ({'disable_filters': ['list_scopes', ' list_content ']}, frozenset({'list_scopes', 'list_content'})),
])
def test_parse_roles_disable_filters(definition, expected):
    """ROLE (CORE): A policy package role disables no filter, unless it names them in its 'disable_filters'."""
    roles = permission._parse_roles([dict(definition, name='user')], 'policy.role')
    assert roles['user']['disable_filters'] == expected


@pytest.mark.parametrize('disable_filters', ['list_scopes', [''], ['list_scopes', 42], {'list_scopes': True}])
def test_parse_roles_invalid_disable_filters(disable_filters):
    """ROLE (CORE): A policy package role whose 'disable_filters' is not a list of filter names is refused."""
    with pytest.raises(ErrorLoadingPolicyPackage):
        permission._parse_roles([{'name': 'user', 'disable_filters': disable_filters}], 'policy.role')


@pytest.fixture
def policy_role_module(monkeypatch):
    """Serve a fake policy package with an empty role module, and an empty role cache, for the test."""
    role_module = types.ModuleType('fake_policy.role')
    monkeypatch.setitem(sys.modules, 'fake_policy', types.ModuleType('fake_policy'))
    monkeypatch.setitem(sys.modules, 'fake_policy.role', role_module)
    monkeypatch.setattr(permission, '_get_policy_package_name', lambda: 'fake_policy')
    monkeypatch.setattr(permission, 'role_definitions', None)
    monkeypatch.setattr(permission, 'disabled_filters', None)
    return role_module


@pytest.mark.parametrize('attribute, getter', [
    ('disable_filters_for_all_roles', permission.get_disabled_filters_for_all_roles),
    ('disable_filters_for_all_accounts', permission.get_disabled_filters_for_all_accounts),
])
@pytest.mark.parametrize('attributes, expected', [
    ({}, frozenset()),
    ({'disable_filters': []}, frozenset()),
    ({'disable_filters': ['list_scopes', ' get_scopes ']}, frozenset({'list_scopes', 'get_scopes'})),
    ({'roles': [{'name': 'user'}], 'disable_filters': ['list_scopes']}, frozenset({'list_scopes'})),
])
def test_load_disabled_filters_for_all(policy_role_module, attribute, getter, attributes, expected):
    """ROLE (CORE): A policy package disables no filter for all roles or all accounts, unless its role module names them in the matching attribute, with or without roles."""
    for name, value in attributes.items():
        setattr(policy_role_module, attribute if name == 'disable_filters' else name, value)
    assert getter() == expected


def test_load_disabled_filters_for_all_are_independent(policy_role_module):
    """ROLE (CORE): The filters disabled for all roles and for all accounts are loaded separately."""
    policy_role_module.disable_filters_for_all_roles = ['list_scopes']
    policy_role_module.disable_filters_for_all_accounts = ['get_scopes']
    assert permission.get_disabled_filters_for_all_roles() == frozenset({'list_scopes'})
    assert permission.get_disabled_filters_for_all_accounts() == frozenset({'get_scopes'})


@pytest.mark.parametrize('attribute', ['disable_filters_for_all_roles', 'disable_filters_for_all_accounts'])
@pytest.mark.parametrize('disable_filters', ['list_scopes', [''], ['list_scopes', 42], {'list_scopes': True}])
def test_load_invalid_disabled_filters_for_all(policy_role_module, attribute, disable_filters):
    """ROLE (CORE): A policy package whose filters disabled for all roles or all accounts are not a list of filter names is refused."""
    setattr(policy_role_module, attribute, disable_filters)
    with pytest.raises(ErrorLoadingPolicyPackage):
        permission.get_roles()


def _stub_disabled_filters(monkeypatch, roles=None, all_roles=frozenset(), all_accounts=frozenset()):
    """Stub the filters the policy package disables for some roles, for all roles and for all accounts."""
    monkeypatch.setattr(core_role.permission, 'get_roles', lambda: roles or {})
    monkeypatch.setattr(core_role.permission, 'get_disabled_filters_for_all_roles', lambda: all_roles)
    monkeypatch.setattr(core_role.permission, 'get_disabled_filters_for_all_accounts', lambda: all_accounts)


@pytest.fixture
def policy_role(db_session):
    """Add a new role for the test, and remove it again afterwards together with its account assignments."""
    role = 'policy-%s' % generate_uuid()
    core_role.add_role(role, locked=False, session=db_session)
    yield role
    # a failing test may leave the transaction aborted, which would make the cleaning fail too
    db_session.rollback()
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

    core_role.add_account_role(root_account, policy_role, expires_at=expires_at, activates_at=None if expires_at is None else expires_at - timedelta(days=1), session=db_session)
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

    core_role.add_account_role(random_account, policy_role, expires_at=expires_at, activates_at=None if expires_at is None else expires_at - timedelta(days=1), session=db_session)
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


@pytest.mark.parametrize('rbac, expected', [(True, []), (False, [{'scope': None}])], indirect=['rbac'])
def test_unfiltered_listing_yields_every_item(db_session, root_account, rbac, expected):
    """ROLE (CORE): Without RBAC, a listing is not filtered: every item is yielded, even one whose scope would be refused."""
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
    """ROLE (REST): DELETE /roles/accounts/expired cleans, while a GET or PUT there still reaches an account named 'expired'."""
    from rucio.web.rest.flaskapi.v1.roles import make_doc
    adapter = make_doc().url_map.bind('localhost')
    assert adapter.match('/roles/accounts/expired', method='DELETE')[0] == 'roles.expired_account_roles'
    assert adapter.match('/roles/accounts/expired', method='GET') == ('roles.account_roles', {'account': 'expired'})
    assert adapter.match('/roles/accounts/expired', method='PUT') == ('roles.account_roles', {'account': 'expired'})
