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

from typing import Any, Optional

import pytest

from rucio.common.exception import InputValidationError, RoleNotFound, RolePermissionNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import permission as core_permission
from rucio.core import role as core_role
from rucio.db.sqla.constants import DidOperationType, DIDType, RolePermissionType


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
def role_factory(db_session):
    """Create roles for the test, and delete them, with their permissions and assignments, afterwards."""
    created = []

    def _make_role(*accounts):
        role = 'did-perm-%s' % generate_uuid()
        core_role.add_role(role, locked=False, session=db_session)
        created.append(role)
        for account in accounts:
            core_role.add_account_role(account, role, session=db_session)
        return role

    yield _make_role
    # a failing test may leave the transaction aborted, which would make the cleaning fail too
    db_session.rollback()
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


def test_did_permission_replaces_its_operations(role_factory, db_session):
    """ROLE DID PERMISSION (CORE): Granting a DID permission sets exactly its operations on the pattern, none being kept, and removing it deletes it."""
    role = role_factory()
    core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operations': [DidOperationType.READ]}, session=db_session)
    core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operations': ['write', 'read']}, session=db_session)
    core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:tmp*', 'operations': []}, session=db_session)
    assert core_role.list_role_permissions(role, session=db_session) == [
        {'type': 'did', 'did_pattern': 'data:raw*', 'operations': ['read', 'write']},
        {'type': 'did', 'did_pattern': 'data:tmp*', 'operations': []},
    ]

    core_role.delete_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*'}, session=db_session)
    assert core_role.list_role_permissions(role, session=db_session) == [{'type': 'did', 'did_pattern': 'data:tmp*', 'operations': []}]
    with pytest.raises(RolePermissionNotFound):
        core_role.delete_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*'}, session=db_session)
    with pytest.raises(InputValidationError):
        core_role.delete_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:tmp*', 'operations': []}, session=db_session)
    with pytest.raises(InputValidationError):
        core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operations': 'read'}, session=db_session)


def test_did_permission_unknown_role(db_session):
    """ROLE DID PERMISSION (CORE): A DID permission cannot be granted to a role which does not exist."""
    with pytest.raises(RoleNotFound):
        core_role.add_role_permission('missing-%s' % generate_uuid(), RolePermissionType.DID, {'did_pattern': 'data:raw*', 'operations': ['read']}, session=db_session)


@pytest.mark.parametrize(('operations', 'stored'), [
    ('', []),
    ('r', ['read']),
    ('w', ['read', 'write']),
    ('rw', ['read', 'write']),
    ('d', ['read', 'write', 'delete']),
    ('wd', ['read', 'write', 'delete']),
    ('rd', ['read', 'write', 'delete']),
    ('rwd', ['read', 'write', 'delete']),
])
def test_did_operations_include_the_lower_ones(role_factory, db_session, operations, stored):
    """ROLE DID PERMISSION (CORE): WRITE includes READ, DELETE includes WRITE and READ: a DID permission is stored with the operations its operations include."""
    role = role_factory()
    parameters = {'did_pattern': 'data:raw*', 'operations': [LETTERS[letter] for letter in operations]}
    core_role.add_role_permission(role, RolePermissionType.DID, parameters, session=db_session)
    assert core_role.list_role_permissions(role, session=db_session) == [{'type': 'did', 'did_pattern': 'data:raw*', 'operations': stored}]


def test_did_permission_request_on_name_pattern(random_account, role_factory, db_session):
    """ROLE DID PERMISSION (CORE): A permission on a name pattern grants the DIDs it matches, not the whole scope."""
    role = role_factory(random_account)
    scope = InternalScope('mock')
    core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'mock:rbac_%s*' % role[-8:], 'operations': ['write']}, session=db_session)

    def granted(name: Optional[str]) -> bool:
        return core_role.has_did_permission(random_account, scope, name, DidOperationType.WRITE, session=db_session)

    assert granted('rbac_%s_file' % role[-8:])
    assert not granted('other_file')
    assert not granted(None)


class _Catalogue:
    """Stands for the DIDs the generic RBAC checks look up, see `catalogue`."""

    def __init__(self):
        self.owners: dict[str, Any] = {}
        self.content: dict[str, list[dict[str, Any]]] = {}

    def add(self, name: str, owner: Any) -> None:
        self.owners[name] = owner

    def attach(self, collection: str, scope: InternalScope, name: str, did_type: DIDType) -> None:
        self.content.setdefault(collection, []).append({'scope': scope, 'name': name, 'type': did_type})


@pytest.fixture
def catalogue(monkeypatch):
    """Let the generic RBAC checks look up made-up DIDs, and their content, instead of the database: a DID not added does not exist."""
    from rucio.common.exception import DataIdentifierNotFound
    from rucio.core.permission import generic

    data = _Catalogue()

    def get_did(scope, name, session):
        if name not in data.owners:
            raise DataIdentifierNotFound()
        return {'account': data.owners[name]}

    def list_content(scope, name, session):
        if name not in data.owners:
            raise DataIdentifierNotFound()
        yield from data.content.get(name, [])

    monkeypatch.setattr(generic, 'get_did', get_did)
    monkeypatch.setattr(generic, 'list_content', list_content)
    return data


LETTERS = {'r': 'read', 'w': 'write', 'd': 'delete'}


@pytest.fixture
def grant(random_account, role_factory, db_session):
    """
    Set operations ('r', 'w', 'd', '' for none) for `random_account` on DID patterns of the scope 'mock' through a role
    of its own, the patterns using `%(prefix)s`. `grant.other_role` grants them through a second role of the account.
    """
    roles: dict[str, str] = {}
    prefix = 'rbac_%s' % generate_uuid()[:8]

    def _role(name: str) -> str:
        if name not in roles:
            roles[name] = role_factory(random_account)
        return roles[name]

    def _grant(did_pattern: str, operations: str, role: str = 'main') -> None:
        parameters = {'did_pattern': did_pattern % {'prefix': prefix}, 'operations': [LETTERS[letter] for letter in operations]}
        core_role.add_role_permission(_role(role), RolePermissionType.DID, parameters, session=db_session)

    _grant.prefix = prefix  # type: ignore[attr-defined]
    return _grant


MOCK = InternalScope('mock')
# the generic policy lets every account create, attach and detach DIDs in the scope 'mock', so these are checked in another scope
OTHER = InternalScope('rbac_other')


@pytest.fixture
def generic():
    """The generic permission policy."""
    from rucio.core.permission import generic

    return generic


def test_ownership_needs_write_on_the_did(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Owning a DID makes an account its admin only while a role grants it WRITE on that DID, not READ, nor WRITE elsewhere."""
    own = '%s_own' % grant.prefix
    catalogue.add(own, owner=random_account)
    grant('mock:%(prefix)s_new*', 'w')
    # setting a key leading to its removal alters the DID
    assert not generic.perm_set_metadata(random_account, {'scope': MOCK, 'name': own, 'key': 'lifetime'}, db_session)
    assert not generic.perm_list_replicas(random_account, {'scope': MOCK, 'name': own}, db_session)

    grant('mock:%(prefix)s_own*', 'r')
    assert not generic.perm_set_metadata(random_account, {'scope': MOCK, 'name': own, 'key': 'lifetime'}, db_session)
    assert generic.perm_list_replicas(random_account, {'scope': MOCK, 'name': own}, db_session)
    assert not generic.did_filter(random_account, 'list_dids', db_session, operation=DidOperationType.DELETE)(MOCK, own)

    # ownership and WRITE make DELETE
    grant('mock:%(prefix)s_own*', 'w')
    assert generic.perm_set_metadata(random_account, {'scope': MOCK, 'name': own, 'key': 'lifetime'}, db_session)
    assert generic.perm_list_replicas(random_account, {'scope': MOCK, 'name': own}, db_session)
    assert generic.did_filter(random_account, 'list_dids', db_session, operation=DidOperationType.DELETE)(MOCK, own)


def test_filtering_listings_per_did(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): A listing shows the DIDs a name pattern matches and the owned DIDs with WRITE on them; the scope itself is listed."""
    calib, other, own = ('%s_%s' % (grant.prefix, suffix) for suffix in ('calib1', 'other', 'own'))
    catalogue.add(calib, owner='someone else')
    catalogue.add(other, owner='someone else')
    catalogue.add(own, owner=random_account)

    # without WRITE on it, an owned DID is not shown, even with READ elsewhere in the scope
    grant('mock:%(prefix)s_calib*', 'r')
    can_access = generic.did_filter(random_account, 'list_dids', db_session)
    assert not can_access(MOCK, own)

    grant('mock:%(prefix)s_own', 'w')
    can_access = generic.did_filter(random_account, 'list_dids', db_session)
    assert can_access(MOCK, calib)
    assert can_access(MOCK, own)
    assert not can_access(MOCK, other)
    assert not can_access(MOCK, None)
    assert not can_access(InternalScope('data'), calib)

    items = [{'scope': MOCK, 'name': name} for name in (calib, other, own)]
    assert [item['name'] for item in core_permission.filter_dids(items, random_account, 'list_dids', session=db_session)] == [calib, own]

    # the scopes are listed if some of their DIDs are readable, the whole-scope items (e.g. counts) are not shown
    assert generic.scope_filter(random_account, 'list_scopes', db_session, any_did=True)(MOCK)
    assert not generic.scope_filter(random_account, 'list_scopes', db_session)(MOCK)


@pytest.mark.parametrize(('operations', 'owned', 'allowed'), [
    ('w', False, False),
    ('d', False, True),
    ('w', True, True),
    ('r', True, False),
], ids=['WRITE on a DID of another account', 'DELETE on a DID of another account', 'own DID with WRITE', 'own DID without WRITE'])
def test_altering_existing_dids(random_account, grant, catalogue, generic, db_session, operations, owned, allowed):
    """ROLE DID PERMISSION (CORE): WRITE does not alter the existing DIDs of other accounts (metadata, detach, ...), DELETE or owning them with WRITE does."""
    name = '%s_file' % grant.prefix
    catalogue.add(name, owner=random_account if owned else 'someone else')
    grant('mock:%(prefix)s*', operations)
    # setting a key leading to its removal alters the DID
    assert generic.perm_set_metadata(random_account, {'scope': MOCK, 'name': name, 'key': 'lifetime'}, db_session) is allowed
    assert generic.perm_set_metadata(random_account, {'scope': MOCK, 'name': name, 'key': 'project'}, db_session) is allowed


def test_attaching(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Adding content into a collection takes WRITE on it, and READ on the attached DIDs (WRITE on the new files registered with it)."""
    collection, readable, unreadable, new_file, read_only_file = ('%s_%s' % (grant.prefix, suffix) for suffix in ('ds', 'f1', 'f2', 'f3', 'f4'))
    catalogue.add(collection, owner='someone else')
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('rbac_other:%(prefix)s_ds', 'w')
    grant('rbac_other:%(prefix)s_f1', 'r')
    grant('rbac_other:%(prefix)s_f3', 'w')
    grant('rbac_other:%(prefix)s_f4', 'r')

    def attaches(name: str, registered: bool = False) -> bool:
        attachment = {'dids': [{'scope': 'rbac_other', 'name': name}], **({'rse_id': 'some-rse'} if registered else {})}
        return generic.perm_attach_dids(random_account, {'scope': OTHER, 'name': collection, 'attachment': attachment}, db_session)

    assert attaches(readable)
    assert not attaches(unreadable)
    assert attaches(new_file, registered=True)
    assert not attaches(read_only_file, registered=True)


def test_detaching(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Removing content from a collection takes DELETE on it or owning it; WRITE on it only removes the DIDs the account owns."""
    writable, deletable, owned, not_owned = ('%s_%s' % (grant.prefix, suffix) for suffix in ('ds1', 'ds2', 'f1', 'f2'))
    for name in (writable, deletable, not_owned):
        catalogue.add(name, owner='someone else')
    catalogue.add(owned, owner=random_account)
    grant('rbac_other:%(prefix)s_ds1', 'rw')
    grant('rbac_other:%(prefix)s_ds2', 'd')
    grant('rbac_other:%(prefix)s_f1', 'w')

    def detaches(collection: str, *names: str) -> bool:
        return generic.perm_detach_dids(random_account, {'scope': OTHER, 'name': collection, 'dids': [{'scope': 'rbac_other', 'name': name} for name in names]}, db_session)

    assert detaches(writable, owned)
    assert not detaches(writable, not_owned)
    assert not detaches(writable, owned, not_owned)
    assert detaches(deletable, not_owned)


def test_creating_dids(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Creating a DID takes WRITE on it, which makes the account its owner; its metadata, content and rules are checked along with it."""
    new = {'scope': OTHER, 'name': '%s_ds' % grant.prefix}
    with_rule = {**new, 'rules': [{'account': random_account, 'copies': 1}]}
    readable, unreadable = '%s_f1' % grant.prefix, 'other_f2'
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('rbac_other:%(prefix)s*', 'w')
    grant('rbac_other:%(prefix)s_f1', 'r')
    assert generic.perm_add_did(random_account, new, db_session)
    assert generic.perm_add_did(random_account, {**new, 'meta': {'project': 'p'}}, db_session)
    # a key Rucio reserves, here one renaming the new DID out of the pattern granting WRITE
    assert not generic.perm_add_did(random_account, {**new, 'meta': {'name': 'other_ds'}}, db_session)
    # the account will own it, with WRITE on it: it may set the keys leading to its removal, and add rules on it
    assert generic.perm_add_did(random_account, {**new, 'meta': {'lifetime': 3600}}, db_session)
    assert generic.perm_add_did(random_account, {**new, 'lifetime': 3600}, db_session)
    assert generic.perm_add_did(random_account, with_rule, db_session)
    # its content must be readable
    assert generic.perm_add_did(random_account, {**new, 'dids': [{'scope': 'rbac_other', 'name': readable}]}, db_session)
    assert not generic.perm_add_did(random_account, {**new, 'dids': [{'scope': 'rbac_other', 'name': unreadable}]}, db_session)
    assert not generic.perm_add_did(random_account, {'scope': OTHER, 'name': 'other_ds'}, db_session)


def test_creating_dids_in_the_mock_scope(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Every account creates DIDs in the scope 'mock', as in standard Rucio, but a rule on the new DID needs to read it or to own it."""
    new = {'scope': MOCK, 'name': '%s_ds' % grant.prefix}
    with_rule = {**new, 'rules': [{'account': random_account, 'copies': 1}]}
    assert generic.perm_add_did(random_account, new, db_session)
    assert not generic.perm_add_did(random_account, with_rule, db_session)
    grant('mock:%(prefix)s*', 'w')
    assert generic.perm_add_did(random_account, with_rule, db_session)


def test_rules_need_read(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): A rule requires to read every DID it is on."""
    readable, unreadable = '%s_r' % grant.prefix, '%s_x' % grant.prefix
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('mock:%(prefix)s_r', 'r')

    def adds_rule(*names: str) -> bool:
        return generic.perm_add_rule(random_account, {'account': random_account, 'locked': False, 'dids': [{'scope': 'mock', 'name': name} for name in names]}, db_session)

    assert adds_rule(readable)
    assert not adds_rule(readable, unreadable)


def test_rules_need_read_on_the_whole_content(random_account, grant, catalogue, generic, db_session, monkeypatch):
    """ROLE DID PERMISSION (CORE): A rule copies the whole content of a collection, recursively, so it requires to read all of it, not only the DIDs it is on."""
    import rucio.core.scope

    container, dataset, nested, top_file, nested_file = ('%s_%s' % (grant.prefix, suffix) for suffix in ('cnt', 'ds', 'ds_nested', 'f1', 'f2'))
    for name in (container, dataset, nested, top_file, nested_file):
        catalogue.add(name, owner='someone else')
    # cnt -> ds -> f1, and cnt -> ds -> ds_nested -> f2, the nested file being in another scope
    catalogue.attach(container, OTHER, dataset, DIDType.DATASET)
    catalogue.attach(dataset, OTHER, top_file, DIDType.FILE)
    catalogue.attach(dataset, OTHER, nested, DIDType.DATASET)
    catalogue.attach(nested, MOCK, nested_file, DIDType.FILE)

    def adds_rule(name: str) -> bool:
        return generic.perm_add_rule(random_account, {'account': random_account, 'locked': False, 'dids': [{'scope': 'rbac_other', 'name': name}]}, db_session)

    # READ on the collection alone does not let its content be copied
    grant('rbac_other:%(prefix)s_cnt', 'r')
    assert not adds_rule(container)
    grant('rbac_other:%(prefix)s*', 'r')
    assert not adds_rule(container)
    # every level of the content is checked, down to the files of the nested datasets, whatever their scope
    grant('mock:%(prefix)s_f2', 'r')
    assert adds_rule(container)
    assert adds_rule(nested)
    # a DID withdrawn from a broader pattern keeps the collections containing it from being replicated
    grant('rbac_other:%(prefix)s_f1', '')
    assert not adds_rule(container)
    assert not adds_rule(dataset)
    assert adds_rule(nested)
    # owning the scope of a DID of the content reads it
    monkeypatch.setattr(rucio.core.scope, 'is_scope_owner', lambda scope, account, *args, **kwargs: scope == OTHER)
    assert adds_rule(container)


def test_rules_of_new_dids_need_read_on_their_whole_content(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): The rules given with a new DID copy its content, recursively, which must be readable; without rules, only the attached DIDs are."""
    dataset, unreadable_file = '%s_ds' % grant.prefix, '%s_f1' % grant.prefix
    catalogue.add(dataset, owner='someone else')
    catalogue.add(unreadable_file, owner='someone else')
    catalogue.attach(dataset, OTHER, unreadable_file, DIDType.FILE)
    grant('rbac_other:%(prefix)s_cnt', 'w')
    grant('rbac_other:%(prefix)s_ds', 'r')
    new = {'scope': OTHER, 'name': '%s_cnt' % grant.prefix, 'dids': [{'scope': 'rbac_other', 'name': dataset}]}
    with_rule = {**new, 'rules': [{'account': random_account, 'copies': 1}]}

    assert generic.perm_add_did(random_account, new, db_session)
    assert not generic.perm_add_did(random_account, with_rule, db_session)
    assert not generic.perm_add_dids(random_account, {'dids': [with_rule]}, db_session)
    grant('rbac_other:%(prefix)s_f1', 'r')
    assert generic.perm_add_did(random_account, with_rule, db_session)


def test_registering_replicas(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): A replica of an existing file needs READ on it; a new file is left to the creation of its DID."""
    readable, unreadable, new_file = '%s_r' % grant.prefix, '%s_x' % grant.prefix, '%s_new' % grant.prefix
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('mock:%(prefix)s_r', 'r')

    def registers(*names: str) -> bool:
        return generic.perm_add_replicas(random_account, {'rse': 'SOME_USERDISK', 'scopes': [MOCK], 'dids': [{'scope': 'mock', 'name': name} for name in names]}, db_session)

    assert registers(readable, new_file)
    assert not registers(unreadable)


# The actions the generic policy leaves to root and admins without RBAC (and 'delete_replicas' to nobody). RBAC grants
# at most what owning a scope grants, so no role, nor owning the scope or the DID, may grant them.
ADMIN_ONLY_ACTIONS = (
    'add_account', 'add_account_identity', 'add_attribute', 'add_bad_pfns', 'add_opendata_did', 'add_protocol', 'add_rse',
    'add_rse_attribute', 'add_scope', 'add_subscription', 'approve_rule', 'cancel_request', 'config_add_section', 'config_get',
    'config_has_option', 'config_has_section', 'config_items', 'config_options', 'config_remove_option', 'config_remove_section',
    'config_sections', 'config_set', 'declare_bad_file_replicas', 'del_account',
    'del_account_identity', 'del_protocol', 'del_rse', 'del_rse_attribute', 'del_rule', 'delete_opendata_did', 'delete_replicas',
    'delete_transfer_limit', 'export', 'get_next', 'get_request_history_by_did', 'list_heartbeats',
    'list_requests', 'list_requests_history', 'list_transfer_limits', 'move_rule', 'queue_requests', 'reduce_rule', 'resurrect',
    'set_rse_limits', 'set_rse_usage', 'set_transfer_limit', 'skip_availability_check', 'update_account', 'update_opendata_did',
    'update_protocol', 'update_replicas_states', 'update_rse', 'update_rule', 'update_subscription',
)


@pytest.mark.parametrize('action', ADMIN_ONLY_ACTIONS)
def test_no_role_grants_what_is_left_to_admins(random_account, grant, catalogue, generic, db_session, monkeypatch, action):
    """ROLE DID PERMISSION (CORE): What the generic policy leaves to root and admins, no role grants, even 'rwd' on every DID to the owner of the scope and of the DID."""
    import rucio.core.scope

    name = '%s_file' % grant.prefix
    catalogue.add(name, owner=random_account)
    grant('*:*', 'rwd')
    monkeypatch.setattr(rucio.core.scope, 'is_scope_owner', lambda *args, **kwargs: True)
    did = {'scope': 'mock', 'name': name, 'state': 'A'}
    # every argument any of these actions may look at, about the DID
    kwargs = {'scope': MOCK, 'name': name, 'account': random_account, 'accounts': [random_account.external], 'rule_id': 'some-rule',
              'options': {'comment': 'c'}, 'override': {}, 'copies': 1, 'rse': 'SOME_USERDISK', 'rse_id': 'some-rse', 'scopes': [MOCK],
              'dids': [did], 'files': [did], 'issuer': random_account, 'vo': random_account.vo}
    assert not generic.has_permission(random_account, action, kwargs, db_session)


# The actions reading a DID or its data, which the generic policy grants every account without RBAC
READ_ACTIONS = (
    'list_dids', 'list_parent_dids', 'get_did', 'get_metadata', 'get_metadata_bulk', 'list_content', 'list_content_history', 'list_files',
    'scope_list', 'list_archive_content', 'get_users_following_did', 'add_did_to_followed', 'list_replication_rule_history',
    'list_replication_rule_full_history', 'get_replication_rule', 'examine_replication_rule', 'get_dataset_locks', 'get_dataset_locks_bulk',
    'list_associated_replication_rules_for_file', 'list_replicas', 'list_dataset_replicas', 'list_dataset_replicas_bulk',
    'list_dataset_replicas_vp', 'get_replica_locks_for_rule_id', 'get_request_by_did', 'delete_metadata',
)


@pytest.mark.parametrize('rbac', [False, True], indirect=True)
def test_without_rbac_every_account_reads_every_did(random_account, grant, catalogue, generic, db_session, rbac):
    """ROLE DID PERMISSION (CORE): Without RBAC, every account reads the DIDs of every scope and copies their data, as in standard Rucio; with RBAC, not without a role."""
    name = '%s_file' % grant.prefix
    catalogue.add(name, owner='someone else')
    did = {'scope': 'rbac_other', 'name': name}
    allowed = {action: generic.has_permission(random_account, action, {'scope': OTHER, 'name': name, 'key': 'project'}, db_session) for action in READ_ACTIONS}
    allowed['add_rule'] = generic.has_permission(random_account, 'add_rule', {'account': random_account, 'locked': False, 'dids': [did]}, db_session)
    allowed['add_replicas'] = generic.has_permission(random_account, 'add_replicas', {'rse': 'SOME_USERDISK', 'scopes': [OTHER], 'dids': [did]}, db_session)
    assert allowed == dict.fromkeys(allowed, not rbac)


@pytest.mark.parametrize('rbac', [False, True], indirect=True)
def test_without_rbac_roles_grant_nothing(random_account, grant, catalogue, generic, db_session, rbac):
    """ROLE DID PERMISSION (CORE): Without RBAC, the actions roles extend are as in standard Rucio: a role granting every operation on the DIDs changes none of them."""
    collection, content = ('%s_%s' % (grant.prefix, suffix) for suffix in ('ds', 'f1'))
    catalogue.add(collection, owner='someone else')
    catalogue.add(content, owner='someone else')
    did, dids = {'scope': OTHER, 'name': collection}, [{'scope': 'rbac_other', 'name': content}]
    kwargs = {
        'add_did': {'scope': OTHER, 'name': '%s_new' % grant.prefix},
        'attach_dids': {**did, 'attachment': {'dids': dids}},
        'attach_dids_to_dids': {'attachments': [{**did, 'dids': dids}]},
        'create_did_sample': did,
        'detach_dids': {**did, 'dids': dids},
        'set_metadata': {**did, 'key': 'project', 'value': 'p'},
        'set_metadata_bulk': {**did, 'meta': {'project': 'p'}},
    }

    def allowed() -> dict[str, bool]:
        return {action: generic.has_permission(random_account, action, action_kwargs, db_session) for action, action_kwargs in kwargs.items()}

    # outside the scope 'mock', an account alters nothing in a scope it does not own
    assert allowed() == dict.fromkeys(kwargs, False)
    grant('rbac_other:%(prefix)s*', 'rwd')
    assert allowed() == dict.fromkeys(kwargs, rbac)


def test_admin_attribute_keeps_counting_with_rbac(random_account, generic, db_session):
    """ROLE DID PERMISSION (CORE): With RBAC, an account with the 'admin' attribute stays an admin, like the holders of the admin role: enabling RBAC demotes no admin."""
    from rucio.core.account import add_account_attribute

    assert not generic.perm_add_scope(random_account, {}, db_session)
    add_account_attribute(random_account, 'admin', True, session=db_session)
    assert generic.perm_add_scope(random_account, {}, db_session)


def test_creating_dids_for_another_account(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): No role grants to create a DID owned by another account: it is left to root, admins and the owner of the scope."""
    grant('rbac_other:%(prefix)s*', 'rw')
    new = {'scope': OTHER, 'name': '%s_ds' % grant.prefix}
    assert generic.perm_add_did(random_account, {**new, 'account': random_account}, db_session)
    assert not generic.perm_add_did(random_account, {**new, 'account': InternalAccount('root')}, db_session)
    assert not generic.perm_add_did(random_account, {**new, 'account': 'root'}, db_session)


def test_recursive_metadata_is_not_granted(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): A recursive metadata update rewrites the whole content, which no role grants, even on an owned DID."""
    from rucio.core.permission import generic

    name = '%s_ds' % grant.prefix
    grant('mock:%(prefix)s*', 'rw')
    catalogue.add(name, owner=random_account)
    kwargs = {'scope': MOCK, 'name': name, 'key': 'project', 'value': 'p', 'meta': {'project': 'p'}}
    assert generic.perm_set_metadata(random_account, kwargs, db_session)
    assert generic.perm_set_metadata_bulk(random_account, kwargs, db_session)
    assert not generic.perm_set_metadata(random_account, {**kwargs, 'recursive': True}, db_session)
    assert not generic.perm_set_metadata_bulk(random_account, {**kwargs, 'recursive': True}, db_session)


def _granted(account, name: Optional[str], db_session) -> str:
    """The operations the roles of an account grant on a DID of the scope 'mock' (on the whole scope without `name`), e.g. 'rw-'."""
    return ''.join(letter if core_role.has_did_permission(account, MOCK, name, DidOperationType(LETTERS[letter]), session=db_session)
                   else '-' for letter in 'rwd')


@pytest.mark.parametrize(('rows', 'name', 'expected'), [
    ([('mock:%(prefix)s*', 'rw'), ('mock:%(prefix)s_raw*', 'r')], '%s_raw1', 'r--'),
    ([('mock:%(prefix)s*', 'rw'), ('mock:%(prefix)s_raw*', 'r')], '%s_calib1', 'rw-'),
    ([('mock:%(prefix)s*', 'r'), ('mock:%(prefix)s_raw*', 'w')], '%s_raw1', 'rw-'),
    ([('mock:%(prefix)s_raw*', 'r'), ('mock:%(prefix)s_raw1', 'w')], '%s_raw1', 'rw-'),
    ([('mock:%(prefix)s_ra*', 'd'), ('mock:%(prefix)s_raw*', 'r')], '%s_raw1', 'r--'),
    ([('mock:*', 'rwd'), ('mock:%(prefix)s_tmp*', '')], '%s_tmp1', '---'),
    ([('mock:*', 'rwd'), ('mock:%(prefix)s_tmp*', '')], '%s_raw1', 'rwd'),
    ([('mo*:*', 'rwd'), ('mock:*', 'w')], '%s_raw1', 'rw-'),
], ids=['narrower grants less', 'wider pattern elsewhere', 'narrower grants more', 'single DID beats a name pattern', 'longer prefix wins',
        'none withdraws everything', 'none only where it matches', 'scope beats scope pattern'])
def test_most_specific_pattern_decides(random_account, grant, db_session, rows, name, expected):
    """ROLE DID PERMISSION (CORE): Within a role, the most specific DID pattern matching a DID decides every operation the role grants on it."""
    for did_pattern, operations in rows:
        grant(did_pattern, operations)
    assert _granted(random_account, name % grant.prefix, db_session) == expected


def test_roles_add_up_despite_none(random_account, grant, db_session):
    """ROLE DID PERMISSION (CORE): A pattern granting nothing only withdraws DIDs within its own role: the roles of an account add up."""
    grant('mock:%(prefix)s*', 'r')
    grant('mock:%(prefix)s*', 'rw', role='other')
    grant('mock:%(prefix)s_tmp*', '', role='other')
    assert _granted(random_account, '%s_tmp1' % grant.prefix, db_session) == 'r--'
    assert _granted(random_account, '%s_raw1' % grant.prefix, db_session) == 'rw-'


def test_whole_scope_and_some_dids(random_account, grant, generic, db_session):
    """ROLE DID PERMISSION (CORE): A whole scope is only granted if no name pattern of the role withdraws the operation; some DIDs of it as soon as a deciding pattern grants it."""
    grant('mock:*', 'r')
    grant('mock:%(prefix)s_raw*', 'rw')
    assert _granted(random_account, None, db_session) == 'r--'
    grant('mock:%(prefix)s_tmp*', '')
    assert _granted(random_account, None, db_session) == '---'
    assert core_role.has_any_scope_prefix_access(account=random_account, scope=MOCK, operation=DidOperationType.READ, session=db_session)
    assert not generic.scope_filter(random_account, 'list_scopes', db_session)(MOCK)
    assert generic.scope_filter(random_account, 'list_scopes', db_session, any_did=True)(MOCK)


def test_none_on_a_scope_hides_it_from_a_scope_pattern(random_account, grant, db_session):
    """ROLE DID PERMISSION (CORE): A whole scope granting nothing withdraws it from a scope pattern of the same role, for its DIDs and for some READ in it."""
    grant('mo*:*', 'r')
    grant('mock:*', '')
    assert _granted(random_account, '%s_raw1' % grant.prefix, db_session) == '---'
    assert not core_role.has_any_scope_prefix_access(account=random_account, scope=MOCK, operation=DidOperationType.READ, session=db_session)
    assert core_role.has_any_scope_prefix_access(account=random_account, scope=InternalScope('mock2'), operation=DidOperationType.READ, session=db_session)


def test_read_only_area_in_a_writable_scope(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): 'rwd' on a scope and 'r' on a name pattern keep the matching DIDs read-only: they are neither altered nor created."""
    raw, calib = '%s_raw1' % grant.prefix, '%s_calib1' % grant.prefix
    catalogue.add(raw, owner='someone else')
    catalogue.add(calib, owner='someone else')
    grant('rbac_other:%(prefix)s*', 'rwd')
    grant('rbac_other:%(prefix)s_raw*', 'r')
    assert generic.perm_list_replicas(random_account, {'scope': OTHER, 'name': raw}, db_session)
    # setting a key leading to its removal alters the DID
    assert not generic.perm_set_metadata(random_account, {'scope': OTHER, 'name': raw, 'key': 'lifetime'}, db_session)
    assert generic.perm_set_metadata(random_account, {'scope': OTHER, 'name': calib, 'key': 'lifetime'}, db_session)
    assert not generic.perm_add_did(random_account, {'scope': OTHER, 'name': '%s_raw2' % grant.prefix}, db_session)
    assert generic.perm_add_did(random_account, {'scope': OTHER, 'name': '%s_calib2' % grant.prefix}, db_session)
    # the metadata keys fall back to the deciding DID permission
    assert not core_role.can_write_metadata_keys(random_account, OTHER, raw, ['project'], session=db_session)
    assert core_role.can_write_metadata_keys(random_account, OTHER, calib, ['project'], session=db_session)
    items = [{'scope': OTHER, 'name': name} for name in (raw, calib)]
    assert [item['name'] for item in core_permission.filter_dids(items, random_account, 'list_dids', session=db_session, operation=DidOperationType.DELETE)] == [calib]


def test_owner_with_write_has_metadata_like_delete(random_account, role_factory, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Owning a DID with WRITE on it grants DELETE on it, nothing more: the metadata keys fall back to it, but a metadata permission deciding a key decides it for the owner too."""
    own, other = '%s_own' % grant.prefix, '%s_other' % grant.prefix
    catalogue.add(own, owner=random_account)
    catalogue.add(other, owner='someone else')
    role = role_factory(random_account)
    pattern = 'rbac_other:%s*' % grant.prefix
    core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': pattern, 'operations': ['read', 'write']}, session=db_session)
    # a metadata permission granting nothing on 'project'
    core_role.add_role_permission(role, RolePermissionType.METADATA, {'did_pattern': pattern, 'keys': ['project'], 'operations': []}, session=db_session)

    def sets(name: str, key: str) -> bool:
        return generic.perm_set_metadata(random_account, {'scope': OTHER, 'name': name, 'key': key}, db_session)

    def deletes(name: str, key: str) -> bool:
        return generic.perm_delete_metadata(random_account, {'scope': OTHER, 'name': name, 'key': key}, db_session)

    # the owner sets and deletes the keys no metadata permission decides, and those removing the DID, as with DELETE
    assert sets(own, 'datatype')
    assert deletes(own, 'datatype')
    assert sets(own, 'lifetime')
    # a metadata permission deciding a key decides it for the owner too, which neither writes nor reads it
    assert not sets(own, 'project')
    assert not deletes(own, 'project')
    key_filter = generic.MetadataKeyFilter(random_account, db_session, filtered=True)
    assert key_filter.is_readable(OTHER, own, 'datatype')
    assert not key_filter.is_readable(OTHER, own, 'project')
    # WRITE alone, on a DID of another account, alters none of its keys
    assert not sets(other, 'datatype')
    assert not deletes(other, 'datatype')
    assert not sets(other, 'lifetime')


@pytest.mark.parametrize('rbac', [False, True], indirect=True)
def test_without_rbac_listings_show_every_did(random_account, generic, db_session, rbac):
    """ROLE DID PERMISSION (CORE): Without RBAC, a listing is not filtered: every DID is shown, even one without a scope or a name; with RBAC, not without a role."""
    items = [{'scope': OTHER, 'name': 'some_file'}, {'scope': None, 'name': None}]
    assert generic.is_listing_filtered(random_account, 'list_dids', db_session) is rbac
    assert list(core_permission.filter_dids(items, random_account, 'list_dids', session=db_session)) == ([] if rbac else items)


def test_reading_dids_and_scopes(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): READ on a DID reads it, its data and its transfer requests; a listing of a scope takes READ on some of its DIDs."""
    readable, unreadable = '%s_r1' % grant.prefix, '%s_x1' % grant.prefix
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')

    def reads(action: str, scope: InternalScope, name: Optional[str] = None) -> bool:
        return generic.has_permission(random_account, action, {'scope': scope, 'name': name}, db_session)

    assert not reads('list_dids', OTHER)
    grant('rbac_other:%(prefix)s_r*', 'r')
    for action in ('get_did', 'list_replicas', 'get_request_by_did'):
        assert reads(action, OTHER, readable)
        assert not reads(action, OTHER, unreadable)
    assert reads('list_dids', OTHER)
    assert not reads('list_dids', MOCK)


def test_root_and_scope_owners_need_no_role(random_account, root_account, catalogue, generic, db_session, monkeypatch):
    """ROLE DID PERMISSION (CORE): With RBAC, root and the owner of a scope read and alter every DID of it without any role, as in standard Rucio; only in that scope for its owner."""
    import rucio.core.scope

    name = 'rbac_%s_file' % generate_uuid()[:8]
    catalogue.add(name, owner='someone else')
    monkeypatch.setattr(rucio.core.scope, 'is_scope_owner', lambda scope, account, *args, **kwargs: scope == OTHER and account == random_account)
    for account in (root_account, random_account):
        assert generic.has_permission(account, 'list_replicas', {'scope': OTHER, 'name': name}, db_session)
        assert generic.has_permission(account, 'list_dids', {'scope': OTHER, 'name': None}, db_session)
        assert generic.perm_delete_metadata(account, {'scope': OTHER, 'name': name, 'key': 'project'}, db_session)
        # the whole scope is listed, so are the items without a name (e.g. counts)
        can_access = generic.did_filter(account, 'list_dids', db_session)
        assert can_access(OTHER, name)
        assert can_access(OTHER, None)
        assert generic.scope_filter(account, 'list_scopes', db_session)(OTHER)

    assert not generic.has_permission(random_account, 'list_replicas', {'scope': MOCK, 'name': name}, db_session)
    assert not generic.did_filter(random_account, 'list_dids', db_session)(MOCK, name)


@pytest.mark.parametrize(('operations', 'owned', 'allowed'), [
    ('r', True, False),
    ('w', False, False),
    ('w', True, True),
    ('d', False, True),
], ids=['own DID without WRITE', 'WRITE on a DID of another account', 'own DID with WRITE', 'DELETE on a DID of another account'])
def test_deleting_metadata(random_account, grant, catalogue, generic, db_session, operations, owned, allowed):
    """ROLE DID PERMISSION (CORE): With RBAC, deleting a metadata key alters the DID, like setting one: owning it with WRITE on it, or DELETE on it."""
    name = '%s_file' % grant.prefix
    catalogue.add(name, owner=random_account if owned else 'someone else')
    kwargs = {'scope': OTHER, 'name': name, 'key': 'project'}
    assert not generic.perm_delete_metadata(random_account, kwargs, db_session)
    grant('rbac_other:%(prefix)s*', operations)
    assert generic.perm_delete_metadata(random_account, kwargs, db_session) is allowed


def test_roles_only_grant_reading_the_dids_of_a_rule(random_account, grant, catalogue, generic, db_session, monkeypatch):
    """ROLE DID PERMISSION (CORE): Roles only add the READ a rule requires: a locked rule or one for another account stays left to root and admins, even with 'rwd' on every DID."""
    import rucio.core.scope

    readable, owned, unreadable = ('%s_%s' % (grant.prefix, suffix) for suffix in ('r1', 'own', 'x1'))
    catalogue.add(readable, owner='someone else')
    catalogue.add(owned, owner=random_account)
    catalogue.add(unreadable, owner='someone else')
    grant('rbac_other:%(prefix)s_r1', 'r')
    grant('rbac_other:%(prefix)s_own', 'w')

    def adds_rule(name: str, account: Optional[InternalAccount] = None, locked: bool = False) -> bool:
        kwargs = {'account': account or random_account, 'locked': locked, 'dids': [{'scope': 'rbac_other', 'name': name}]}
        return generic.perm_add_rule(random_account, kwargs, db_session)

    assert adds_rule(readable)
    # owning a DID, with WRITE on it, reads it
    assert adds_rule(owned)
    assert not adds_rule(unreadable)
    grant('*:*', 'rwd', role='other')
    assert not adds_rule(readable, locked=True)
    assert not adds_rule(readable, account=InternalAccount('root', vo=random_account.vo))
    # owning the scope reads its DIDs
    grant('rbac_other:%(prefix)s_x1', '', role='other')
    monkeypatch.setattr(rucio.core.scope, 'is_scope_owner', lambda scope, account, *args, **kwargs: scope == OTHER)
    assert adds_rule(unreadable)


def test_registering_replicas_of_whole_scopes(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Replicas given without their DIDs take READ on the whole scopes of their files; no role grants replicas on an RSE which is not a user RSE."""
    readable = '%s_r1' % grant.prefix
    catalogue.add(readable, owner='someone else')

    def registers(rse: str = 'SOME_USERDISK', *names: str) -> bool:
        kwargs = {'rse': rse, 'scopes': [OTHER], 'dids': [{'scope': 'rbac_other', 'name': name} for name in names]}
        return generic.perm_add_replicas(random_account, kwargs, db_session)

    grant('rbac_other:%(prefix)s*', 'r')
    assert registers('SOME_USERDISK', readable)
    # READ on some DIDs of the scope is not READ on the scope
    assert not registers()
    grant('rbac_other:*', 'r', role='other')
    assert registers()
    grant('*:*', 'rwd', role='other')
    assert not registers('SOME_DATADISK', readable)


def test_attaching_to_several_collections(random_account, grant, catalogue, generic, db_session):
    """ROLE DID PERMISSION (CORE): Attaching to several collections at once takes WRITE on each of them and READ on every attached DID, as attaching to one."""
    ds1, ds2, readable, unreadable = ('%s_%s' % (grant.prefix, suffix) for suffix in ('ds1', 'ds2', 'f1', 'f2'))
    for name in (ds1, ds2, readable, unreadable, 'other_ds'):
        catalogue.add(name, owner='someone else')
    grant('rbac_other:%(prefix)s_ds*', 'w')
    grant('rbac_other:%(prefix)s_f1', 'r')

    def attaches(*attachments: tuple[str, str]) -> bool:
        kwargs = {'attachments': [{'scope': OTHER, 'name': collection, 'dids': [{'scope': 'rbac_other', 'name': name}]} for collection, name in attachments]}
        return generic.perm_attach_dids_to_dids(random_account, kwargs, db_session)

    assert attaches((ds1, readable), (ds2, readable))
    assert not attaches((ds1, readable), (ds2, unreadable))
    assert not attaches((ds1, readable), ('other_ds', readable))


def test_creating_a_sample(random_account, grant, generic, db_session):
    """ROLE DID PERMISSION (CORE): A sample is a new dataset: it takes WRITE on its name, not READ."""
    grant('rbac_other:%(prefix)s*', 'w')
    grant('rbac_other:%(prefix)s_ro*', 'r')

    def samples(name: str) -> bool:
        return generic.perm_create_did_sample(random_account, {'issuer': random_account, 'scope': OTHER, 'name': name}, db_session)

    assert samples('%s_sample1' % grant.prefix)
    assert not samples('%s_ro1' % grant.prefix)
    assert not samples('other_sample1')


def test_policy_package_listing_filters(random_account, db_session, monkeypatch):
    """ROLE DID PERMISSION (CORE): A policy package defining no listing filter gets the generic ones; a filter it defines replaces the generic one."""
    import types

    package = types.SimpleNamespace(has_permission=lambda *args, **kwargs: None)
    monkeypatch.setitem(core_permission.permission_modules, random_account.vo, package)
    items = [{'scope': OTHER, 'name': 'some_file'}]
    assert core_permission.is_listing_filtered(random_account, 'list_dids', session=db_session)
    assert list(core_permission.filter_dids(items, random_account, 'list_dids', session=db_session)) == []
    assert list(core_permission.filter_scopes(items, random_account, 'list_scopes', session=db_session)) == []

    package.is_listing_filtered = lambda *args, **kwargs: False
    package.did_filter = lambda *args, **kwargs: lambda scope, name: True
    package.scope_filter = lambda *args, **kwargs: lambda scope: True
    assert not core_permission.is_listing_filtered(random_account, 'list_dids', session=db_session)
    assert list(core_permission.filter_dids(items, random_account, 'list_dids', session=db_session)) == items
    assert list(core_permission.filter_scopes(items, random_account, 'list_scopes', session=db_session)) == items
