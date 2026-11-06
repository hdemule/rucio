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

from types import SimpleNamespace
from typing import Any, Optional

import pytest

from rucio.common.exception import Duplicate, InputValidationError
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import role as core_role
from rucio.db.sqla.constants import DidOperationType, ReplicaState, RolePermissionType


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


class _Catalogue:
    """Stands for the DIDs, replicas and locks the generic RBAC checks look up, see `catalogue`."""

    def __init__(self):
        self.owners: dict[str, Any] = {}
        self.states: dict[str, ReplicaState] = {}
        self.lock_accounts: dict[str, list[Any]] = {}

    def add(self, name: str, owner: Any, state: ReplicaState = ReplicaState.AVAILABLE, lock_accounts: Optional[list[Any]] = None) -> None:
        self.owners[name], self.states[name], self.lock_accounts[name] = owner, state, lock_accounts or []


@pytest.fixture
def catalogue(monkeypatch):
    """Let the generic RBAC checks look up made-up DIDs, replicas and locks instead of the database: a DID not added does not exist."""
    from rucio.common.exception import DataIdentifierNotFound
    from rucio.core.permission import generic

    data = _Catalogue()

    def get_did(scope, name, session):
        if name not in data.owners:
            raise DataIdentifierNotFound()
        return {'account': data.owners[name]}

    monkeypatch.setattr(generic, 'get_did', get_did)
    monkeypatch.setattr(core_role, '_did_owner', lambda scope, name, session: data.owners.get(name))
    monkeypatch.setattr(generic, 'get_replica', lambda rse_id, scope, name, session: {'state': data.states[name]})
    monkeypatch.setattr(generic, 'get_replica_locks', lambda scope, name, restrict_rses, session: [SimpleNamespace(account=account) for account in data.lock_accounts.get(name, [])])
    return data


@pytest.fixture
def grant(random_account, role_factory, db_session):
    """Grant operations ('r', 'w', 'd') to `random_account` on DID patterns of the scope 'mock' through a role of its own, the patterns using `%(prefix)s`."""
    role = role_factory(random_account)
    prefix = 'rbac_%s' % role[-8:]

    def _grant(did_pattern: str, operations: str) -> None:
        for letter in operations:
            operation = {'r': 'read', 'w': 'write', 'd': 'delete'}[letter]
            core_role.add_role_permission(role, RolePermissionType.DID, {'did_pattern': did_pattern % {'prefix': prefix}, 'operation': operation}, session=db_session)

    _grant.prefix = prefix  # type: ignore[attr-defined]
    return _grant


MOCK = InternalScope('mock')


def test_ownership_needs_read_in_scope(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): Owning a DID makes an account its admin only with some READ in its scope, on any pattern of the scope."""
    from rucio.core.permission import generic

    own = '%s_own' % grant.prefix
    catalogue.add(own, owner=random_account)
    grant('mock:%(prefix)s_new*', 'w')
    assert not core_role.has_any_scope_prefix_access(account=random_account, scope=MOCK, operation=DidOperationType.READ, session=db_session)
    assert not generic._rbac_can_alter_did(random_account, MOCK, own, db_session)
    assert not generic._rbac_can_read_did(random_account, MOCK, own, db_session)

    grant('mock:%(prefix)s_calib*', 'r')
    assert core_role.has_any_scope_prefix_access(account=random_account, scope=MOCK, operation=DidOperationType.READ, session=db_session)
    assert generic._rbac_can_alter_did(random_account, MOCK, own, db_session)
    assert generic._rbac_can_read_did(random_account, MOCK, own, db_session)


def test_filtering_listings_per_did(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): A listing shows the DIDs a name pattern matches and the owned DIDs of a scope with some READ; the scope itself is listed."""
    calib, other, own = ('%s_%s' % (grant.prefix, suffix) for suffix in ('calib1', 'other', 'own'))
    catalogue.add(calib, owner='someone else')
    catalogue.add(other, owner='someone else')
    catalogue.add(own, owner=random_account)

    # without READ in the scope, an owned DID is not shown either
    grant('mock:%(prefix)s_new*', 'w')
    can_access = core_role.did_access_checker(account=random_account, session=db_session)
    assert not can_access(MOCK, own)

    grant('mock:%(prefix)s_calib*', 'r')
    can_access = core_role.did_access_checker(account=random_account, session=db_session)
    assert can_access(MOCK, calib)
    assert can_access(MOCK, own)
    assert not can_access(MOCK, other)
    assert not can_access(MOCK, None)
    assert not can_access(InternalScope('data'), calib)

    items = [{'scope': MOCK, 'name': name} for name in (calib, other, own)]
    assert [item['name'] for item in core_role.filter_iterable_by_did_access(items, account=random_account, session=db_session)] == [calib, own]

    # the scopes are listed if some of their DIDs are readable, the whole-scope items (e.g. counts) are not shown
    assert core_role.scope_access_checker(account=random_account, session=db_session, any_did=True)(MOCK)
    assert not core_role.scope_access_checker(account=random_account, session=db_session)(MOCK)


@pytest.mark.parametrize(('operations', 'owned', 'allowed'), [
    ('w', False, False),
    ('d', False, True),
    ('rw', True, True),
], ids=['WRITE on a DID of another account', 'DELETE on a DID of another account', 'own DID'])
def test_altering_existing_dids(random_account, grant, catalogue, db_session, operations, owned, allowed):
    """ROLE DID PERMISSION (CORE): WRITE does not alter the existing DIDs of other accounts (metadata, detach, ...), DELETE or owning them does."""
    from rucio.core.permission import generic

    name = '%s_file' % grant.prefix
    catalogue.add(name, owner=random_account if owned else 'someone else')
    grant('mock:%(prefix)s*', operations)
    assert generic._rbac_can_alter_did(random_account, MOCK, name, db_session) is allowed
    assert generic._rbac_can_alter_metadata(random_account, MOCK, name, ['project'], db_session) is allowed
    # the keys held by Rucio are granted by no role, not even to the owner
    assert not generic._rbac_can_alter_metadata(random_account, MOCK, name, ['bytes'], db_session)


def test_attaching(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): Adding content into a collection takes WRITE on it, and READ on the attached DIDs (WRITE on the new files registered with it)."""
    from rucio.core.permission import generic

    collection, readable, unreadable, new_file = ('%s_%s' % (grant.prefix, suffix) for suffix in ('ds', 'f1', 'f2', 'f3'))
    catalogue.add(collection, owner='someone else')
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('mock:%(prefix)s_ds', 'w')
    grant('mock:%(prefix)s_f1', 'r')
    grant('mock:%(prefix)s_f3', 'w')

    assert generic._rbac_can_attach_into(random_account, MOCK, collection, db_session)
    assert generic._rbac_can_attach_dids(random_account, [{'scope': 'mock', 'name': readable}], False, db_session)
    assert not generic._rbac_can_attach_dids(random_account, [{'scope': 'mock', 'name': unreadable}], False, db_session)
    assert generic._rbac_can_attach_dids(random_account, [{'scope': 'mock', 'name': new_file}], True, db_session)
    assert not generic._rbac_can_attach_dids(random_account, [{'scope': 'mock', 'name': new_file}], False, db_session)


def test_detaching(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): Removing content from a collection takes DELETE on it or owning it; WRITE on it only removes the DIDs the account owns."""
    from rucio.core.permission import generic

    writable, deletable, owned, not_owned = ('%s_%s' % (grant.prefix, suffix) for suffix in ('ds1', 'ds2', 'f1', 'f2'))
    for name in (writable, deletable, not_owned):
        catalogue.add(name, owner='someone else')
    catalogue.add(owned, owner=random_account)
    grant('mock:%(prefix)s_ds1', 'rw')
    grant('mock:%(prefix)s_ds2', 'd')

    owned_did, not_owned_did = {'scope': 'mock', 'name': owned}, {'scope': 'mock', 'name': not_owned}
    assert generic._rbac_can_detach_from(random_account, MOCK, writable, [owned_did], db_session)
    assert not generic._rbac_can_detach_from(random_account, MOCK, writable, [not_owned_did], db_session)
    assert not generic._rbac_can_detach_from(random_account, MOCK, writable, [owned_did, not_owned_did], db_session)
    assert generic._rbac_can_detach_from(random_account, MOCK, deletable, [not_owned_did], db_session)


def test_creating_dids(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): Creating a DID takes WRITE on it; its metadata, content and rules are checked along with it."""
    from rucio.core.permission import generic

    new = {'scope': MOCK, 'name': '%s_ds' % grant.prefix}
    grant('mock:%(prefix)s*', 'w')
    assert generic._rbac_can_create_did(random_account, new, db_session)
    assert generic._rbac_can_create_did(random_account, {**new, 'meta': {'project': 'p'}}, db_session)
    assert not generic._rbac_can_create_did(random_account, {**new, 'meta': {'bytes': 1}}, db_session)
    # removing it later needs to own it, which needs some READ in the scope
    assert not generic._rbac_can_create_did(random_account, {**new, 'meta': {'lifetime': 3600}}, db_session)
    # its rules copy data, which needs to read it
    assert not generic._rbac_can_create_did_with(random_account, {**new, 'rules': [{'copies': 1}]}, db_session)

    grant('mock:%(prefix)s_calib*', 'r')
    assert generic._rbac_can_create_did(random_account, {**new, 'meta': {'lifetime': 3600}}, db_session)
    assert generic._rbac_can_create_did_with(random_account, {**new, 'rules': [{'copies': 1}]}, db_session)
    assert not generic._rbac_can_create_did(random_account, {'scope': MOCK, 'name': 'other_ds'}, db_session)


def test_rules_need_read(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): A rule requires to read every DID it is on."""
    from rucio.core.permission import generic

    readable, unreadable = '%s_r' % grant.prefix, '%s_x' % grant.prefix
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('mock:%(prefix)s_r', 'r')
    assert generic._rbac_can_read_dids(random_account, [{'scope': 'mock', 'name': readable}], db_session)
    assert not generic._rbac_can_read_dids(random_account, [{'scope': 'mock', 'name': readable}, {'scope': 'mock', 'name': unreadable}], db_session)


def test_registering_replicas(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): A replica of an existing file needs READ on it; a new file is left to the creation of its DID."""
    from rucio.core.permission import generic

    readable, unreadable, new_file = '%s_r' % grant.prefix, '%s_x' % grant.prefix, '%s_new' % grant.prefix
    catalogue.add(readable, owner='someone else')
    catalogue.add(unreadable, owner='someone else')
    grant('mock:%(prefix)s_r', 'r')

    def registers(*names: str) -> bool:
        return generic._rbac_can_register_replicas(random_account, {'scopes': [MOCK], 'dids': [{'scope': 'mock', 'name': name} for name in names]}, db_session)

    assert registers(readable, new_file)
    assert not registers(unreadable)


@pytest.mark.parametrize(('operations', 'owned', 'state', 'path', 'allowed'), [
    ('w', True, ReplicaState.COPYING, None, True),
    ('w', True, ReplicaState.AVAILABLE, None, False),
    ('w', False, ReplicaState.COPYING, None, False),
    ('w', True, ReplicaState.COPYING, 'new/path', False),
    ('d', False, ReplicaState.AVAILABLE, None, True),
    ('rw', True, ReplicaState.AVAILABLE, 'new/path', True),
], ids=['own upload with WRITE', 'own available replica with WRITE', 'upload of another account with WRITE', 'new path with WRITE',
        'replica of another account with DELETE', 'owner reading the scope'])
def test_marking_replica_available(random_account, grant, catalogue, db_session, operations, owned, state, path, allowed):
    """ROLE DID PERMISSION (CORE): Marking a replica available takes WRITE only to finish the upload of an owned file, else altering the file."""
    from rucio.core.permission import generic

    name = '%s_file' % grant.prefix
    grant('mock:%(prefix)s*', operations)
    catalogue.add(name, owner=random_account if owned else 'someone else', state=state)

    kwargs = {'rse': 'SOME_USERDISK', 'rse_id': 'some-rse', 'scopes': [MOCK], 'dids': [{'scope': 'mock', 'name': name, 'state': 'A', 'path': path}]}
    assert generic._rbac_can_update_replica_states(random_account, kwargs, db_session) is allowed
    assert not generic._rbac_can_update_replica_states(random_account, {**kwargs, 'rse': 'SOME_DATADISK'}, db_session)


@pytest.mark.parametrize(('operations', 'owned', 'lock_by_other', 'allowed'), [
    ('d', False, False, True),
    ('d', False, True, False),
    ('rw', True, False, True),
    ('rw', True, True, False),
    ('w', True, False, False),
    ('w', False, False, False),
], ids=['DELETE', 'DELETE, locked by another account', 'owner reading the scope', 'owner, locked by another account',
        'owner without READ in the scope', 'WRITE on a file of another account'])
def test_invalidating_and_deleting_replicas(random_account, grant, catalogue, db_session, operations, owned, lock_by_other, allowed):
    """ROLE DID PERMISSION (CORE): Deleting or invalidating a replica alters its file, and no role grants it on a replica a rule of another account holds."""
    from rucio.core.permission import generic

    name = '%s_file' % grant.prefix
    grant('mock:%(prefix)s*', operations)
    catalogue.add(name, owner=random_account if owned else 'someone else', lock_accounts=[random_account] + (['someone else'] if lock_by_other else []))

    did = {'scope': 'mock', 'name': name}
    deletion = {'rse': 'SOME_USERDISK', 'rse_id': 'some-rse', 'scopes': [MOCK], 'dids': [did]}
    assert generic._rbac_can_delete_replicas(random_account, deletion, db_session) is allowed
    for state in ('U', 'D', 'T', 'B'):
        update = {**deletion, 'dids': [{**did, 'state': state}]}
        assert generic._rbac_can_update_replica_states(random_account, update, db_session) is allowed


def test_creating_dids_for_another_account(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): No role grants to create a DID owned by another account: it is left to root, admins and the owner of the scope."""
    from rucio.core.permission import generic

    grant('mock:%(prefix)s*', 'rw')
    new = {'scope': MOCK, 'name': '%s_ds' % grant.prefix}
    assert generic._rbac_can_create_did(random_account, {**new, 'account': random_account}, db_session)
    assert not generic._rbac_can_create_did(random_account, {**new, 'account': InternalAccount('root')}, db_session)
    assert not generic._rbac_can_create_did(random_account, {**new, 'account': 'root'}, db_session)


def test_finishing_the_upload_of_a_copy(random_account, grant, catalogue, db_session):
    """ROLE DID PERMISSION (CORE): Who may register a copy of a readable file may also finish its upload, but not change its path or its state otherwise."""
    from rucio.core.permission import generic

    name = '%s_file' % grant.prefix
    grant('mock:%(prefix)s*', 'r')
    catalogue.add(name, owner='someone else', state=ReplicaState.COPYING, lock_accounts=[random_account])
    did = {'scope': 'mock', 'name': name}
    kwargs = {'rse': 'SOME_USERDISK', 'rse_id': 'some-rse', 'scopes': [MOCK]}
    assert generic._rbac_can_update_replica_states(random_account, {**kwargs, 'dids': [{**did, 'state': 'A'}]}, db_session)
    assert not generic._rbac_can_update_replica_states(random_account, {**kwargs, 'dids': [{**did, 'state': 'A', 'path': 'new/path'}]}, db_session)
    assert not generic._rbac_can_update_replica_states(random_account, {**kwargs, 'dids': [{**did, 'state': 'U'}]}, db_session)

    catalogue.add(name, owner='someone else', state=ReplicaState.COPYING, lock_accounts=['someone else'])
    assert not generic._rbac_can_update_replica_states(random_account, {**kwargs, 'dids': [{**did, 'state': 'A'}]}, db_session)


def test_recursive_metadata_is_not_granted(random_account, grant, catalogue, db_session, monkeypatch):
    """ROLE DID PERMISSION (CORE): A recursive metadata update rewrites the whole content, which no role grants, even on an owned DID."""
    from rucio.core.permission import generic

    monkeypatch.setattr(generic, '_use_roles', lambda: True)
    name = '%s_ds' % grant.prefix
    grant('mock:%(prefix)s*', 'rw')
    catalogue.add(name, owner=random_account)
    kwargs = {'scope': MOCK, 'name': name, 'key': 'project', 'value': 'p', 'meta': {'project': 'p'}}
    assert generic.perm_set_metadata(random_account, kwargs, db_session)
    assert generic.perm_set_metadata_bulk(random_account, kwargs, db_session)
    assert not generic.perm_set_metadata(random_account, {**kwargs, 'recursive': True}, db_session)
    assert not generic.perm_set_metadata_bulk(random_account, {**kwargs, 'recursive': True}, db_session)
