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

"""
End-to-end tests of the metadata permissions of roles, through the gateway.

Each test builds its own world in the database (a scope owned by root, accounts, roles, an RSE, DIDs with
metadata and replicas), acts on it as these accounts, and deletes it all afterwards. RBAC is enabled for the
test only. The metadata keys used are columns of the DIDs, so that no metadata plugin is needed.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional

import pytest
from sqlalchemy import delete

from rucio.common.exception import AccessDenied, InputValidationError
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import account_limit as core_account_limit
from rucio.core import did as core_did
from rucio.core import replica as core_replica
from rucio.core import role as core_role
from rucio.core import rse as core_rse
from rucio.core import scope as core_scope
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType, DidOperationType, DIDType, MetadataOperationType, RolePermissionType
from rucio.db.sqla.session import db_session
from rucio.gateway import did as gw_did
from rucio.gateway import replica as gw_replica
from rucio.gateway import rule as gw_rule
from rucio.gateway import scope as gw_scope
from rucio.tests.common_server import cleanup_db_deps

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

pytestmark = pytest.mark.usefixtures('generic_permission_policy')

DID_LETTERS = {'r': DidOperationType.READ, 'w': DidOperationType.WRITE, 'd': DidOperationType.DELETE}
META_LETTERS = {'r': MetadataOperationType.READ, 'w': MetadataOperationType.WRITE}
# the metadata keys of the world, set on every file: 'project' plays the 'quality' of the documentation
KEYS = ('project', 'datatype', 'campaign', 'version')
FILES = ('file1', 'file2', 'calib1', 'raw1')


def _db(function: "Callable[..., Any]", *args, **kwargs) -> Any:
    """Call a core function in a database session of its own, committed once it returns."""
    with db_session(DatabaseOperationType.WRITE) as session:
        return function(*args, session=session, **kwargs)


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
def no_disabled_filters(monkeypatch):
    """Disable no filter for the test, whatever the policy package of the instance disables."""
    monkeypatch.setattr(core_role, 'is_filter_disabled', lambda account, filter_name, *, session: False)


@dataclass
class World:
    vo: str
    scope: str
    rse: str
    accounts: dict[str, InternalAccount] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)

    @property
    def alice(self) -> str:
        return self.accounts['alice'].external

    @property
    def bob(self) -> str:
        return self.accounts['bob'].external

    @property
    def internal_scope(self) -> InternalScope:
        return InternalScope(self.scope, vo=self.vo)

    def did(self, name: str) -> dict[str, Any]:
        return {'scope': self.scope, 'name': name}

    def _pattern(self, did_pattern: str) -> str:
        return self.scope + did_pattern[1:] if did_pattern.startswith('S') else did_pattern

    def _role(self, account: str, role: Optional[str], **dates) -> str:
        if role in self.roles:
            return role  # type: ignore[return-value]
        new_role = 'rbac-%s' % generate_uuid()[:12]
        _db(core_role.add_role, new_role, locked=False)
        self.roles.append(new_role)
        # active since a while, so that the role holds whatever the clock does during the test
        dates.setdefault('activates_at', datetime.utcnow() - timedelta(hours=1))
        _db(core_role.add_account_role, self.accounts[account], new_role, **dates)
        return new_role

    def grant_did(self, account: str, did_pattern: str, operations: str, role: Optional[str] = None, **dates) -> str:
        """Grant DID `operations` ('r', 'w', 'd', '' for none) on `did_pattern` ('S' standing for the scope) through a role."""
        role = self._role(account, role, **dates)
        _db(core_role.add_role_permission, role, RolePermissionType.DID,
            {'did_pattern': self._pattern(did_pattern), 'operations': [DID_LETTERS[letter] for letter in operations]})
        return role

    def grant_meta(self, account: str, did_pattern: str, keys: tuple[str, ...], operations: str, role: Optional[str] = None, **dates) -> str:
        """Grant metadata `operations` ('r', 'w', '' for none) on `keys` ('*' for every key, none for no key) of `did_pattern` through a role."""
        role = self._role(account, role, **dates)
        _db(core_role.add_role_permission, role, RolePermissionType.METADATA,
            {'did_pattern': self._pattern(did_pattern), 'keys': list(keys), 'operations': [META_LETTERS[letter] for letter in operations]})
        return role

    def grant(self, account: str, grants: list[tuple[Any, ...]], role: Optional[str] = None) -> str:
        """Grant several permissions through one role: ('did', pattern, operations) or ('meta', pattern, keys, operations)."""
        for kind, *arguments in grants:
            role = (self.grant_did if kind == 'did' else self.grant_meta)(account, *arguments, role=role)
        return role  # type: ignore[return-value]


@pytest.fixture
def world(vo, no_disabled_filters, random_account_factory) -> "Iterator[World]":
    """
    A scope 'S' owned by root, the accounts alice and bob, an RSE X_USERDISK, the files file1, file2, calib1 and raw1 owned
    by root, each with a replica and the metadata keys of KEYS, the dataset ds1 owned by root holding file1 and file2, and the
    file mine owned by alice with the same keys.
    """
    prefix = generate_uuid()[:10]
    root = InternalAccount('root', vo=vo)
    world = World(vo=vo, scope='rbac_%s' % prefix, rse='RBAC%s_X_USERDISK' % prefix.upper())
    _db(core_scope.add_scope, world.internal_scope, root)
    rse_id = core_rse.add_rse(world.rse, vo=vo)
    try:
        for name in ('alice', 'bob'):
            world.accounts[name] = random_account_factory()
            _db(core_account_limit.set_local_account_limit, world.accounts[name], rse_id, 10**12)
        files = [{'scope': world.internal_scope, 'name': name, 'bytes': 1, 'adler32': '0cc737eb'} for name in FILES]
        core_replica.add_replicas(rse_id, files, root)
        core_replica.add_replicas(rse_id, [{'scope': world.internal_scope, 'name': 'mine', 'bytes': 1, 'adler32': '0cc737eb'}], world.accounts['alice'])
        core_did.add_did(world.internal_scope, 'ds1', DIDType.DATASET, root)
        core_did.attach_dids(world.internal_scope, 'ds1', [{'scope': world.internal_scope, 'name': name} for name in ('file1', 'file2')], root)
        for name in FILES + ('mine',):
            core_did.set_metadata_bulk(world.internal_scope, name, {key: '%s_%s' % (key, name) for key in KEYS})
        yield world
    finally:
        for role in world.roles:
            _db(core_role.delete_role, role, force=True)
        with db_session(DatabaseOperationType.WRITE) as session:
            cleanup_db_deps(model=models.Scope, select_rows_stmt=models.Scope.scope == world.internal_scope, session=session)
            session.execute(delete(models.Scope).where(models.Scope.scope == world.internal_scope))
            cleanup_db_deps(model=models.RSE, select_rows_stmt=models.RSE.id == rse_id, session=session)
            session.execute(delete(models.RSE).where(models.RSE.id == rse_id))


def _shown(w: World, account: str, name: str) -> Optional[set[str]]:
    """The keys of KEYS an account sees on a DID, None if it may not see the DID at all."""
    try:
        meta = gw_did.get_metadata(account, w.scope, name, vo=w.vo)
    except AccessDenied:
        return None
    return {key for key in KEYS if key in meta}


def _writes(w: World, account: str, name: str, key: str) -> bool:
    try:
        gw_did.set_metadata(w.scope, name, key, 'new', issuer=account, vo=w.vo)
    except AccessDenied:
        return False
    return True


def _access(w: World, account: str, name: str, key: str) -> str:
    """What an account may do on a key of a DID: 'rw', 'r-', '-w' or '--'."""
    shown = _shown(w, account, name)
    return ('r' if shown and key in shown else '-') + ('w' if _writes(w, account, name, key) else '-')


def _listed(w: World, account: str, filters: Optional[dict[str, Any]] = None) -> Optional[set[str]]:
    """The names of the DIDs an account lists in the scope, None if it may not list it."""
    try:
        return {did['name'] if isinstance(did, dict) else did
                for did in gw_did.list_dids(account, w.scope, [dict({'name': '*'}, **(filters or {}))], 'all', vo=w.vo)}
    except AccessDenied:
        return None


# ----------------------------------------------------------------------------------------------
# Granting
# ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(('keys', 'operations'), [
    ((), ''), ((), 'w'), ((), 'rw'),
    (('bytes',), 'w'), (('lifetime',), 'rw'), (('name',), 'w'),
], ids=['none on no key', 'w on no key', 'rw on no key', 'w on a reserved key', 'rw on a deletion key', 'w on the name'])
def test_invalid_metadata_permissions_are_refused(world, keys, operations):
    """ROLE METADATA PERMISSION (CORE): A permission on no key only makes DIDs visible, so it is r; no permission writes the keys Rucio reserves or the deletion keys."""
    with pytest.raises(InputValidationError):
        world.grant_meta('alice', 'S:*', keys, operations)


@pytest.mark.parametrize(('operations', 'stored'), [('', []), ('r', ['read']), ('w', ['read', 'write']), ('rw', ['read', 'write'])])
def test_metadata_write_includes_read(world, operations, stored):
    """ROLE METADATA PERMISSION (CORE): WRITE includes READ: a metadata permission is stored with the operations its operations include."""
    role = world.grant_meta('alice', 'S:*', ('project',), operations)
    permissions = _db(core_role.list_role_permissions, role)
    assert [permission['operations'] for permission in permissions if permission['type'] == 'metadata'] == [stored]


def test_reading_reserved_and_deletion_keys_can_be_granted(world):
    """ROLE METADATA PERMISSION (GATEWAY): READ may be granted on a reserved key, which then shows it, while WRITE on it never is."""
    world.grant_meta('alice', 'S:*', ('bytes', 'lifetime'), 'r')
    meta = gw_did.get_metadata(world.alice, world.scope, 'file1', vo=world.vo)
    assert meta['bytes'] == 1
    assert not set(KEYS) & set(meta)
    assert not _writes(world, world.alice, 'file1', 'bytes')


def test_granting_replaces_the_operations_of_a_key(world):
    """ROLE METADATA PERMISSION (CORE): Granting a key again replaces its operations, and a key granted nothing is kept, listed with no operation."""
    role = world.grant_meta('alice', 'S:*', ('project', 'campaign'), 'rw')
    world.grant_meta('alice', 'S:*', ('project',), 'r', role=role)
    world.grant_meta('alice', 'S:*', ('campaign',), '', role=role)
    permissions = sorted((p['meta_key'], tuple(p['operations'])) for p in _db(core_role.list_role_permissions, role) if p['type'] == 'metadata')
    assert permissions == [('campaign', ()), ('project', ('read',))]


# ----------------------------------------------------------------------------------------------
# Levels of access to a DID
# ----------------------------------------------------------------------------------------------

def test_no_permission_shows_nothing(world):
    """ROLE METADATA PERMISSION (GATEWAY): Without any row matching a DID, an account sees nothing of it."""
    world.grant_meta('alice', 'S:calib*', ('project',), 'r')
    assert _shown(world, world.alice, 'file1') is None
    # owning 'mine' does not let alice read it: ownership only grants DELETE, together with DID WRITE
    assert _listed(world, world.alice) == {'calib1'}


def test_metadata_permission_on_no_key_makes_dids_visible_only(world):
    """ROLE METADATA PERMISSION (GATEWAY): 'r' on no key lists the DIDs and their content, without any key nor data."""
    world.grant_meta('alice', 'S:*', (), 'r')
    assert _shown(world, world.alice, 'file1') == set()
    gw_did.get_did(world.alice, world.scope, 'file1', vo=world.vo)
    assert _listed(world, world.alice) == set(FILES) | {'ds1', 'mine'}
    assert {did['name'] for did in gw_did.list_content(world.alice, world.scope, 'ds1', vo=world.vo)} == {'file1', 'file2'}
    assert world.scope in gw_scope.list_scopes(world.alice, vo=world.vo)
    with pytest.raises(AccessDenied):
        list(gw_replica.list_replicas([world.did('file1')], issuer=world.alice, vo=world.vo))


def test_metadata_permission_on_some_keys(world):
    """ROLE METADATA PERMISSION (GATEWAY): 'r' on keys shows the DIDs with these keys only, and their identity, without their data."""
    world.grant_meta('alice', 'S:*', ('datatype', 'project'), 'r')
    meta = gw_did.get_metadata(world.alice, world.scope, 'file1', vo=world.vo)
    assert {key for key in KEYS if key in meta} == {'datatype', 'project'}
    assert meta['name'] == 'file1' and meta['scope'] == world.scope
    with pytest.raises(AccessDenied):
        list(gw_replica.list_replicas([world.did('file1')], issuer=world.alice, vo=world.vo))


def test_did_permission_reads_everything(world):
    """ROLE METADATA PERMISSION (GATEWAY): Without metadata permission, DID 'r' shows every key and the data."""
    world.grant_did('alice', 'S:*', 'r')
    assert _shown(world, world.alice, 'file1') == set(KEYS)
    list(gw_replica.list_replicas([world.did('file1')], issuer=world.alice, vo=world.vo))


@pytest.mark.parametrize('keys', [('*',), ('project',)], ids=['every key', 'one key'])
def test_hiding_keys_never_hides_the_did(world, keys):
    """ROLE METADATA PERMISSION (GATEWAY): '--' on keys hides them only: with DID 'r', the DID stays listed and its data readable."""
    role = world.grant_did('alice', 'S:*', 'r')
    world.grant_meta('alice', 'S:file1', keys, '', role=role)
    assert _shown(world, world.alice, 'file1') == (set() if keys == ('*',) else set(KEYS) - {'project'})
    assert 'file1' in _listed(world, world.alice)
    list(gw_replica.list_replicas([world.did('file1')], issuer=world.alice, vo=world.vo))
    assert _shown(world, world.alice, 'file2') == set(KEYS)


def test_hiding_keys_alone_grants_nothing(world):
    """ROLE METADATA PERMISSION (GATEWAY): A role made of '--' rows only grants nothing, not even seeing the DIDs."""
    role = world.grant_meta('alice', 'S:*', ('*',), '')
    world.grant_meta('alice', 'S:*', ('project',), '', role=role)
    assert _shown(world, world.alice, 'file1') is None
    assert _listed(world, world.alice) is None


def test_writing_a_key_shows_it(world):
    """ROLE METADATA PERMISSION (GATEWAY): 'w' on a key includes 'r': the DID is visible with that key, which is written, and no key is written blindly."""
    world.grant_meta('alice', 'S:*', ('project',), 'w')
    assert _shown(world, world.alice, 'file1') == {'project'}
    assert _writes(world, world.alice, 'file1', 'project')
    assert core_did.get_metadata(world.internal_scope, 'file1')['project'] == 'new'
    assert not _writes(world, world.alice, 'file1', 'campaign')


# ----------------------------------------------------------------------------------------------
# Within a role: the narrowest subject decides
# ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(('grants', 'expected'), [
    # the same key on several patterns: the most specific pattern decides
    ([('meta', 'S:*', ('project',), 'rw'), ('meta', 'S:file*', ('project',), ''), ('meta', 'S:file1', ('project',), 'r')],
     {('file1', 'project'): 'r-', ('file2', 'project'): '--', ('calib1', 'project'): 'rw'}),
    ([('meta', 'S*:*', ('project',), 'rw'), ('meta', 'S:*', ('project',), 'r')],
     {('file1', 'project'): 'r-', ('calib1', 'project'): 'r-'}),
    ([('meta', 'S:*', ('project',), ''), ('meta', 'S:file1', ('project',), 'rw')],
     {('file1', 'project'): 'rw', ('file2', 'project'): '--'}),
    # a row naming the key beats '*', even with a less specific pattern
    ([('meta', 'S:file1', ('*',), 'rw'), ('meta', 'S:*', ('project',), 'r')],
     {('file1', 'project'): 'r-', ('file1', 'campaign'): 'rw'}),
    ([('meta', 'S:*', ('*',), ''), ('meta', 'S:file1', ('project',), 'r')],
     {('file1', 'project'): 'r-', ('file1', 'campaign'): '--'}),
    ([('meta', 'S:*', ('*',), 'r'), ('meta', 'S:*', ('project',), '')],
     {('file1', 'project'): '--', ('file1', 'campaign'): 'r-'}),
    # metadata permissions against the DID permissions of the role
    ([('did', 'S:*', 'r'), ('meta', 'S:file1', ('project',), '')],
     {('file1', 'project'): '--', ('file1', 'campaign'): 'r-', ('file2', 'project'): 'r-'}),
    ([('did', 'S:*', 'r'), ('meta', 'S:*', ('project',), 'rw')],
     {('file1', 'project'): 'rw', ('file1', 'campaign'): 'r-'}),
    # 'w' includes 'r': a row writing the key never hides it
    ([('did', 'S:*', 'r'), ('meta', 'S:*', ('project',), 'w')],
     {('file1', 'project'): 'rw', ('file1', 'campaign'): 'r-'}),
    ([('did', 'S:*', 'rwd'), ('meta', 'S:*', ('project',), 'r')],
     {('file1', 'project'): 'r-', ('file1', 'campaign'): 'rw'}),
    # the keys fall back to the DID permission deciding the DID
    ([('did', 'S:*', 'rwd'), ('did', 'S:raw*', 'r'), ('meta', 'S:file1', ('version',), 'r')],
     {('raw1', 'project'): 'r-', ('file2', 'project'): 'rw'}),
], ids=lambda value: str(value))
def test_narrowest_subject_decides_within_a_role(world, grants, expected):
    """ROLE METADATA PERMISSION (GATEWAY): For each key of each DID, a row naming the key, then a row on '*', then the DID permission of the role decides."""
    world.grant('alice', grants)
    assert {did_key: _access(world, world.alice, *did_key) for did_key in expected} == expected


def test_every_key_of_a_call_must_be_writable(world):
    """ROLE METADATA PERMISSION (GATEWAY): Setting several keys at once needs every one of them writable."""
    world.grant('alice', [('did', 'S:*', 'r'), ('meta', 'S:file1', ('project',), 'rw')])
    with pytest.raises(AccessDenied):
        gw_did.set_metadata_bulk(world.scope, 'file1', {'project': 'new', 'campaign': 'new'}, issuer=world.alice, vo=world.vo)
    gw_did.set_metadata_bulk(world.scope, 'file1', {'project': 'new'}, issuer=world.alice, vo=world.vo)


def test_every_key_but_the_reserved_ones(world):
    """ROLE METADATA PERMISSION (GATEWAY): 'rw' on '*' writes every key but those Rucio holds and the deletion keys."""
    world.grant_meta('alice', 'S:*', ('*',), 'rw')
    assert all(_writes(world, world.alice, 'file1', key) for key in KEYS)
    with pytest.raises(AccessDenied):
        gw_did.set_metadata(world.scope, 'file1', 'bytes', 2, issuer=world.alice, vo=world.vo)
    with pytest.raises(AccessDenied):
        gw_did.set_metadata(world.scope, 'file1', 'lifetime', 3600, issuer=world.alice, vo=world.vo)


def test_deletion_key_is_set_through_the_did(world):
    """ROLE METADATA PERMISSION (GATEWAY): A deletion key hidden by a metadata row is still set through DID DELETE, and never through a metadata row."""
    world.grant('alice', [('did', 'S:*', 'rd'), ('meta', 'S:file1', ('lifetime',), '')])
    gw_did.set_metadata(world.scope, 'file1', 'lifetime', 3600, issuer=world.alice, vo=world.vo)
    assert 'lifetime' not in gw_did.get_metadata(world.alice, world.scope, 'file1', vo=world.vo)


# ----------------------------------------------------------------------------------------------
# Across roles: everything adds up
# ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(('role_a', 'role_b', 'expected'), [
    ([('did', 'S:*', 'r')], [('meta', 'S:*', ('project',), '')], {'project': 'r-', 'campaign': 'r-'}),
    ([('did', 'S:*', 'r')], [('meta', 'S:*', ('*',), '')], {'project': 'r-', 'campaign': 'r-'}),
    ([('did', 'S:*', 'r'), ('meta', 'S:*', ('project',), '')], [('meta', 'S:*', ('project',), 'rw')], {'project': 'rw', 'campaign': 'r-'}),
    ([('did', 'S:*', 'rwd')], [('meta', 'S:*', ('project',), '')], {'project': 'rw', 'campaign': 'rw'}),
    ([('meta', 'S:*', ('project',), 'r')], [('meta', 'S:*', ('project',), 'w')], {'project': 'rw', 'campaign': '--'}),
    ([('meta', 'S:*', ('project',), 'r')], [('meta', 'S:file1', ('project',), '')], {'project': 'r-', 'campaign': '--'}),
    ([('meta', 'S:*', ('*',), 'rw')], [('meta', 'S:*', ('project',), 'r')], {'project': 'rw', 'campaign': 'rw'}),
    ([('meta', 'S:*', ('project',), 'w')], [('did', 'S:*', 'r')], {'project': 'rw', 'campaign': 'r-'}),
], ids=lambda value: str(value))
def test_roles_add_up(world, role_a, role_b, expected):
    """ROLE METADATA PERMISSION (GATEWAY): A key is readable (writable) if one role makes it so: a '--' never hides what another role shows."""
    world.grant('alice', role_a)
    world.grant('alice', role_b)
    assert {key: _access(world, world.alice, 'file1', key) for key in expected} == expected


def test_metadata_permissions_per_did_across_roles(world):
    """ROLE METADATA PERMISSION (GATEWAY): Each DID is decided on its own: DID 'r' on one DID, metadata 'r' on a key of the others."""
    world.grant('alice', [('meta', 'S:*', ('project',), 'r')])
    world.grant('alice', [('did', 'S:file1', 'r')])
    assert _shown(world, world.alice, 'file1') == set(KEYS)
    assert _shown(world, world.alice, 'file2') == {'project'}
    list(gw_replica.list_replicas([world.did('file1')], issuer=world.alice, vo=world.vo))
    with pytest.raises(AccessDenied):
        list(gw_replica.list_replicas([world.did('file2')], issuer=world.alice, vo=world.vo))


def test_expired_role_shows_no_key(world):
    """ROLE METADATA PERMISSION (GATEWAY): The metadata permissions of an inactive assignment grant nothing."""
    now = datetime.utcnow()
    world.grant_meta('alice', 'S:*', ('*',), 'r', activates_at=now - timedelta(days=2), expires_at=now - timedelta(days=1))
    assert _shown(world, world.alice, 'file1') is None


# ----------------------------------------------------------------------------------------------
# What a metadata permission never grants
# ----------------------------------------------------------------------------------------------

def test_metadata_read_is_not_did_read(world):
    """ROLE METADATA PERMISSION (GATEWAY): Metadata READ grants neither the data, nor READ as a prerequisite: rules, attaching, owning."""
    world.grant('alice', [('meta', 'S:*', ('*',), 'r'), ('did', 'S:alice.*', 'w')])
    with pytest.raises(AccessDenied):
        list(gw_replica.list_replicas([world.did('ds1')], issuer=world.alice, vo=world.vo))
    gw_did.add_did(world.scope, 'alice.ds', 'DATASET', issuer=world.alice, vo=world.vo)
    with pytest.raises(AccessDenied):
        gw_did.attach_dids(world.scope, 'alice.ds', {'dids': [world.did('file1')]}, issuer=world.alice, vo=world.vo)
    with pytest.raises(AccessDenied):
        gw_rule.add_replication_rule([world.did('file1')], copies=1, rse_expression=world.rse, weight=None, lifetime=None, grouping='NONE',
                                     account=world.alice, locked=False, subscription_id=None, source_replica_expression=None, activity=None,
                                     notify=None, purge_replicas=False, ignore_availability=False, comment=None, ask_approval=False,
                                     asynchronous=False, delay_injection=None, priority=3, split_container=False, meta=None,
                                     issuer=world.alice, vo=world.vo)
    # nor ownership: without DID WRITE on her own file, alice may not delete it as its owner, so neither write its keys
    assert not _writes(world, world.alice, 'mine', 'project')
    with pytest.raises(AccessDenied):
        gw_did.set_metadata(world.scope, 'mine', 'lifetime', 3600, issuer=world.alice, vo=world.vo)


def test_metadata_visibility_lists_rse_level_items(world):
    """ROLE METADATA PERMISSION (GATEWAY): A visible DID has its rules, locks and dataset replicas listed, not its file replicas."""
    gw_rule.add_replication_rule([world.did('ds1')], copies=1, rse_expression=world.rse, weight=None, lifetime=None, grouping='DATASET',
                                 account='root', locked=False, subscription_id=None, source_replica_expression=None, activity=None,
                                 notify=None, purge_replicas=False, ignore_availability=False, comment=None, ask_approval=False,
                                 asynchronous=False, delay_injection=None, priority=3, split_container=False, meta=None, issuer='root', vo=world.vo)
    world.grant_meta('alice', 'S:*', (), 'r')
    assert len(list(gw_rule.list_associated_replication_rules_for_file(world.alice, world.scope, 'file1', vo=world.vo))) == 1
    assert len(list(gw_replica.list_dataset_replicas(world.alice, world.scope, 'ds1', vo=world.vo))) == 1
    with pytest.raises(AccessDenied):
        list(gw_replica.list_replicas([world.did('file1')], issuer=world.alice, vo=world.vo))


# ----------------------------------------------------------------------------------------------
# Who bypasses them, and listings
# ----------------------------------------------------------------------------------------------

def test_owner_with_write_is_bound_by_them_like_delete(world):
    """ROLE METADATA PERMISSION (GATEWAY): The owner of a DID, with DID WRITE on it, has DELETE on it: the metadata permissions decide its keys as for an account with DID DELETE."""
    # alice owns 'mine' and writes it, bob does not own it but may delete it
    world.grant('alice', [('did', 'S:calib*', 'r'), ('did', 'S:mine', 'w'), ('meta', 'S:*', ('project',), '')])
    world.grant('bob', [('did', 'S:mine', 'rwd'), ('meta', 'S:*', ('project',), '')])
    for account in (world.alice, world.bob):
        # a metadata permission deciding a key decides it
        assert _shown(world, account, 'mine') == set(KEYS) - {'project'}
        assert not _writes(world, account, 'mine', 'project')
        # the other keys fall back to DELETE on the DID, which the owner has through WRITE
        assert _writes(world, account, 'mine', 'datatype')
    assert _shown(world, world.alice, 'calib1') == set(KEYS) - {'project'}
    assert not _writes(world, world.alice, 'calib1', 'datatype')


def test_root_and_scope_owner_bypass_them(world):
    """ROLE METADATA PERMISSION (GATEWAY): Root reads every key, whatever the metadata permissions."""
    assert _shown(world, 'root', 'file1') == set(KEYS)


def test_listing_filter_on_an_unreadable_key(world):
    """ROLE METADATA PERMISSION (GATEWAY): A listing filtered on a key leaves out the DIDs on which the account may not read the key."""
    world.grant('alice', [('did', 'S:*', 'r'), ('meta', 'S:file1', ('project',), '')])
    assert _listed(world, world.alice, {'project': 'project_file2'}) == {'file2'}
    assert _listed(world, world.alice, {'project': 'project_file1'}) == set()
    assert _listed(world, 'root', {'project': 'project_file1'}) == {'file1'}


def test_listing_hides_the_unreadable_keys(world):
    """ROLE METADATA PERMISSION (GATEWAY): The metadata returned in bulk leaves out the keys the account may not read."""
    world.grant('alice', [('meta', 'S:*', ('project',), 'r')])
    metas = list(gw_did.get_metadata_bulk(world.alice, [world.did(name) for name in ('file1', 'file2')], vo=world.vo))
    assert len(metas) == 2
    assert all({key for key in KEYS if key in meta} == {'project'} for meta in metas)


@pytest.mark.parametrize('rbac', [False], indirect=True)
def test_rbac_disabled_ignores_them(world, rbac):
    """ROLE METADATA PERMISSION (GATEWAY): Without RBAC, every key of every DID is shown, as in standard Rucio."""
    world.grant_meta('alice', 'S:*', ('*',), '')
    assert _shown(world, world.alice, 'file1') == set(KEYS)
