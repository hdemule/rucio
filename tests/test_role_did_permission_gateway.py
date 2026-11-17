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
End-to-end tests of the DID permissions of roles, through the gateway.

Each test builds its own world in the database (a scope owned by root, accounts, roles, RSEs, DIDs, replicas
and rules), acts on it as these accounts, and deletes it all afterwards. RBAC is enabled for the test only.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional, Union

import pytest
from sqlalchemy import delete, update

from rucio.common.constants import ADMIN_ROLE
from rucio.common.exception import AccessDenied, DataIdentifierNotFound, RucioException, UnsupportedOperation
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import account as core_account
from rucio.core import account_limit as core_account_limit
from rucio.core import did as core_did
from rucio.core import permission as core_permission
from rucio.core import replica as core_replica
from rucio.core import role as core_role
from rucio.core import rse as core_rse
from rucio.core import rule as core_rule
from rucio.core import scope as core_scope
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType, DidOperationType, DIDType, LockState, ReplicaState, RolePermissionType, RuleState
from rucio.db.sqla.session import db_session
from rucio.db.sqla.util import json_implemented
from rucio.gateway import did as gw_did
from rucio.gateway import lifetime_exception as gw_lifetime_exception
from rucio.gateway import lock as gw_lock
from rucio.gateway import replica as gw_replica
from rucio.gateway import rule as gw_rule
from rucio.gateway import scope as gw_scope
from rucio.tests.common_server import cleanup_db_deps

pytestmark = pytest.mark.usefixtures('generic_permission_policy')

LETTERS = {'r': DidOperationType.READ, 'w': DidOperationType.WRITE, 'd': DidOperationType.DELETE}
ADLER32 = '0cc737eb'


def _db(function: Callable[..., Any], *args, **kwargs) -> Any:
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
def scope_cleaner() -> Iterator[Callable[[InternalScope], None]]:
    """Register scopes made by the test: they are deleted afterwards, with every DID, replica, rule and lock in them."""
    scopes: list[InternalScope] = []
    yield scopes.append
    with db_session(DatabaseOperationType.WRITE) as session:
        for scope in scopes:
            cleanup_db_deps(model=models.Scope, select_rows_stmt=models.Scope.scope == scope, session=session)
            session.execute(delete(models.Scope).where(models.Scope.scope == scope))


@pytest.fixture
def rse_cleaner() -> Iterator[Callable[[str], None]]:
    """Register RSEs made by the test, by id: they are deleted afterwards, with everything on them."""
    rse_ids: list[str] = []
    yield rse_ids.append
    with db_session(DatabaseOperationType.WRITE) as session:
        for rse_id in rse_ids:
            cleanup_db_deps(model=models.RSE, select_rows_stmt=models.RSE.id == rse_id, session=session)
            session.execute(delete(models.RSE).where(models.RSE.id == rse_id))


@pytest.fixture
def role_cleaner() -> Iterator[list[str]]:
    """The roles made by the test: they are deleted afterwards, with their permissions and assignments."""
    roles: list[str] = []
    yield roles
    for role in roles:
        _db(core_role.delete_role, role, force=True)


@dataclass
class World:
    vo: str
    scope: str
    prefix: str
    accounts: dict[str, InternalAccount] = field(default_factory=dict)
    rses: dict[str, str] = field(default_factory=dict)
    rules: dict[str, str] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)

    def __getattr__(self, name: str) -> str:
        """The external name of an account of the world, e.g. `world.alice`."""
        accounts = self.__dict__.get('accounts', {})
        if name in accounts:
            return accounts[name].external
        raise AttributeError(name)

    @property
    def internal_scope(self) -> InternalScope:
        return InternalScope(self.scope, vo=self.vo)

    def did(self, name: str) -> dict[str, Any]:
        return {'scope': self.scope, 'name': name}

    def file(self, name: str) -> dict[str, Any]:
        return {'scope': self.scope, 'name': name, 'bytes': 1, 'adler32': ADLER32}

    def rse(self, short: str) -> str:
        return self.rses[short]

    def grant(self, account: str, did_pattern: str, operations: str, role: Optional[str] = None, **dates) -> str:
        """Grant `operations` ('r', 'w', 'd', '' for none) on `did_pattern` ('S' standing for the scope) to an account through a role."""
        if role is None or role not in self.roles:
            new_role = 'rbac-%s' % generate_uuid()[:12]
            _db(core_role.add_role, new_role, locked=False)
            self.roles.append(new_role)
            # active since a while, so that the role holds whatever the clock does during the test
            dates.setdefault('activates_at', datetime.utcnow() - timedelta(hours=1))
            _db(core_role.add_account_role, self.accounts[account], new_role, **dates)
            role = new_role
        _db(core_role.add_role_permission, role, RolePermissionType.DID, {'did_pattern': did_pattern.replace('S', self.scope, 1) if did_pattern.startswith('S') else did_pattern,
                                                                       'operations': [LETTERS[letter] for letter in operations]})
        return role


@pytest.fixture
def make_world(vo, random_account_factory, rse_cleaner, scope_cleaner, role_cleaner):
    """
    Build an empty world: a scope owned by root, named 'rbac_*', the accounts given, the RSEs given (by suffix, e.g.
    'X_USERDISK'), with large account limits for the accounts on them.
    """

    def _make(accounts=('alice', 'bob', 'carol'), rses=('X_USERDISK', 'Y_USERDISK', 'Z_USERDISK', 'X_DATADISK'), scope: Optional[str] = None) -> World:
        prefix = generate_uuid()[:10]
        world = World(vo=vo, scope=scope or 'rbac_%s' % prefix, prefix=prefix, roles=role_cleaner)
        _db(core_scope.add_scope, world.internal_scope, InternalAccount('root', vo=vo))
        scope_cleaner(world.internal_scope)
        for name in accounts:
            world.accounts[name] = random_account_factory()
        for short in rses:
            rse = 'RBAC%s_%s' % (prefix.upper(), short)
            rse_id = core_rse.add_rse(rse, vo=vo)
            rse_cleaner(rse_id)
            core_rse.add_protocol(rse_id, {'scheme': 'mock', 'hostname': 'localhost', 'port': 0, 'prefix': '/rbac/', 'impl': 'rucio.rse.protocols.mock.Default',
                                           'domains': {'wan': {'read': 1, 'write': 1, 'delete': 1, 'third_party_copy_read': 1, 'third_party_copy_write': 1},
                                                       'lan': {'read': 1, 'write': 1, 'delete': 1}}})
            world.rses[short] = rse
            for account in world.accounts.values():
                _db(core_account_limit.set_local_account_limit, account, rse_id, 10**12)
        return world

    return _make


def _rse_id(world: World, short: str) -> str:
    return core_rse.get_rse_id(world.rse(short), vo=world.vo)


def _replica(world: World, short: str, name: str, owner: str, state: ReplicaState = ReplicaState.AVAILABLE) -> None:
    account = InternalAccount(owner, vo=world.vo) if owner == 'root' else world.accounts[owner]
    core_replica.add_replicas(_rse_id(world, short), [dict(world.file(name), scope=world.internal_scope, state=state.value)], account)


def _dataset(world: World, name: str, owner: str, content: tuple[str, ...] = ()) -> None:
    account = InternalAccount(owner, vo=world.vo) if owner == 'root' else world.accounts[owner]
    core_did.add_did(world.internal_scope, name, DIDType.DATASET, account)
    if content:
        core_did.attach_dids(world.internal_scope, name, [{'scope': world.internal_scope, 'name': child} for child in content], InternalAccount('root', vo=world.vo))


def _rule(world: World, key: str, name: str, owner: str, short: str) -> None:
    account = InternalAccount(owner, vo=world.vo) if owner == 'root' else world.accounts[owner]
    world.rules[key] = core_rule.add_rule([{'scope': world.internal_scope, 'name': name}], account, copies=1, rse_expression=world.rse(short), grouping='NONE',
                                          weight=None, lifetime=None, locked=False, subscription_id=None, ignore_account_limit=True)[0]


@pytest.fixture
def world(make_world) -> World:
    """
    The world of the examples of the DID permissions, in a scope 'S' owned by root:

    - alice: 'S:*' r; 'S:alice.*' rw; 'S:shared_ds' rw; 'S:file1' rd
    - bob: 'S:bob.*' w, stored rw (READ on his DIDs only)
    - carol: 'S:calib*' r
    - DIDs owned by root: file1, calib1, shared_ds (holding alice.f1), root_ds; by alice: alice.f1, alice.up, alice.ds
      (holding alice.f1); by bob: bob.f1, bob.ds; by carol: carol_file
    - replicas on X_USERDISK: file1 A (locked by root), alice.f1 A (alice), alice.up C (alice), bob.f1 C (bob),
      carol_file A (carol and root); on Y_USERDISK: file1 C (alice's copy), calib1 C (carol's copy)
    - rules: r_root_file1, r_alice_file1 (on Y), r_alice_f1, r_alice_up, r_bob, r_carol, r_root_carol, r_carol_calib1 (on Y)
    """
    world = make_world()
    alice = world.grant('alice', 'S:*', 'r')
    world.grant('alice', 'S:alice.*', 'rw', role=alice)
    world.grant('alice', 'S:shared_ds', 'rw', role=alice)
    world.grant('alice', 'S:file1', 'rd', role=alice)
    world.grant('bob', 'S:bob.*', 'w')
    world.grant('carol', 'S:calib*', 'r')

    _replica(world, 'X_USERDISK', 'file1', 'root')
    _replica(world, 'Y_USERDISK', 'file1', 'root', ReplicaState.COPYING)
    _replica(world, 'Y_USERDISK', 'calib1', 'root', ReplicaState.COPYING)
    _replica(world, 'X_USERDISK', 'alice.f1', 'alice')
    _replica(world, 'X_USERDISK', 'alice.up', 'alice', ReplicaState.COPYING)
    _replica(world, 'X_USERDISK', 'bob.f1', 'bob', ReplicaState.COPYING)
    _replica(world, 'X_USERDISK', 'carol_file', 'carol')
    _dataset(world, 'shared_ds', 'root', ('alice.f1',))
    _dataset(world, 'root_ds', 'root')
    _dataset(world, 'alice.ds', 'alice', ('alice.f1',))
    _dataset(world, 'bob.ds', 'bob')
    _rule(world, 'r_root_file1', 'file1', 'root', 'X_USERDISK')
    _rule(world, 'r_alice_file1', 'file1', 'alice', 'Y_USERDISK')
    _rule(world, 'r_alice_f1', 'alice.f1', 'alice', 'X_USERDISK')
    _rule(world, 'r_alice_up', 'alice.up', 'alice', 'X_USERDISK')
    _rule(world, 'r_bob', 'bob.f1', 'bob', 'X_USERDISK')
    _rule(world, 'r_carol', 'carol_file', 'carol', 'X_USERDISK')
    _rule(world, 'r_root_carol', 'carol_file', 'root', 'X_USERDISK')
    _rule(world, 'r_carol_calib1', 'calib1', 'carol', 'Y_USERDISK')
    return world


def _names(dids: Iterator[Any]) -> set[str]:
    """The names of the DIDs of a listing, which yields their names, or dictionaries with the long format."""
    return {did['name'] if isinstance(did, dict) else did for did in dids}


Expected = Union[bool, type[Exception]]


def _check(call: Callable[[], Any], expected: Expected) -> None:
    """
    Run a gateway call: True expects it to succeed, False to be refused by the permission policy (AccessDenied), and an
    exception class that the permission policy grants it but the core refuses it for another reason.
    """
    if expected is True:
        result = call()
        if isinstance(result, Iterator):
            list(result)
    elif expected is False:
        with pytest.raises(AccessDenied):
            result = call()
            if isinstance(result, Iterator):
                list(result)
    else:
        with pytest.raises(expected) as error:  # type: ignore[arg-type]
            result = call()
            if isinstance(result, Iterator):
                list(result)
        assert not isinstance(error.value, AccessDenied)


@dataclass(frozen=True)
class Case:
    description: str
    call: Callable[[World], Any]
    expected: Expected

    def __str__(self) -> str:
        return self.description


def _cases(*cases: Case):
    return pytest.mark.parametrize('case', [pytest.param(case, id=case.description) for case in cases])


# ----------------------------------------------------------------------------------------------
# DIDs: creating, attaching, detaching, metadata and status
# ----------------------------------------------------------------------------------------------

DID_CASES = (
    Case('alice creates a DID on a pattern granting rw',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, vo=w.vo), True),
    Case('alice cannot create a DID decided by a pattern granting r only',
         lambda w: gw_did.add_did(w.scope, 'other.new', 'DATASET', issuer=w.alice, vo=w.vo), False),
    Case('bob creates a DID on a pattern granting w',
         lambda w: gw_did.add_did(w.scope, 'bob.new', 'DATASET', issuer=w.bob, vo=w.vo), True),
    Case('carol cannot create a DID with r only',
         lambda w: gw_did.add_did(w.scope, 'calib2', 'DATASET', issuer=w.carol, vo=w.vo), False),
    Case('alice cannot create a DID owned by another account',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, account=w.bob, vo=w.vo), False),
    Case('alice cannot create a DID owned by another account through add_dids',
         lambda w: gw_did.add_dids([{'scope': w.scope, 'name': 'alice.new', 'type': 'DATASET', 'account': w.bob}], issuer=w.alice, vo=w.vo), False),
    Case('the scope owner creates a DID owned by another account',
         lambda w: gw_did.add_did(w.scope, 'bob.root', 'DATASET', issuer='root', account=w.bob, vo=w.vo), True),
    Case('alice creates a DID with an ordinary metadata key',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, meta={'project': 'rbac'}, vo=w.vo), True),
    Case('alice cannot create a DID with a reserved metadata key, which would rename it out of her pattern',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, meta={'name': 'other.new'}, vo=w.vo), False),
    Case('alice creates a DID with a lifetime: she will own it, with WRITE on it',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, lifetime=3600, vo=w.vo), True),
    Case('bob creates a DID with a lifetime: he will own it, with WRITE on it',
         lambda w: gw_did.add_did(w.scope, 'bob.new', 'DATASET', issuer=w.bob, lifetime=3600, vo=w.vo), True),
    Case('bob creates a DID with a lifetime in its metadata',
         lambda w: gw_did.add_did(w.scope, 'bob.new', 'DATASET', issuer=w.bob, meta={'lifetime': 3600}, vo=w.vo), True),
    Case('bob creates a DID with a lifetime through add_dids',
         lambda w: gw_did.add_dids([{'scope': w.scope, 'name': 'bob.new', 'type': 'DATASET', 'lifetime': 3600}], issuer=w.bob, vo=w.vo), True),
    Case('alice creates a DID with a rule of her own',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, vo=w.vo,
                                  rules=[{'account': w.alice, 'copies': 1, 'rse_expression': w.rse('X_USERDISK')}]), True),
    Case('bob creates a DID with a rule of his own: he will own it, with WRITE on it',
         lambda w: gw_did.add_did(w.scope, 'bob.new', 'DATASET', issuer=w.bob, vo=w.vo,
                                  rules=[{'account': w.bob, 'copies': 1, 'rse_expression': w.rse('X_USERDISK')}]), True),
    Case('alice cannot create a DID with a rule of another account',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, vo=w.vo,
                                  rules=[{'account': w.bob, 'copies': 1, 'rse_expression': w.rse('X_USERDISK')}]), False),
    Case('alice creates a dataset with a content she reads',
         lambda w: gw_did.add_dids([{'scope': w.scope, 'name': 'alice.new', 'type': 'DATASET', 'dids': [w.did('file1')]}], issuer=w.alice, vo=w.vo), True),
    Case('alice creates a dataset with a content she reads through add_did',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, dids=[w.did('file1')], vo=w.vo), True),
    Case('bob cannot create a dataset with a content he does not read',
         lambda w: gw_did.add_dids([{'scope': w.scope, 'name': 'bob.new', 'type': 'DATASET', 'dids': [w.did('file1')]}], issuer=w.bob, vo=w.vo), False),
    Case('bob cannot create a dataset with a content he does not read through add_did',
         lambda w: gw_did.add_did(w.scope, 'bob.new', 'DATASET', issuer=w.bob, dids=[w.did('file1')], vo=w.vo), False),
    Case('alice creates a dataset registering a new file she may create through add_did',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, dids=[w.file('alice.nf')], rse=w.rse('X_USERDISK'), vo=w.vo), True),
    Case('alice cannot create a dataset registering a new file she may not create through add_did',
         lambda w: gw_did.add_did(w.scope, 'alice.new', 'DATASET', issuer=w.alice, dids=[w.file('zz')], rse=w.rse('X_USERDISK'), vo=w.vo), False),
    Case('carol cannot create a dataset, even with a content she reads',
         lambda w: gw_did.add_dids([{'scope': w.scope, 'name': 'calib.new', 'type': 'DATASET', 'dids': [w.did('calib1')]}], issuer=w.carol, vo=w.vo), False),
    Case('alice attaches a file she reads into a dataset of root she may write into',
         lambda w: gw_did.attach_dids(w.scope, 'shared_ds', {'dids': [w.did('file1')]}, issuer=w.alice, vo=w.vo), True),
    Case('alice cannot attach into a dataset she may not write into',
         lambda w: gw_did.attach_dids(w.scope, 'root_ds', {'dids': [w.did('file1')]}, issuer=w.alice, vo=w.vo), False),
    Case('alice attaches into her own dataset',
         lambda w: gw_did.attach_dids(w.scope, 'alice.ds', {'dids': [w.did('file1')]}, issuer=w.alice, vo=w.vo), True),
    Case('alice attaches and registers a new file she may create',
         lambda w: gw_did.attach_dids(w.scope, 'alice.ds', {'rse': w.rse('X_USERDISK'), 'dids': [w.file('alice.nf')]}, issuer=w.alice, vo=w.vo), True),
    Case('alice cannot attach and register a new file she may not create',
         lambda w: gw_did.attach_dids(w.scope, 'alice.ds', {'rse': w.rse('X_USERDISK'), 'dids': [w.file('zz')]}, issuer=w.alice, vo=w.vo), False),
    Case('bob attaches his file into his dataset, owning both with WRITE on them',
         lambda w: gw_did.attach_dids(w.scope, 'bob.ds', {'dids': [w.did('bob.f1')]}, issuer=w.bob, vo=w.vo), True),
    Case('bob cannot attach a file he does not read into his dataset',
         lambda w: gw_did.attach_dids(w.scope, 'bob.ds', {'dids': [w.did('file1')]}, issuer=w.bob, vo=w.vo), False),
    Case('attach_dids_to_dids checks each attachment',
         lambda w: gw_did.attach_dids_to_dids([{'scope': w.scope, 'name': 'alice.ds', 'dids': [w.did('file1')]},
                                               {'scope': w.scope, 'name': 'root_ds', 'dids': [w.did('file1')]}], issuer=w.alice, vo=w.vo), False),
    Case('alice detaches her file from a dataset she may write into',
         lambda w: gw_did.detach_dids(w.scope, 'shared_ds', [w.did('alice.f1')], issuer=w.alice, vo=w.vo), True),
    Case('alice cannot detach a file of root with WRITE only on the dataset',
         lambda w: gw_did.detach_dids(w.scope, 'shared_ds', [w.did('file1')], issuer=w.alice, vo=w.vo), False),
    Case('alice cannot detach her file and a file of root at once',
         lambda w: gw_did.detach_dids(w.scope, 'shared_ds', [w.did('alice.f1'), w.did('file1')], issuer=w.alice, vo=w.vo), False),
    Case('alice detaches from her own dataset',
         lambda w: gw_did.detach_dids(w.scope, 'alice.ds', [w.did('alice.f1')], issuer=w.alice, vo=w.vo), True),
    Case('alice may detach from file1 (rd), the core refusing it as a file has no content',
         lambda w: gw_did.detach_dids(w.scope, 'file1', [w.did('alice.f1')], issuer=w.alice, vo=w.vo), RucioException),
    Case('alice sets a metadata key on her own file',
         lambda w: gw_did.set_metadata(w.scope, 'alice.f1', 'project', 'rbac', issuer=w.alice, vo=w.vo), True),
    Case('alice cannot set a metadata key on a dataset of root without DELETE',
         lambda w: gw_did.set_metadata(w.scope, 'root_ds', 'project', 'rbac', issuer=w.alice, vo=w.vo), False),
    Case('alice sets a metadata key on file1, with DELETE on it',
         lambda w: gw_did.set_metadata(w.scope, 'file1', 'project', 'rbac', issuer=w.alice, vo=w.vo), True),
    Case('alice sets the lifetime of her own file',
         lambda w: gw_did.set_metadata(w.scope, 'alice.f1', 'lifetime', 3600, issuer=w.alice, vo=w.vo), True),
    Case('alice cannot set a reserved key, even on her own file',
         lambda w: gw_did.set_metadata(w.scope, 'alice.f1', 'bytes', 2, issuer=w.alice, vo=w.vo), False),
    Case('alice cannot set metadata recursively, even on her own dataset',
         lambda w: gw_did.set_metadata(w.scope, 'alice.ds', 'project', 'rbac', issuer=w.alice, recursive=True, vo=w.vo), False),
    Case('alice cannot set metadata in bulk recursively',
         lambda w: gw_did.set_metadata_bulk(w.scope, 'alice.ds', {'project': 'rbac'}, issuer=w.alice, recursive=True, vo=w.vo), False),
    Case('the scope owner sets metadata recursively',
         lambda w: gw_did.set_metadata(w.scope, 'alice.ds', 'project', 'rbac', issuer='root', recursive=True, vo=w.vo), True),
    Case('bob sets metadata on his own file, with WRITE on it',
         lambda w: gw_did.set_metadata(w.scope, 'bob.f1', 'project', 'rbac', issuer=w.bob, vo=w.vo), True),
    Case('carol cannot set metadata on her own file, without WRITE on it',
         lambda w: gw_did.set_metadata(w.scope, 'carol_file', 'project', 'rbac', issuer=w.carol, vo=w.vo), False),
    Case('alice cannot delete a metadata key of a dataset of root without DELETE',
         lambda w: gw_did.delete_metadata(w.alice, w.scope, 'root_ds', 'project', vo=w.vo), False),
    Case('alice cannot close her own dataset',
         lambda w: gw_did.set_status(w.scope, 'alice.ds', issuer=w.alice, vo=w.vo, open=False), False),
    Case('the scope owner closes a dataset of alice',
         lambda w: gw_did.set_status(w.scope, 'alice.ds', issuer='root', vo=w.vo, open=False), True),
    Case('alice creates a sample of a collection she reads into a DID she may create',
         lambda w: gw_did.create_did_sample(w.scope, 'shared_ds', w.scope, 'alice.sample', issuer=w.alice, nbfiles=1, vo=w.vo), True),
    Case('alice cannot create a sample into a DID she may not create',
         lambda w: gw_did.create_did_sample(w.scope, 'shared_ds', w.scope, 'other.sample', issuer=w.alice, nbfiles=1, vo=w.vo), False),
    Case('carol cannot create a sample of a collection she does not read',
         lambda w: (w.grant('carol', 'S:calib.*', 'w'), gw_did.create_did_sample(w.scope, 'shared_ds', w.scope, 'calib.sample', issuer=w.carol, nbfiles=1, vo=w.vo)), False),
)


@_cases(*DID_CASES)
def test_did_actions(world, case):
    """ROLE DID PERMISSION (GATEWAY): What the DID permissions of roles grant on creating, attaching, detaching, the metadata and the status of DIDs."""
    _check(lambda: case.call(world), case.expected)


def test_owner_deletes_a_metadata_key_of_its_did(world):
    """ROLE DID PERMISSION (GATEWAY): The owner of a DID, with WRITE on it, deletes its metadata keys."""
    if not json_implemented():
        pytest.skip("JSON support is not implemented in this database")
    gw_did.set_metadata(world.scope, 'alice.f1', 'rbac_key', 'value', issuer='root', vo=world.vo)
    try:
        gw_did.delete_metadata(world.alice, world.scope, 'alice.f1', 'rbac_key', vo=world.vo)
    except AccessDenied:
        pytest.fail('the owner of the DID may delete its metadata keys')
    except RucioException:
        pass  # the metadata plugin of the instance may not support deleting a key


# ----------------------------------------------------------------------------------------------
# Reading
# ----------------------------------------------------------------------------------------------

READ_CASES = (
    Case('alice reads the metadata of file1', lambda w: gw_did.get_metadata(w.alice, w.scope, 'file1', vo=w.vo), True),
    Case('carol reads the metadata of a DID her name pattern matches', lambda w: gw_did.get_metadata(w.carol, w.scope, 'calib1', vo=w.vo), True),
    Case('carol cannot read the metadata of a DID no pattern of hers matches', lambda w: gw_did.get_metadata(w.carol, w.scope, 'file1', vo=w.vo), False),
    Case('carol cannot read her own DID without READ nor WRITE on it, even reading some DIDs of the scope',
         lambda w: gw_did.get_metadata(w.carol, w.scope, 'carol_file', vo=w.vo), False),
    Case('bob reads his own DID, WRITE on it including READ', lambda w: gw_did.get_metadata(w.bob, w.scope, 'bob.f1', vo=w.vo), True),
    Case('carol gets a DID her pattern matches', lambda w: gw_did.get_did(w.carol, w.scope, 'calib1', vo=w.vo), True),
    Case('carol cannot list the content of a dataset she does not read', lambda w: gw_did.list_content(w.carol, w.scope, 'shared_ds', vo=w.vo), False),
    Case('carol cannot list the files of a dataset she does not read', lambda w: gw_did.list_files(w.carol, w.scope, 'shared_ds', long=False, vo=w.vo), False),
    Case('carol cannot list the parents of a DID she does not read', lambda w: gw_did.list_parent_dids(w.carol, w.scope, 'file1', vo=w.vo), False),
    Case('bob lists the DIDs of a scope he reads some DIDs in, WRITE including READ', lambda w: gw_did.list_dids(w.bob, w.scope, [{'name': '*'}], 'all', vo=w.vo), True),
    Case('carol cannot list the replicas (data) of a DID she does not read', lambda w: gw_replica.list_replicas([w.did('file1')], issuer=w.carol, vo=w.vo), False),
    Case('carol lists the replicas of a DID she reads', lambda w: gw_replica.list_replicas([w.did('calib1')], issuer=w.carol, vo=w.vo), True),
    Case('carol cannot get the rules of a DID she does not read', lambda w: gw_rule.list_associated_replication_rules_for_file(w.carol, w.scope, 'file1', vo=w.vo), False),
    Case('carol cannot get a rule of a DID she does not read', lambda w: gw_rule.get_replication_rule(w.rules['r_root_file1'], issuer=w.carol, vo=w.vo), False),
    Case('carol gets her rule on a DID she reads', lambda w: gw_rule.get_replication_rule(w.rules['r_carol_calib1'], issuer=w.carol, vo=w.vo), True),
    Case('carol cannot get her rule on a DID she owns without READ nor WRITE on it',
         lambda w: gw_rule.get_replication_rule(w.rules['r_carol'], issuer=w.carol, vo=w.vo), False),
)


@_cases(*READ_CASES)
def test_reading(world, case):
    """ROLE DID PERMISSION (GATEWAY): Reading a DID takes READ on it, or owning it with WRITE on it."""
    _check(lambda: case.call(world), case.expected)


def test_listings_are_filtered_per_did(world):
    """ROLE DID PERMISSION (GATEWAY): A listing of a scope only shows the DIDs the account reads, its own ones included if it may write them."""
    listed = _names(gw_did.list_dids(world.carol, world.scope, [{'name': '*'}], 'all', vo=world.vo))
    assert listed == {'calib1'}
    world.grant('carol', 'S:carol_file', 'w')
    listed = _names(gw_did.list_dids(world.carol, world.scope, [{'name': '*'}], 'all', vo=world.vo))
    assert listed == {'calib1', 'carol_file'}

    listed = _names(gw_did.list_dids(world.alice, world.scope, [{'name': '*'}], 'all', vo=world.vo))
    assert listed == {'file1', 'calib1', 'shared_ds', 'root_ds', 'alice.f1', 'alice.up', 'alice.ds', 'bob.f1', 'bob.ds', 'carol_file'}

    # WRITE includes READ: bob lists his own DIDs, whatever other grants he holds
    listed = _names(gw_did.list_dids(world.bob, world.scope, [{'name': '*'}], 'all', vo=world.vo))
    assert listed == {'bob.f1', 'bob.ds'}

    # the content of a readable collection is filtered per child
    gw_did.attach_dids(world.scope, 'root_ds', {'dids': [world.did('calib1'), world.did('carol_file'), world.did('file1')]}, issuer='root', vo=world.vo)
    world.grant('carol', 'S:root_ds', 'r')
    assert {did['name'] for did in gw_did.list_content(world.carol, world.scope, 'root_ds', vo=world.vo)} == {'calib1', 'carol_file'}
    assert {did['name'] for did in gw_did.list_files(world.carol, world.scope, 'root_ds', long=False, vo=world.vo)} == {'calib1', 'carol_file'}

    # the rules listed are those of the readable DIDs
    rules = {rule['id'] for rule in gw_rule.list_replication_rules(world.carol, filters={'scope': world.scope}, vo=world.vo)}
    assert rules == {world.rules['r_carol'], world.rules['r_root_carol'], world.rules['r_carol_calib1']}


def test_scopes_are_listed_when_some_did_is_readable(world, make_world):
    """ROLE DID PERMISSION (GATEWAY): A scope is listed to an account reading some DIDs in it, even through a name pattern only."""
    other = make_world(accounts=(), rses=())
    assert world.scope in gw_scope.list_scopes(world.carol, vo=world.vo)
    assert other.scope not in gw_scope.list_scopes(world.carol, vo=world.vo)
    # bob writes into the scope, WRITE including READ
    assert world.scope in gw_scope.list_scopes(world.bob, vo=world.vo)


def test_root_and_admins_are_not_limited(world):
    """ROLE DID PERMISSION (GATEWAY): Root, the holders of the admin role and the accounts with the 'admin' attribute read and alter everything, as in standard Rucio."""
    gw_did.get_metadata('root', world.scope, 'bob.f1', vo=world.vo)
    with pytest.raises(AccessDenied):
        gw_did.get_metadata(world.bob, world.scope, 'file1', vo=world.vo)
    _db(core_role.add_account_role, world.accounts['bob'], ADMIN_ROLE, force=True)
    try:
        gw_did.get_metadata(world.bob, world.scope, 'file1', vo=world.vo)
        gw_did.set_metadata(world.scope, 'root_ds', 'project', 'rbac', issuer=world.bob, vo=world.vo)
        assert _names(gw_did.list_dids(world.bob, world.scope, [{'name': '*'}], 'all', vo=world.vo)) >= {'file1', 'calib1', 'root_ds'}
    finally:
        _db(core_role.delete_account_role, world.accounts['bob'], ADMIN_ROLE, force=True)

    # enabling RBAC demotes no admin: the 'admin' attribute keeps counting
    with pytest.raises(AccessDenied):
        gw_did.get_metadata(world.carol, world.scope, 'file1', vo=world.vo)
    _db(core_account.add_account_attribute, world.accounts['carol'], 'admin', True)
    gw_did.get_metadata(world.carol, world.scope, 'file1', vo=world.vo)
    gw_rule.delete_replication_rule(world.rules['r_root_file1'], purge_replicas=False, issuer=world.carol, vo=world.vo)


@pytest.mark.parametrize('rbac', [False], indirect=True)
def test_rbac_disabled_grants_as_standard_rucio(world, rbac):
    """ROLE DID PERMISSION (GATEWAY): Without RBAC, the roles are ignored and every account reads every DID, as in standard Rucio."""
    gw_did.get_metadata(world.bob, world.scope, 'file1', vo=world.vo)
    assert _names(gw_did.list_dids(world.bob, world.scope, [{'name': '*'}], 'all', vo=world.vo)) >= {'file1', 'calib1'}
    with pytest.raises(AccessDenied):
        gw_did.set_metadata(world.scope, 'root_ds', 'project', 'rbac', issuer=world.alice, vo=world.vo)
    # deleting a metadata key is not checked in standard Rucio
    try:
        gw_did.delete_metadata(world.alice, world.scope, 'root_ds', 'project', vo=world.vo)
    except AccessDenied:
        pytest.fail('without RBAC, every account may delete a metadata key, as in standard Rucio')
    except (RucioException, NotImplementedError):
        pass  # the metadata plugin of the instance may not support deleting a key


def test_lifetime_exception_takes_reading_every_did(world):
    """ROLE DID PERMISSION (GATEWAY): Requesting a lifetime exception tells whether each DID exists, so it takes READ on every DID."""
    def request(*names: str) -> Any:
        return gw_lifetime_exception.add_exception([world.did(name) for name in names], world.carol, pattern='', comments='rbac', expires_at=None, vo=world.vo)

    # a DID she does not read is refused like one which does not exist
    _check(lambda: request('calib1', 'file1'), False)
    _check(lambda: request('nothing_here'), False)
    try:
        # calib1 has no end of life, so no exception is recorded for it
        assert request('calib1')['not_affected'] == [{'scope': world.scope, 'name': 'calib1', 'did_type': 'FILE'}]
    except AccessDenied:
        pytest.fail('carol reads calib1, so she may request a lifetime exception for it')
    except UnsupportedOperation:
        pass  # the instance may not configure the lifetime model


# ----------------------------------------------------------------------------------------------
# Rules
# ----------------------------------------------------------------------------------------------

def _add_rule(w: World, issuer: str, name: str, account: Optional[str] = None, locked: bool = False, rse: str = 'Z_USERDISK'):
    return gw_rule.add_replication_rule([w.did(name)], copies=1, rse_expression=w.rse(rse), weight=None, lifetime=None, grouping='NONE',
                                        account=account or issuer, locked=locked, subscription_id=None, source_replica_expression=None, activity=None,
                                        notify=None, purge_replicas=False, ignore_availability=False, comment=None, ask_approval=False, asynchronous=False,
                                        delay_injection=None, priority=3, split_container=False, meta=None, issuer=issuer, vo=w.vo)


RULE_CASES = (
    Case('alice adds a rule on a DID she reads', lambda w: _add_rule(w, w.alice, 'file1'), True),
    Case('carol cannot add a rule on a DID she does not read', lambda w: _add_rule(w, w.carol, 'file1'), False),
    Case('carol adds a rule on a DID she reads', lambda w: _add_rule(w, w.carol, 'calib1'), True),
    Case('bob adds a rule on his own DID, with WRITE on it', lambda w: _add_rule(w, w.bob, 'bob.f1'), True),
    Case('carol cannot add a rule on her own DID without READ nor WRITE on it', lambda w: _add_rule(w, w.carol, 'carol_file'), False),
    Case('alice cannot add a locked rule', lambda w: _add_rule(w, w.alice, 'file1', locked=True), False),
    Case('alice cannot add a rule for another account', lambda w: _add_rule(w, w.alice, 'file1', account=w.bob), False),
    # altering a rule is left to root and admins, as in standard Rucio: no role grants it, nor owning the rule or its DID
    Case('alice cannot delete her rule', lambda w: gw_rule.delete_replication_rule(w.rules['r_alice_f1'], purge_replicas=False, issuer=w.alice, vo=w.vo), False),
    Case('alice cannot delete a rule of root on a DID she has DELETE on',
         lambda w: gw_rule.delete_replication_rule(w.rules['r_root_file1'], purge_replicas=False, issuer=w.alice, vo=w.vo), False),
    Case('alice cannot update the comment of her rule',
         lambda w: gw_rule.update_replication_rule(w.rules['r_alice_f1'], {'comment': 'rbac'}, issuer=w.alice, vo=w.vo), False),
    Case('alice cannot reduce her rule',
         lambda w: gw_rule.reduce_replication_rule(w.rules['r_alice_f1'], copies=1, exclude_expression=None, issuer=w.alice, vo=w.vo), False),
    Case('alice cannot move her rule',
         lambda w: gw_rule.move_replication_rule(w.rules['r_alice_f1'], w.rse('Z_USERDISK'), override={}, issuer=w.alice, vo=w.vo), False),
    Case('root deletes a rule of alice', lambda w: gw_rule.delete_replication_rule(w.rules['r_alice_f1'], purge_replicas=False, issuer='root', vo=w.vo), True),
)


@_cases(*RULE_CASES)
def test_rules(world, case):
    """ROLE DID PERMISSION (GATEWAY): Adding a rule takes READ on its DID, or owning it with WRITE on it; altering one is left to root and admins."""
    _check(lambda: case.call(world), case.expected)


def test_examining_a_rule_only_names_the_readable_files(world):
    """ROLE DID PERMISSION (GATEWAY): Examining a rule on a readable collection names only the stuck files of its content the account reads."""
    gw_did.attach_dids(world.scope, 'root_ds', {'dids': [world.did('calib1'), world.did('file1')]}, issuer='root', vo=world.vo)
    world.grant('carol', 'S:root_ds', 'r')
    _rule(world, 'r_root_ds', 'root_ds', 'root', 'Z_USERDISK')
    rule_id = world.rules['r_root_ds']
    # only a stuck rule lists its transfers, those of its stuck locks
    with db_session(DatabaseOperationType.WRITE) as session:
        session.execute(update(models.ReplicationRule).where(models.ReplicationRule.id == rule_id).values(state=RuleState.STUCK))
        session.execute(update(models.ReplicaLock).where(models.ReplicaLock.rule_id == rule_id).values(state=LockState.STUCK))

    def stuck_files(issuer: str) -> set[str]:
        return {transfer['name'] for transfer in gw_rule.examine_replication_rule(rule_id, issuer=issuer, vo=world.vo)['transfers']}

    assert stuck_files('root') == {'calib1', 'file1'}
    assert stuck_files(world.carol) == {'calib1'}


def test_dataset_locks_of_a_container_only_name_the_readable_datasets(world):
    """ROLE DID PERMISSION (GATEWAY): The dataset locks of a readable container are only those of the datasets in it the account reads."""
    root = InternalAccount('root', vo=world.vo)
    _dataset(world, 'calib.ds', 'root', ('calib1',))
    gw_did.attach_dids(world.scope, 'root_ds', {'dids': [world.did('file1')]}, issuer='root', vo=world.vo)
    core_did.add_did(world.internal_scope, 'root_cont', DIDType.CONTAINER, root)
    core_did.attach_dids(world.internal_scope, 'root_cont', [{'scope': world.internal_scope, 'name': name} for name in ('calib.ds', 'root_ds')], root)
    # grouped by dataset, the rule locks each dataset of the container
    core_rule.add_rule([{'scope': world.internal_scope, 'name': 'root_cont'}], root, copies=1, rse_expression=world.rse('Z_USERDISK'), grouping='DATASET',
                       weight=None, lifetime=None, locked=False, subscription_id=None, ignore_account_limit=True)
    world.grant('carol', 'S:root_cont', 'r')

    def locked_datasets(issuer: str) -> set[str]:
        return {lock['name'] for lock in gw_lock.get_dataset_locks_bulk(issuer, [world.did('root_cont')], vo=world.vo)}

    assert locked_datasets('root') == {'calib.ds', 'root_ds'}
    assert locked_datasets(world.carol) == {'calib.ds'}


# ----------------------------------------------------------------------------------------------
# Replicas
# ----------------------------------------------------------------------------------------------

def _states(w: World, issuer: str, short: str, name: str, state: str, **extra):
    return gw_replica.update_replicas_states(w.rse(short), [dict(w.did(name), state=state, **extra)], issuer=issuer, vo=w.vo)


REPLICA_CASES = (
    Case('alice registers a replica of a new file she may create',
         lambda w: gw_replica.add_replicas(w.rse('X_USERDISK'), [w.file('alice.n')], issuer=w.alice, vo=w.vo), True),
    Case('alice cannot register a replica of a new file she may not create',
         lambda w: gw_replica.add_replicas(w.rse('X_USERDISK'), [w.file('other.n')], issuer=w.alice, vo=w.vo), False),
    Case('alice registers a copy of a file she reads',
         lambda w: gw_replica.add_replicas(w.rse('Z_USERDISK'), [w.file('file1')], issuer=w.alice, vo=w.vo), True),
    Case('carol cannot register a copy of a file she does not read',
         lambda w: gw_replica.add_replicas(w.rse('Z_USERDISK'), [w.file('file1')], issuer=w.carol, vo=w.vo), False),
    Case('alice cannot register a replica on an RSE which is not a user RSE',
         lambda w: gw_replica.add_replicas(w.rse('X_DATADISK'), [w.file('alice.n')], issuer=w.alice, vo=w.vo), False),
    # changing the states of replicas is left to root and admins, and deleting them through the API to nobody, as in standard Rucio
    Case('alice cannot finish her upload', lambda w: _states(w, w.alice, 'X_USERDISK', 'alice.up', 'A'), False),
    Case('alice cannot change the state of her replica held by her own rule only', lambda w: _states(w, w.alice, 'X_USERDISK', 'alice.f1', 'U'), False),
    Case('alice cannot change the state of a replica of a file she has DELETE on', lambda w: _states(w, w.alice, 'Y_USERDISK', 'file1', 'A'), False),
    Case('root finishes the upload of alice', lambda w: _states(w, 'root', 'X_USERDISK', 'alice.up', 'A'), True),
    Case('alice cannot delete her replica', lambda w: gw_replica.delete_replicas(w.rse('X_USERDISK'), [w.did('alice.f1')], issuer=w.alice, vo=w.vo), False),
    Case('alice cannot delete her copy of a file she has DELETE on',
         lambda w: gw_replica.delete_replicas(w.rse('Y_USERDISK'), [w.did('file1')], issuer=w.alice, vo=w.vo), False),
)


@_cases(*REPLICA_CASES)
def test_replicas(world, case):
    """ROLE DID PERMISSION (GATEWAY): Replicas are registered on user RSEs only, by reading or creating their files; altering and deleting them is left to root and admins."""
    _check(lambda: case.call(world), case.expected)


def test_declaring_suspicious_replicas_takes_reading_their_data(world):
    """ROLE DID PERMISSION (GATEWAY): Declaring a replica suspicious acts on it and tells whether it exists, so it takes READ on the data of its DID."""
    def pfn(name: str, short: str) -> str:
        replicas = gw_replica.list_replicas([world.did(name)], schemes=['mock'], all_states=True, issuer='root', vo=world.vo)
        return next(rep['rses'][world.rse(short)][0] for rep in replicas)

    def declare(*pfns: str) -> Any:
        return gw_replica.declare_suspicious_file_replicas(list(pfns), reason='rbac', issuer=world.carol, vo=world.vo)

    readable, hidden = pfn('calib1', 'Y_USERDISK'), pfn('file1', 'X_USERDISK')
    try:
        _check(lambda: declare(readable, hidden), False)
        # a PFN of a DID which does not exist is refused like one of a hidden DID
        _check(lambda: declare(hidden.replace('file1', 'nothing_here')), False)
        assert declare(readable) == {}
    finally:
        # the declarations are not removed with the scope of the world
        with db_session(DatabaseOperationType.WRITE) as session:
            session.execute(delete(models.BadReplica).where(models.BadReplica.scope == world.internal_scope))


# ----------------------------------------------------------------------------------------------
# The most specific pattern, within a role
# ----------------------------------------------------------------------------------------------

def _access(w: World, account: str, name: Optional[str], scope: Optional[str] = None) -> str:
    """The operations ('rwd', '-' where not granted) the roles of an account grant on a DID, or on the whole scope without name."""
    scope_ = InternalScope(scope or w.scope, vo=w.vo)
    letters = ''
    for letter, operation in LETTERS.items():
        letters += letter if _db(core_role.has_did_permission, w.accounts[account], scope_, name, operation) else '-'
    return letters


@pytest.fixture
def bare_world(make_world) -> World:
    """A world with alice only, and the DIDs file1, file2, calib1, secret1, raw1 and ds1 owned by root, mine owned by alice."""
    world = make_world(accounts=('alice',), rses=('X_USERDISK',))
    for name in ('file1', 'file2', 'calib1', 'secret1', 'raw1'):
        _replica(world, 'X_USERDISK', name, 'root')
    _replica(world, 'X_USERDISK', 'mine', 'alice')
    _dataset(world, 'ds1', 'root')
    return world


@pytest.mark.parametrize(('grants', 'expected'), [
    ([('S:*', 'r'), ('S:file*', 'r')], {'file1': 'r--', 'calib1': 'r--'}),
    ([('S*:*', 'r'), ('S:*', 'rw')], {'file1': 'rw-', 'calib1': 'rw-'}),
    ([('S:*', 'rw'), ('S:file*', 'r')], {'file1': 'r--', 'calib1': 'rw-'}),
    ([('S:*', 'r'), ('S:file*', 'w')], {'file1': 'rw-', 'calib1': 'r--'}),
    ([('S:file1', 'r'), ('S:*', 'd')], {'file1': 'r--', 'calib1': 'rwd'}),
    ([('S:fi*', 'd'), ('S:file*', 'r')], {'file1': 'r--', 'calib1': '---'}),
    ([('S:*', 'rwd'), ('S:file*', '')], {'file1': '---', 'calib1': 'rwd'}),
    ([('S:file*', 'w')], {'file1': 'rw-', 'calib1': '---'}),
    ([('S:*', 'rwd'), ('S:raw*', 'r')], {'raw1': 'r--', 'file1': 'rwd'}),
    ([('S:*', 'rwd'), ('S:secret*', '')], {'secret1': '---', 'file1': 'rwd'}),
    # the order the rows are added in does not matter
    ([('S:file*', 'r'), ('S:*', 'rw')], {'file1': 'r--', 'calib1': 'rw-'}),
], ids=lambda value: str(value))
def test_most_specific_pattern_decides_within_a_role(bare_world, grants, expected):
    """ROLE DID PERMISSION (CORE): Within a role, the most specific pattern matching a DID gives every operation of the role on it."""
    role = None
    for did_pattern, operations in grants:
        role = bare_world.grant('alice', did_pattern, operations, role=role)
    assert {name: _access(bare_world, 'alice', name) for name in expected} == expected


@pytest.mark.parametrize(('grants', 'expected'), [
    ([[('S:file1', 'r')], [('S:file1', 'w')]], 'rw-'),
    ([[('S:*', 'r')], [('S:file1', 'd')]], 'rwd'),
    ([[('S:*', 'r')], [('S:*', 'r')]], 'r--'),
    ([[('S:*', 'rwd')], [('S:*', '')]], 'rwd'),
    ([[('S:*', 'r'), ('S:file*', '')], [('S:file1', 'w')]], 'rw-'),
], ids=lambda value: str(value))
def test_roles_add_up(bare_world, grants, expected):
    """ROLE DID PERMISSION (CORE): Across the roles of an account the operations add up: a role granting nothing never withdraws what another grants."""
    for role_grants in grants:
        role = None
        for did_pattern, operations in role_grants:
            role = bare_world.grant('alice', did_pattern, operations, role=role)
    assert _access(bare_world, 'alice', 'file1') == expected


def test_inactive_assignments_grant_nothing(bare_world):
    """ROLE DID PERMISSION (CORE): A role whose assignment has expired, or is not active yet, grants nothing, ownership included."""
    now = datetime.utcnow()
    bare_world.grant('alice', 'S:*', 'rw', activates_at=now - timedelta(days=2), expires_at=now - timedelta(days=1))
    bare_world.grant('alice', 'S:file*', 'w')
    assert _access(bare_world, 'alice', 'file1') == 'rw-'
    with pytest.raises(AccessDenied):
        gw_did.get_metadata(bare_world.alice, bare_world.scope, 'mine', vo=bare_world.vo)

    bare_world.grant('alice', 'S:file1', 'd', activates_at=now + timedelta(days=1))
    assert _access(bare_world, 'alice', 'file1') == 'rw-'


def test_whole_scope_and_scope_prefix(bare_world, make_world):
    """ROLE DID PERMISSION (CORE): The whole scope beats a scope prefix, and only patterns with the '*' name part grant the whole scope."""
    other = make_world(accounts=(), rses=(), scope=bare_world.scope + '2')
    role = bare_world.grant('alice', 'S*:*', 'r')
    bare_world.grant('alice', 'S:*', '', role=role)
    assert _access(bare_world, 'alice', 'file1') == '---'
    assert _access(bare_world, 'alice', 'file1', scope=other.scope) == 'r--'
    assert not _db(core_role.has_any_scope_prefix_access, account=bare_world.accounts['alice'], scope=bare_world.internal_scope, operation=DidOperationType.READ)


def test_name_pattern_withdrawing_the_whole_scope(bare_world):
    """ROLE DID PERMISSION (GATEWAY): READ on a scope but none on some names lists the other DIDs, and refuses the items standing for the whole scope."""
    role = bare_world.grant('alice', 'S:*', 'r')
    bare_world.grant('alice', 'S:secret*', '', role=role)
    listed = _names(gw_did.list_dids(bare_world.alice, bare_world.scope, [{'name': '*'}], 'all', vo=bare_world.vo))
    assert listed == {'file1', 'file2', 'calib1', 'raw1', 'ds1', 'mine'}
    with pytest.raises(AccessDenied):
        gw_did.get_metadata(bare_world.alice, bare_world.scope, 'secret1', vo=bare_world.vo)
    with db_session(DatabaseOperationType.READ) as session:
        assert not core_permission.scope_filter(bare_world.accounts['alice'], 'list_scopes', session=session)(bare_world.internal_scope)
        assert core_permission.scope_filter(bare_world.accounts['alice'], 'list_scopes', session=session, any_did=True)(bare_world.internal_scope)


def test_no_inheritance(bare_world):
    """ROLE DID PERMISSION (GATEWAY): A pattern matches the DID itself, not its content: READ on a dataset does not read the files in it."""
    gw_did.attach_dids(bare_world.scope, 'ds1', {'dids': [bare_world.did('file1')]}, issuer='root', vo=bare_world.vo)
    bare_world.grant('alice', 'S:ds1', 'r')
    gw_did.get_metadata(bare_world.alice, bare_world.scope, 'ds1', vo=bare_world.vo)
    assert list(gw_did.list_content(bare_world.alice, bare_world.scope, 'ds1', vo=bare_world.vo)) == []
    with pytest.raises(AccessDenied):
        gw_did.get_metadata(bare_world.alice, bare_world.scope, 'file1', vo=bare_world.vo)


@pytest.mark.parametrize(('grants', 'administers'), [
    ([('S:mine', 'w')], True),
    ([('S:*', 'w')], True),
    ([('S:calib*', 'r')], False),
    ([('S:file*', 'w')], False),
    ([('S:*', 'w'), ('S:mine', '')], False),
], ids=['WRITE on the DID', 'WRITE on its scope', 'READ elsewhere in the scope', 'WRITE elsewhere in the scope', 'a pattern withdrawing WRITE from the DID'])
def test_ownership(bare_world, grants, administers):
    """ROLE DID PERMISSION (GATEWAY): The owner of a DID deletes it, and so sets its metadata, only while a role gives it WRITE on that DID, as its deciding pattern grants it."""
    role = None
    for did_pattern, operations in grants:
        role = bare_world.grant('alice', did_pattern, operations, role=role)
    _check(lambda: gw_did.get_metadata(bare_world.alice, bare_world.scope, 'mine', vo=bare_world.vo), administers)
    _check(lambda: gw_did.set_metadata(bare_world.scope, 'mine', 'project', 'rbac', issuer=bare_world.alice, vo=bare_world.vo), administers)


def test_operations_include_the_lower_ones(bare_world):
    """ROLE DID PERMISSION (GATEWAY): DELETE includes WRITE and READ, and WRITE includes READ: no role writes into or alters DIDs it does not see."""
    role = bare_world.grant('alice', 'S:file1', 'd')
    bare_world.grant('alice', 'S:ds1', 'w', role=role)
    assert _access(bare_world, 'alice', 'file1') == 'rwd'
    assert _access(bare_world, 'alice', 'ds1') == 'rw-'
    # DELETE alters the DID, and sees it
    gw_did.set_metadata(bare_world.scope, 'file1', 'project', 'rbac', issuer=bare_world.alice, vo=bare_world.vo)
    gw_did.get_metadata(bare_world.alice, bare_world.scope, 'file1', vo=bare_world.vo)
    # WRITE on a collection lets it be read and written into, not altered
    gw_did.get_metadata(bare_world.alice, bare_world.scope, 'ds1', vo=bare_world.vo)
    with pytest.raises(AccessDenied):
        gw_did.set_metadata(bare_world.scope, 'ds1', 'project', 'rbac', issuer=bare_world.alice, vo=bare_world.vo)
    gw_did.attach_dids(bare_world.scope, 'ds1', {'dids': [bare_world.did('file1')]}, issuer=bare_world.alice, vo=bare_world.vo)
    assert _names(gw_did.list_content(bare_world.alice, bare_world.scope, 'ds1', vo=bare_world.vo)) == {'file1'}
    assert _names(gw_did.list_dids(bare_world.alice, bare_world.scope, [{'name': '*'}], 'all', vo=bare_world.vo)) == {'file1', 'ds1'}


def test_unknown_did_is_not_revealed(bare_world):
    """ROLE DID PERMISSION (GATEWAY): Reading a DID which does not exist is refused like an unreadable one to an account reading nothing there, and reported missing otherwise."""
    with pytest.raises(AccessDenied):
        gw_did.get_metadata(bare_world.alice, bare_world.scope, 'missing', vo=bare_world.vo)
    bare_world.grant('alice', 'S:*', 'r')
    with pytest.raises(DataIdentifierNotFound):
        gw_did.get_metadata(bare_world.alice, bare_world.scope, 'missing', vo=bare_world.vo)


def test_attach_into_a_file_passes_the_policy_only(world):
    """ROLE DID PERMISSION (GATEWAY): Attaching into a file one may write into is granted by the policy, and refused by the core."""
    world.grant('carol', 'S:carol_file', 'w')
    with pytest.raises(UnsupportedOperation):
        gw_did.attach_dids(world.scope, 'carol_file', {'dids': [world.did('calib1')]}, issuer=world.carol, vo=world.vo)
