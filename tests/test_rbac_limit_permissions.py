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
End-to-end tests of the limit permissions of roles, through the gateway.

Each test builds its own world in the database (a scope owned by root, an account, roles, RSEs tagged by an
attribute of their own, and its usage on them), manages the limits as root, adds rules as the account, and
deletes it all afterwards. RBAC is enabled for the test only.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional

import pytest
from sqlalchemy import delete

from rucio.common.constants import ADMIN_ROLE, ROLE_QUOTA_NOCAP
from rucio.common.exception import AccessDenied, InputValidationError, InsufficientAccountLimit
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import account_limit as core_account_limit
from rucio.core import replica as core_replica
from rucio.core import role as core_role
from rucio.core import rse as core_rse
from rucio.core import scope as core_scope
from rucio.core.rse_expression_parser import REGION
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType, DidOperationType, RolePermissionType
from rucio.db.sqla.session import db_session
from rucio.gateway import role as gw_role
from rucio.gateway import rule as gw_rule
from rucio.tests.common_server import cleanup_db_deps

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

pytestmark = pytest.mark.usefixtures('generic_permission_policy')

GB = 10**9
NOCAP = ROLE_QUOTA_NOCAP


def _db(function: "Callable[..., Any]", *args, **kwargs) -> Any:
    """Call a core function in a database session of its own, committed once it returns."""
    with db_session(DatabaseOperationType.WRITE) as session:
        return function(*args, session=session, **kwargs)


@pytest.fixture
def rbac_enabled(monkeypatch):
    """Enable RBAC for the test only, without any filter disabled by the policy package of the instance."""
    monkeypatch.setattr(core_role, 'is_rbac_enabled', lambda: True)
    monkeypatch.setattr(core_role, 'is_filter_disabled', lambda account, filter_name, *, session: False)


@dataclass
class World:
    vo: str
    scope: str
    tag: str
    account: InternalAccount
    rses: dict[str, str] = field(default_factory=dict)
    rse_ids: dict[str, str] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)
    files: int = 0

    @property
    def alice(self) -> str:
        return self.account.external

    @property
    def tier1(self) -> str:
        """The RSE expression of the RSEs tagged tier=1: RSE1 and RSE2, and the RSEs tagged later."""
        return '%s=1' % self.tag

    def role(self, **dates) -> str:
        """A new role held by alice, see :meth:`add_rse`."""
        role = 'rbac-%s' % generate_uuid()[:12]
        gw_role.add_role(role, issuer='root', vo=self.vo)
        self.roles.append(role)
        # active since a while, so that the role holds whatever the clock does during the test
        dates.setdefault('activates_at', datetime.utcnow() - timedelta(hours=1))
        _db(core_role.add_account_role, self.account, role, **dates)
        return role

    def local(self, role: str, rse: str, bytes_: int) -> None:
        gw_role.add_role_permission(role, 'limit', {'rse_expression': self.rses.get(rse, rse), 'local': bytes_}, issuer='root', vo=self.vo)

    def global_(self, role: str, rse_expression: str, bytes_: int) -> None:
        gw_role.add_role_permission(role, 'limit', {'rse_expression': rse_expression, 'global': bytes_}, issuer='root', vo=self.vo)

    def add_rse(self, name: str, tier1: bool = True) -> str:
        """Add an RSE, tagged tier=1 (see :attr:`tier1`) unless told otherwise."""
        rse = 'RBAC%s_%s' % (self.tag.upper()[5:], name)
        rse_id = core_rse.add_rse(rse, vo=self.vo)
        self.rses[name], self.rse_ids[name] = rse, rse_id
        if tier1:
            core_rse.add_rse_attribute(rse_id, self.tag, 1)
            # the RSE expressions are cached: forget them, so that the expressions matching the tag match the new RSE
            REGION.invalidate()
        return rse_id

    def use(self, rse: str, bytes_: int) -> None:
        """Set what alice uses on an RSE, as the account usage computed by abacus."""
        with db_session(DatabaseOperationType.WRITE) as session:
            session.merge(models.AccountUsage(account=self.account, rse_id=self.rse_ids[rse], files=1, bytes=bytes_))

    def add_rule(self, rse: str, bytes_: int) -> str:
        """Add, as alice, a rule on a new file of `bytes_` on an RSE, and return its id."""
        self.files += 1
        name = 'file%d' % self.files
        # the file is registered through a replica on an RSE no limit covers, the rule then copying it
        core_replica.add_replicas(self.rse_ids['SOURCE'], [{'scope': InternalScope(self.scope, vo=self.vo), 'name': name, 'bytes': bytes_, 'adler32': '0cc737eb'}],
                                  InternalAccount('root', vo=self.vo))
        return gw_rule.add_replication_rule([{'scope': self.scope, 'name': name}], copies=1, rse_expression=self.rses.get(rse, rse), weight=None,
                                            lifetime=None, grouping='NONE', account=self.alice, locked=False, subscription_id=None,
                                            source_replica_expression=None, activity=None, notify=None, purge_replicas=False,
                                            ignore_availability=False, comment=None, ask_approval=False, asynchronous=False, delay_injection=None,
                                            priority=3, split_container=False, meta=None, issuer=self.alice, vo=self.vo)[0]

    def can_write(self, rse: str, bytes_: int) -> bool:
        try:
            self.add_rule(rse, bytes_)
        except InsufficientAccountLimit:
            return False
        return True

    def space_left(self, rse: str) -> Optional[float]:
        """
        The largest file alice may still place on an RSE by a rule, found by adding rules: infinity without cap, None if not
        even one byte fits. The RSE selector places a file if it is smaller than what a local limit leaves, and not larger
        than what a global limit leaves, as with the account limits: see :func:`_assert_space_left`.
        """
        if self.can_write(rse, 10**15):
            return float('inf')
        if not self.can_write(rse, 1):
            return None
        fits, too_large = 1, 10**15
        while too_large - fits > 1:
            middle = (fits + too_large) // 2
            if self.can_write(rse, middle):
                fits = middle
            else:
                too_large = middle
        return fits


def _assert_space_left(world: World, rse: str, expected: Optional[float]) -> None:
    """Check what an account may still write on an RSE, a file of exactly that size fitting for a global limit, not for a local one."""
    left = world.space_left(rse)
    if expected is None or expected == float('inf'):
        assert left == expected
    else:
        assert left in (expected - 1, expected), (left, expected)


@pytest.fixture
def world(vo, rbac_enabled, random_account) -> "Iterator[World]":
    """
    A scope owned by root, the account alice, reading the scope through a role of its own, and the RSEs RSE1 and RSE2,
    tagged tier=1, on which alice uses 3 GB and 4 GB.
    """
    prefix = generate_uuid()[:10]
    world = World(vo=vo, scope='rbac_%s' % prefix, tag='rbac_%s' % prefix, account=random_account)
    _db(core_scope.add_scope, InternalScope(world.scope, vo=vo), InternalAccount('root', vo=vo))
    try:
        reader = 'rbac-%s' % generate_uuid()[:12]
        _db(core_role.add_role, reader)
        world.roles.append(reader)
        _db(core_role.add_account_role, world.account, reader, activates_at=datetime.utcnow() - timedelta(hours=1))
        _db(core_role.add_role_permission, reader, RolePermissionType.DID, {'did_pattern': '%s:*' % world.scope, 'operations': [DidOperationType.READ]})
        world.add_rse('SOURCE', tier1=False)
        world.add_rse('RSE1')
        world.add_rse('RSE2')
        world.use('RSE1', 3 * GB)
        world.use('RSE2', 4 * GB)
        yield world
    finally:
        for role in world.roles:
            _db(core_role.delete_role, role, force=True)
        with db_session(DatabaseOperationType.WRITE) as session:
            scope = InternalScope(world.scope, vo=vo)
            cleanup_db_deps(model=models.Scope, select_rows_stmt=models.Scope.scope == scope, session=session)
            session.execute(delete(models.Scope).where(models.Scope.scope == scope))
            for rse_id in world.rse_ids.values():
                cleanup_db_deps(model=models.RSE, select_rows_stmt=models.RSE.id == rse_id, session=session)
                session.execute(delete(models.RSE).where(models.RSE.id == rse_id))


# ----------------------------------------------------------------------------------------------
# Applying the limits, within a role and across roles
# ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(('role_a', 'role_b', 'expected'), [
    ([('local', 'RSE1', 5 * GB)], [], 2 * GB),
    ([('local', 'RSE1', 5 * GB), ('global', 'tier1', 8 * GB)], [], 1 * GB),
    ([('local', 'RSE1', 5 * GB)], [('local', 'RSE1', 10 * GB)], 7 * GB),
    ([('local', 'RSE1', 20 * GB), ('global', 'tier1', 8 * GB)], [('local', 'RSE1', 6 * GB)], 3 * GB),
    ([('local', 'RSE1', 5 * GB)], [('global', 'tier1', 1 * GB)], 2 * GB),
    ([('local', 'RSE1', 0)], [('local', 'RSE1', NOCAP)], float('inf')),
    ([('local', 'RSE1', 5 * GB)], [('local', 'RSE1', 5 * GB)], 2 * GB),
    ([('local', 'RSE1', NOCAP), ('global', 'tier1', NOCAP)], [], float('inf')),
], ids=['local limit', 'its global limit restricts it', 'the role leaving the most space', 'a global limit counts within its role',
        'a global limit only restricts its own role', 'no cap', 'identical limits, usage counted once', 'no cap anywhere'])
def test_space_left(world, role_a, role_b, expected):
    """ROLE LIMIT (GATEWAY): On an RSE, a role leaves the least of its local limit and its global ones; across roles, the one leaving the most is taken."""
    for limits in (role_a, role_b):
        if limits:
            role = world.role()
            for locality, target, bytes_ in limits:
                if locality == 'local':
                    world.local(role, target, bytes_)
                else:
                    world.global_(role, world.tier1, bytes_)
    _assert_space_left(world, 'RSE1', expected)


def test_local_limit_of_zero_writes_nothing(world):
    """ROLE LIMIT (GATEWAY): A local limit of 0 still covers its RSE: nothing may be written there, and the account limits are not used."""
    _db(core_account_limit.set_local_account_limit, world.account, world.rse_ids['RSE1'], 100 * GB)
    world.local(world.role(), 'RSE1', 0)
    _assert_space_left(world, 'RSE1', None)


@pytest.mark.parametrize('smaller', [True, False], ids=['smaller role limit', 'larger role limit'])
def test_role_limit_replaces_account_limits(world, smaller):
    """ROLE LIMIT (GATEWAY): Once a role has a local limit on an RSE, the account limits are ignored there, even larger ones."""
    _db(core_account_limit.set_local_account_limit, world.account, world.rse_ids['RSE1'], 100 * GB)
    world.local(world.role(), 'RSE1', (5 if smaller else 200) * GB)
    _assert_space_left(world, 'RSE1', (2 if smaller else 197) * GB)


def test_account_limits_apply_where_no_role_limit(world):
    """ROLE LIMIT (GATEWAY): Where no role has a local limit, the account limits apply, as in standard Rucio; global role limits never grant."""
    _db(core_account_limit.set_local_account_limit, world.account, world.rse_ids['RSE2'], 10 * GB)
    role = world.role()
    world.local(role, 'RSE1', 5 * GB)
    world.global_(role, world.tier1, 100 * GB)
    _assert_space_left(world, 'RSE2', 6 * GB)
    # a role with global limits only lets nothing be written by itself
    world.add_rse('RSE3')
    _assert_space_left(world, 'RSE3', None)


def test_global_limit_covers_rses_tagged_later(world):
    """ROLE LIMIT (GATEWAY): The expression of a global limit is resolved each time: an RSE tagged later is covered at once."""
    role = world.role()
    world.global_(role, world.tier1, 8 * GB)
    world.add_rse('RSE3')
    world.local(role, 'RSE3', 5 * GB)
    # 7 GB used on tier=1, so 1 GB left by the global limit
    _assert_space_left(world, 'RSE3', 1 * GB)


def test_usage_is_the_accounts_own(world):
    """ROLE LIMIT (GATEWAY): The usage measured against a role limit is everything the account uses on the RSE, whichever role it wrote under."""
    world.local(world.role(), 'RSE1', 5 * GB)
    world.use('RSE1', 4 * GB)
    _assert_space_left(world, 'RSE1', 1 * GB)


def test_inactive_assignment_grants_no_limit(world):
    """ROLE LIMIT (GATEWAY): The limits of an expired role, or of one not active yet, do not apply: the account limits do."""
    now = datetime.utcnow()
    _db(core_account_limit.set_local_account_limit, world.account, world.rse_ids['RSE1'], 10 * GB)
    world.local(world.role(activates_at=now - timedelta(days=2), expires_at=now - timedelta(days=1)), 'RSE1', 100 * GB)
    world.local(world.role(activates_at=now + timedelta(days=1)), 'RSE1', 100 * GB)
    _assert_space_left(world, 'RSE1', 7 * GB)


def test_admins_are_not_limited(world):
    """ROLE LIMIT (GATEWAY): The holders of the admin role are not bound by the limits of their roles."""
    world.local(world.role(), 'RSE1', 0)
    _db(core_role.add_account_role, world.account, ADMIN_ROLE, force=True)
    assert world.can_write('RSE1', 10**15)


def test_rbac_disabled_ignores_role_limits(world, monkeypatch):
    """ROLE LIMIT (GATEWAY): Without RBAC, only the account limits apply, as in standard Rucio."""
    _db(core_account_limit.set_local_account_limit, world.account, world.rse_ids['RSE1'], 10 * GB)
    world.local(world.role(), 'RSE1', 100 * GB)
    monkeypatch.setattr(core_role, 'is_rbac_enabled', lambda: False)
    _assert_space_left(world, 'RSE1', 7 * GB)


def test_rule_on_several_rses_selects_one_with_space(world):
    """ROLE LIMIT (GATEWAY): A rule on an RSE expression is placed on an RSE whose limits leave enough space."""
    role = world.role()
    world.local(role, 'RSE1', 3 * GB)
    world.local(role, 'RSE2', 10 * GB)
    rule = gw_rule.get_replication_rule(world.add_rule(world.tier1, 5 * GB), issuer='root', vo=world.vo)
    assert rule['rse_expression'] == world.tier1
    with pytest.raises(InsufficientAccountLimit):
        world.add_rule(world.tier1, 20 * GB)


# ----------------------------------------------------------------------------------------------
# Managing the limits
# ----------------------------------------------------------------------------------------------

def test_limits_are_listed_and_overwritten(world):
    """ROLE LIMIT (GATEWAY): A role has one local limit per RSE and one global limit per expression: setting one again overwrites it."""
    role = world.role()
    world.local(role, 'RSE1', 5 * GB)
    world.local(role, 'RSE1', 6 * GB)
    world.global_(role, world.tier1, 8 * GB)
    limits = [permission for permission in gw_role.list_role_permissions(role, issuer='root', vo=world.vo) if permission['type'] == 'limit']
    assert len(limits) == 2
    # the local limit leaves 6 - 3 GB, but the global one only 8 - 7 GB
    _assert_space_left(world, 'RSE1', 1 * GB)


def test_alice_lists_the_limits_of_her_roles(world):
    """ROLE LIMIT (GATEWAY): An account lists the limits of the roles it holds, not those of other roles."""
    role = world.role()
    world.local(role, 'RSE1', 5 * GB)
    assert any(permission['type'] == 'limit' for permission in gw_role.list_role_permissions(role, issuer=world.alice, vo=world.vo))
    detail = gw_role.list_account_roles(world.alice, issuer=world.alice, detail=True, vo=world.vo)
    assert any(permission['role'] == role and permission['type'] == 'limit' for permission in detail['permissions'])
    other = 'rbac-%s' % generate_uuid()[:12]
    gw_role.add_role(other, issuer='root', vo=world.vo)
    world.roles.append(other)
    with pytest.raises(AccessDenied):
        gw_role.list_role_permissions(other, issuer=world.alice, vo=world.vo)


def test_only_admins_manage_limits(world):
    """ROLE LIMIT (GATEWAY): An account cannot set limits, not even on the roles it holds."""
    role = world.role()
    with pytest.raises(AccessDenied):
        gw_role.add_role_permission(role, 'limit', {'rse_expression': world.rses['RSE1'], 'local': NOCAP}, issuer=world.alice, vo=world.vo)


def test_removing_a_limit(world):
    """ROLE LIMIT (GATEWAY): Removing the local limit of a role on an RSE gives it back to the account limits."""
    _db(core_account_limit.set_local_account_limit, world.account, world.rse_ids['RSE1'], 10 * GB)
    role = world.role()
    world.local(role, 'RSE1', 100 * GB)
    assert gw_role.delete_role_permission(role, 'limit', {'rse_expression': world.rses['RSE1'], 'local': True}, issuer='root', vo=world.vo) == 1
    _assert_space_left(world, 'RSE1', 7 * GB)


@pytest.mark.parametrize('parameters', [
    {'local': -2},
    {'local': 'a lot'},
    {'global': 5 * GB},
    {},
], ids=['negative', 'not a size', 'global limit on a single RSE', 'no limit'])
def test_invalid_limits_are_refused(world, parameters):
    """ROLE LIMIT (GATEWAY): A limit is a number of bytes, or no cap; a global limit covers several RSEs, a local one a single RSE."""
    with pytest.raises(InputValidationError):
        gw_role.add_role_permission(world.role(), 'limit', dict(parameters, rse_expression=world.rses['RSE1']), issuer='root', vo=world.vo)


def test_local_limit_needs_a_single_rse(world):
    """ROLE LIMIT (GATEWAY): A local limit on an expression matching several RSEs is refused."""
    with pytest.raises(InputValidationError):
        world.local(world.role(), world.tier1, 5 * GB)
