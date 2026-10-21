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

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from rucio.common.constants import ADMIN_ROLE, ROLE_QUOTA_NOCAP
from rucio.common.exception import InputValidationError, InsufficientAccountLimit, RolePermissionNotFound
from rucio.common.utils import generate_uuid
from rucio.core import role as core_role
from rucio.core.account_limit import set_global_account_limit, set_local_account_limit
from rucio.core.rse import add_rse_attribute
from rucio.core.rse_selector import RSESelector
from rucio.db.sqla import models
from rucio.db.sqla.constants import RolePermissionType, ScopeOperationType

INF = float('inf')
NOCAP = ROLE_QUOTA_NOCAP


@pytest.fixture
def role_factory(db_session):
    """Create roles for the test, and delete them, with their permissions and assignments, afterwards."""
    created = []

    def _make_role(*accounts, **assignment):
        role = 'rse-quota-%s' % generate_uuid()
        core_role.add_role(role, session=db_session)
        created.append(role)
        for account in accounts:
            core_role.add_account_role(account, role, session=db_session, **assignment)
        return role

    yield _make_role
    for role in created:
        core_role.delete_role(role, force=True, session=db_session)


@pytest.fixture
def tagged_rse_factory(rse_factory, db_session):
    """Create RSEs selected by an RSE expression of their own, e.g. to add an RSE to the expression later."""
    key = 'rbac_%s' % generate_uuid()[:8]

    def _make_rses(count):
        rses = [rse_factory.make_rse() for _ in range(count)]
        for _, rse_id in rses:
            add_rse_attribute(rse_id, key, True, session=db_session)
        return rses

    _make_rses.expression = '%s=True' % key
    return _make_rses


def _set(role, rse_expression, session, **limits):
    core_role.add_role_permission(role, RolePermissionType.LIMIT, {'rse_expression': rse_expression, **limits}, session=session)


def _local(role, rse_expression, bytes_, session):
    _set(role, rse_expression, session, local=bytes_)


def _global(role, rse_expression, bytes_, session):
    _set(role, rse_expression, session, **{'global': bytes_})


def _remove(role, rse_expression, session, **localities):
    return core_role.delete_role_permission(role, RolePermissionType.LIMIT, {'rse_expression': rse_expression, **localities}, session=session)


def _listed(role, session):
    return [permission for permission in core_role.list_role_permissions(role, session=session) if permission['type'] == 'limit']


def _set_usage(account, rse_id, bytes_, session):
    session.merge(models.AccountUsage(account=account, rse_id=rse_id, files=1, bytes=bytes_))
    session.commit()


def _selected(account, rse_ids, session):
    """Run the RSE selector of a rule on the RSEs, and return the RSEs it keeps by id, with what their limits leave."""
    rses = [{'id': rse_id, 'staging_area': False, 'availability_write': True} for rse_id in rse_ids]
    try:
        selector = RSESelector(account=account, rses=rses, weight=None, copies=1, session=session)
    except InsufficientAccountLimit:
        return {}
    return {rse['rse_id']: rse for rse in selector.rses}


# --- applying the limits ------------------------------------------------------------------------

def test_account_limits_apply_without_role_limit(random_account, rse_factory, db_session):
    """ROLE LIMIT (CORE): Without any role limit, the account limits apply as they always did."""
    _, rse_id = rse_factory.make_rse()
    _, other_rse_id = rse_factory.make_rse()
    set_local_account_limit(random_account, rse_id, 100, session=db_session)

    selected = _selected(random_account, [rse_id, other_rse_id], db_session)
    assert selected[rse_id]['quota_left'] == 100
    # no account limit is a quota of 0
    assert other_rse_id not in selected


@pytest.mark.parametrize('role_bytes', [1000, 10], ids=['role allows more', 'role allows less'])
def test_local_role_limit_takes_precedence_over_account_limits(random_account, rse_factory, role_factory, db_session, role_bytes):
    """ROLE LIMIT (CORE): On an RSE covered by a local role limit, the role replaces the account limits, larger or smaller, global ones included."""
    rse, rse_id = rse_factory.make_rse()
    set_local_account_limit(random_account, rse_id, 100, session=db_session)
    set_global_account_limit(random_account, rse, 5, session=db_session)
    _local(role_factory(random_account), rse, role_bytes, db_session)

    selected = _selected(random_account, [rse_id], db_session)
    assert selected[rse_id]['quota_left'] == role_bytes
    assert selected[rse_id]['global_quota_left'] == {}


def test_local_role_limit_of_zero(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): A local limit of 0 lets nothing be written, and still takes precedence over the account limits."""
    rse, rse_id = rse_factory.make_rse()
    set_local_account_limit(random_account, rse_id, 100, session=db_session)
    _local(role_factory(random_account), rse, 0, db_session)

    assert _selected(random_account, [rse_id], db_session) == {}


def test_local_role_limit_without_cap(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): A local limit of ROLE_QUOTA_NOCAP does not cap anything."""
    rse, rse_id = rse_factory.make_rse()
    _local(role_factory(random_account), rse, NOCAP, db_session)

    assert _selected(random_account, [rse_id], db_session)[rse_id]['quota_left'] == INF


def test_global_role_limit_alone_grants_nothing(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): Like a global account limit, a global role limit only restricts: alone, it does not cover an RSE, so the account limits apply."""
    rse, rse_id = rse_factory.make_rse()
    other_rse, _ = rse_factory.make_rse()
    set_local_account_limit(random_account, rse_id, 100, session=db_session)
    _global(role_factory(random_account), '%s|%s' % (rse, other_rse), 1000, db_session)

    assert _selected(random_account, [rse_id], db_session)[rse_id]['quota_left'] == 100


def test_local_and_global_role_limits_both_apply(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): Within a role, an RSE needs room under its local limit and under every global limit covering it, like the account limits."""
    rse, rse_id = rse_factory.make_rse()
    other_rse, other_rse_id = rse_factory.make_rse()
    rse_expression = '%s|%s' % (rse, other_rse)
    role = role_factory(random_account)
    _local(role, rse, 100, db_session)
    _local(role, other_rse, 100, db_session)
    _global(role, rse_expression, 150, db_session)
    _set_usage(random_account, rse_id, 90, db_session)
    _set_usage(random_account, other_rse_id, 40, db_session)

    selected = _selected(random_account, [rse_id, other_rse_id], db_session)
    assert (selected[rse_id]['quota_left'], selected[rse_id]['global_quota_left']) == (10, {rse_expression: 20})
    assert (selected[other_rse_id]['quota_left'], selected[other_rse_id]['global_quota_left']) == (60, {rse_expression: 20})

    # once the global limit is used up, neither RSE may be written to, whatever their local limits leave
    _set_usage(random_account, other_rse_id, 60, db_session)
    assert _selected(random_account, [rse_id, other_rse_id], db_session) == {}


def test_most_space_left_among_roles(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): Among the roles covering an RSE with a local limit, the one leaving the most space is taken."""
    rse, rse_id = rse_factory.make_rse()
    _local(role_factory(random_account), rse, 100, db_session)
    _local(role_factory(random_account), rse, 500, db_session)
    _set_usage(random_account, rse_id, 50, db_session)

    assert _selected(random_account, [rse_id], db_session)[rse_id]['quota_left'] == 450


def test_global_role_limit_does_not_bind_another_role(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): The global limits of a role only restrict its own local limits, not those of another role."""
    rse, rse_id = rse_factory.make_rse()
    other_rse, other_rse_id = rse_factory.make_rse()
    restricted = role_factory(random_account)
    _local(restricted, rse, 100, db_session)
    _global(restricted, '%s|%s' % (rse, other_rse), 100, db_session)
    _local(role_factory(random_account), rse, 10_000, db_session)
    _set_usage(random_account, other_rse_id, 100, db_session)

    selected = _selected(random_account, [rse_id], db_session)
    assert (selected[rse_id]['quota_left'], selected[rse_id]['global_quota_left']) == (10_000, {})


def test_uncovered_rse_falls_back_to_account_limits(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): On an RSE no local role limit covers, the account limits keep applying."""
    rse, rse_id = rse_factory.make_rse()
    _, other_rse_id = rse_factory.make_rse()
    _local(role_factory(random_account), rse, 1000, db_session)
    set_local_account_limit(random_account, other_rse_id, 100, session=db_session)

    selected = _selected(random_account, [rse_id, other_rse_id], db_session)
    assert selected[rse_id]['quota_left'] == 1000
    assert selected[other_rse_id]['quota_left'] == 100


def test_global_limit_covers_rse_matched_later(random_account, tagged_rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): A global limit is resolved whenever it is applied, so that it also covers the RSEs its expression only matches later."""
    (rse, rse_id), _ = tagged_rse_factory(2)
    role = role_factory(random_account)
    _local(role, rse, 100, db_session)
    _global(role, tagged_rse_factory.expression, 1000, db_session)
    [(_, later_rse_id)] = tagged_rse_factory(1)
    _set_usage(random_account, later_rse_id, 950, db_session)

    # the RSE matched later counts towards the global limit, but has no local limit, so the account limits apply there
    selected = _selected(random_account, [rse_id, later_rse_id], db_session)
    assert (selected[rse_id]['quota_left'], selected[rse_id]['global_quota_left']) == (100, {tagged_rse_factory.expression: 50})
    assert later_rse_id not in selected


def test_inactive_role_assignment_grants_no_limit(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT (CORE): A role assignment which is not active yet grants no limit, so the account limits apply."""
    rse, rse_id = rse_factory.make_rse()
    set_local_account_limit(random_account, rse_id, 100, session=db_session)
    future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
    _local(role_factory(random_account, activates_at=future), rse, 1000, db_session)

    assert core_role.list_account_rse_quota_grants(random_account, session=db_session) == []
    assert _selected(random_account, [rse_id], db_session)[rse_id]['quota_left'] == 100


def test_admin_role_is_exempt_from_limits(random_account, rse_factory, db_session):
    """ROLE LIMIT (CORE): An account holding the admin role is not bound by any limit."""
    _, rse_id = rse_factory.make_rse()
    core_role.setup_reserved_roles(session=db_session)
    core_role.add_account_role(random_account, ADMIN_ROLE, force=True, session=db_session)
    try:
        assert _selected(random_account, [rse_id], db_session)[rse_id]['quota_left'] == INF
    finally:
        core_role.delete_account_role(random_account, ADMIN_ROLE, force=True, session=db_session)


# --- managing the limits --------------------------------------------------------------------------

def test_local_and_global_limits_are_listed(tagged_rse_factory, role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): A local limit is listed under the name of its RSE, even if set through another expression matching it, a global one under its expression."""
    [(rse, _)] = tagged_rse_factory(1)
    role = role_factory()
    _local(role, tagged_rse_factory.expression, 100, db_session)
    # once the expression matches a second RSE, it takes a global limit
    tagged_rse_factory(1)
    _global(role, tagged_rse_factory.expression, NOCAP, db_session)

    assert _listed(role, db_session) == sorted([
        {'type': 'limit', 'rse_expression': rse, 'local': 100},
        {'type': 'limit', 'rse_expression': tagged_rse_factory.expression, 'global': NOCAP},
    ], key=lambda permission: permission['rse_expression'])


def test_local_limit_needs_a_single_rse(tagged_rse_factory, role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): A local limit is refused on an expression matching several RSEs, or none."""
    tagged_rse_factory(2)
    role = role_factory()
    for rse_expression in (tagged_rse_factory.expression, 'NO-SUCH-RSE-%s' % generate_uuid().upper()):
        with pytest.raises(InputValidationError):
            _local(role, rse_expression, 100, db_session)
    assert _listed(role, db_session) == []


def test_global_limit_needs_several_rses(rse_factory, role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): A global limit is refused on an expression matching a single RSE, or none."""
    rse, _ = rse_factory.make_rse()
    role = role_factory()
    for rse_expression in (rse, 'NO-SUCH-RSE-%s' % generate_uuid().upper()):
        with pytest.raises(InputValidationError):
            _global(role, rse_expression, 100, db_session)
    assert _listed(role, db_session) == []


def test_setting_a_limit_overwrites_it(rse_factory, role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): Setting a limit which exists already overwrites it."""
    rse, _ = rse_factory.make_rse()
    other_rse, _ = rse_factory.make_rse()
    rse_expression = '%s|%s' % (rse, other_rse)
    role = role_factory()
    _local(role, rse, 100, db_session)
    _global(role, rse_expression, 200, db_session)
    _local(role, rse, 150, db_session)
    _global(role, rse_expression, NOCAP, db_session)

    assert _listed(role, db_session) == sorted([
        {'type': 'limit', 'rse_expression': rse, 'local': 150},
        {'type': 'limit', 'rse_expression': rse_expression, 'global': NOCAP},
    ], key=lambda permission: permission['rse_expression'])


def test_removing_limits(rse_factory, role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): Limits are removed by locality, both being looked for if none is given: the local one on the RSE the expression matches, the global one on the expression."""
    rse, _ = rse_factory.make_rse()
    other_rse, _ = rse_factory.make_rse()
    rse_expression = '%s|%s' % (rse, other_rse)
    role = role_factory()
    _local(role, rse, 100, db_session)
    _local(role, other_rse, 100, db_session)
    _global(role, rse_expression, 1000, db_session)

    assert _remove(role, rse_expression, db_session, **{'global': True}) == 1
    with pytest.raises(RolePermissionNotFound):
        _remove(role, rse_expression, db_session, **{'global': True})
    # the local limit on an expression matching several RSEs is ambiguous, so only refused when asked for
    with pytest.raises(InputValidationError):
        _remove(role, rse_expression, db_session, local=True)
    with pytest.raises(RolePermissionNotFound):
        _remove(role, rse_expression, db_session)

    assert _remove(role, rse, db_session, local=True) == 1
    assert _remove(role, other_rse, db_session) == 1
    assert _listed(role, db_session) == []


@pytest.mark.parametrize('limits', [
    {'local': -2},
    {'local': None},
    {'local': '100GB'},
    {'local': True},
    {'bytes': 100},
    {'local': 100, 'global': 100},
    {},
], ids=['negative limit', 'null limit', 'limit not in bytes', 'limit as a boolean', 'unknown parameter', 'local and global', 'no limit'])
def test_invalid_limit_is_rejected(rse_factory, role_factory, db_session, limits):
    """ROLE LIMIT PERMISSION (CORE): A limit is only accepted as either a local or a global non-negative number of bytes, or ROLE_QUOTA_NOCAP; null never means no cap."""
    rse, _ = rse_factory.make_rse()
    with pytest.raises(InputValidationError):
        _set(role_factory(), rse, db_session, **limits)


@pytest.mark.parametrize('localities', [
    {'local': 100},
    {'local': False, 'global': False},
], ids=['locality not a boolean', 'no locality selected'])
def test_invalid_limit_removal_is_rejected(rse_factory, role_factory, db_session, localities):
    """ROLE LIMIT PERMISSION (CORE): Limits are removed by localities given as booleans, at least one of them true."""
    rse, _ = rse_factory.make_rse()
    role = role_factory()
    _local(role, rse, 100, db_session)
    with pytest.raises(InputValidationError):
        _remove(role, rse, db_session, **localities)


def test_malformed_rse_expression_is_rejected(role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): A malformed RSE expression is refused."""
    with pytest.raises(InputValidationError):
        _global(role_factory(), 'CERN-EOS-DISK||', 100, db_session)


def test_limit_is_not_checked_against_requests(random_account, rse_factory, role_factory, db_session):
    """ROLE LIMIT PERMISSION (CORE): A limit is applied by the RSE selector, not checked against a permission request."""
    @dataclass(frozen=True)
    class LimitRequest(core_role.PermissionRequest):
        permission_type = RolePermissionType.LIMIT

    with pytest.raises(InputValidationError):
        core_role.has_permission(random_account, LimitRequest(operation=ScopeOperationType.WRITE), session=db_session)


@pytest.mark.parametrize('parameters', [
    {'scope_pattern': 'user.*'},
    {'scope_pattern': 'user.*', 'operation': 'write', 'local': 100},
    {'operation': 'write'},
], ids=['no operation', 'limit on a scope', 'no scope pattern'])
def test_scope_permission_parameters(role_factory, db_session, parameters):
    """ROLE LIMIT PERMISSION (CORE): A scope permission takes a scope pattern and an operation, and nothing else."""
    with pytest.raises(InputValidationError):
        core_role.add_role_permission(role_factory(), RolePermissionType.SCOPE, parameters, session=db_session)
