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

from typing import TYPE_CHECKING, Any

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError

from rucio.common.exception import AccountNotFound, Duplicate, RoleAssignmentNotFound, RoleInUse, RoleNotFound, RolePermissionNotFound, ScopeNotFound
from rucio.common.types import InternalScope
from rucio.core import permission
from rucio.core.scope import is_scope_owner
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount


def _violates_constraint(error: IntegrityError, constraint_name: str) -> bool:
    """Best-effort match of a named DB constraint against the raised IntegrityError text."""
    return constraint_name.lower() in str(error.orig or error).lower()


def list_roles(session: "Session") -> list[str]:
    """
    List all roles defined in the system.
    """
    stmt = select(models.Roles.role).order_by(models.Roles.role)
    result = session.execute(stmt).scalars().all()
    return list(result)


def add_role(role: str, session: "Session") -> None:
    """
    Add a new role to the system.
    """
    new_role = models.Roles(role=role)
    session.add(new_role)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise Duplicate("Role '%s' already exists." % role)


def delete_role(role: str, session: "Session") -> None:
    """
    Delete an existing role from the system.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    session.delete(role_obj)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise RoleInUse("Role '%s' is still assigned to accounts or has permissions defined and cannot be deleted." % role)


def list_account_roles(account: "InternalAccount", session: "Session") -> list[str]:
    stmt = (
        select(models.AccountRoleAssociation.role)
        .where(models.AccountRoleAssociation.account == account)
        .order_by(models.AccountRoleAssociation.role)
    )
    return list(session.execute(stmt).scalars())


def add_account_role(account: "InternalAccount", role: str, session: "Session") -> None:
    session.add(models.AccountRoleAssociation(account=account, role=role))
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        if _violates_constraint(error, 'ACCOUNT_ROLE_MAP_ACCOUNT_FK'):
            raise AccountNotFound("Account '%s' does not exist." % account)
        if _violates_constraint(error, 'ACCOUNT_ROLE_MAP_ROLE_FK'):
            raise RoleNotFound("Role '%s' does not exist." % role)
        if _violates_constraint(error, 'ACCOUNT_ROLE_MAP_PK'):
            raise Duplicate("Account '%s' already has role '%s'." % (account, role))
        raise Duplicate("Either account '%s' or role '%s' does not exist, or account '%s' already has role '%s'." % (account, role, account, role))


def delete_account_role(account: "InternalAccount", role: str, session: "Session") -> None:
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    session.delete(mapping)
    session.commit()


def list_role_permissions(role: str, session: "Session") -> list[dict[str, str]]:
    stmt = (
        select(models.RolePermissionAssociation)
        .where(models.RolePermissionAssociation.role == role)
        .order_by(models.RolePermissionAssociation.scope, models.RolePermissionAssociation.operation)
    )
    return [
        {'operation': permission.operation.value, 'scope': str(permission.scope.external)}
        for permission in session.execute(stmt).scalars()
    ]


def add_role_permission(role: str, scope: "InternalScope", operation: "DatabaseOperationType", session: "Session") -> None:
    session.add(models.RolePermissionAssociation(role=role, scope=scope, operation=operation))
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        if _violates_constraint(error, 'ROLE_PERMISSION_MAP_ROLE_FK'):
            raise RoleNotFound("Role '%s' does not exist." % role)
        if _violates_constraint(error, 'ROLE_PERMISSION_MAP_SCOPE_FK'):
            raise ScopeNotFound("Scope '%s' does not exist." % scope)
        if _violates_constraint(error, 'ROLE_PERMISSION_MAP_PK'):
            raise Duplicate("Role '%s' already has '%s' permission on scope '%s'." % (role, operation.value, scope))
        raise Duplicate("Either role '%s' or scope '%s' does not exist, or role '%s' already has '%s' permission on scope '%s'." % (role, scope, role, operation.value, scope))


def delete_role_permission(role: str, scope: "InternalScope", operation: "DatabaseOperationType", session: "Session") -> None:
    mapping = session.get(models.RolePermissionAssociation, (role, scope, operation))
    if mapping is None:
        raise RolePermissionNotFound("Either role '%s' or scope '%s' does not exist, or the role does not have '%s' permission on that scope." % (role, scope, operation.value))

    session.delete(mapping)
    session.commit()


def has_account_role(account: "InternalAccount", role: str, session: "Session") -> bool:
    stmt = select(models.AccountRoleAssociation).where(
        models.AccountRoleAssociation.account == account,
        models.AccountRoleAssociation.role == role,
    )
    return bool(session.execute(stmt).scalar_one_or_none())


def has_role_scope_access(
    account: "InternalAccount",
    scope: "InternalScope",
    operation: "DatabaseOperationType",
    session: "Session",
) -> bool:
    """
    Return True if the account has the specified operation permission
    on the given scope, according to the RBAC tables.
    """
    exists_stmt = (
        select(1)
        .select_from(models.AccountRoleAssociation)
        .join(
            models.RolePermissionAssociation,
            models.RolePermissionAssociation.role
            == models.AccountRoleAssociation.role,
        )
        .where(
            models.AccountRoleAssociation.account == account,
            models.RolePermissionAssociation.scope == scope,
            models.RolePermissionAssociation.operation == operation,
        )
    )

    stmt = select(exists(exists_stmt))
    return bool(session.execute(stmt).scalar())


def has_scope_access(
    account: "InternalAccount",
    scope: "InternalScope",
    operation: "DatabaseOperationType",
    *,
    session: "Session",
) -> bool:
    """
    Return True if the account has the specified operation permission
    on the given scope, either through ownership, RBAC or admin/root privileges.
    """

    # Check for admin priviledges
    if permission.has_permission(issuer=account, action='can_read_all_scopes', kwargs={}, session=session):
        return True

    if is_scope_owner(scope=scope, account=account, session=session):
        return True

    return has_role_scope_access(
        account=account,
        scope=scope,
        operation=operation,
        session=session,
    )


def filter_iterable_by_scope_access(
    items: "Iterable[dict[str, Any]]",
    *,
    account: "InternalAccount",
    session: "Session",
    operation: "DatabaseOperationType" = DatabaseOperationType.READ,
    scope_keyword: str = 'scope',
) -> "Iterator[dict[str, Any]]":
    """
    Yield only items whose scope the account may access in terms of RBAC, ownership and admin/root privileges.

    Access decisions are cached for the lifetime of this iterator, so each
    distinct scope is checked at most once.

    :param items: An iterable of dictionaries representing items with associated scopes.
    :param account: The account for which to check access.
    :param session: The database session.
    :param operation: The type of operation to check access for.
    :param scope_keyword: The key in the item dictionaries that contains the associated scope.
    :returns: An iterator over the items that the account has access to.
    """
    access_by_scope: dict["InternalScope", bool] = {}

    for item in items:
        scope = item.get(scope_keyword)
        if scope is None or not isinstance(scope, InternalScope):
            continue

        if scope not in access_by_scope:
            access_by_scope[scope] = has_scope_access(
                account=account,
                scope=scope,
                operation=operation,
                session=session,
            )
        if access_by_scope[scope]:
            yield item
