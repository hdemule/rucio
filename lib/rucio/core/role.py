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

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError

from rucio.common.exception import AccountNotFound, Duplicate, InputValidationError, RoleAssignmentNotFound, RoleInUse, RoleNotFound, RolePermissionNotFound, ScopeNotFound
from rucio.common.types import InternalScope
from rucio.common.utils import DATE_FORMAT, str_to_date
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


def _normalize_description(description: Optional[str]) -> Optional[str]:
    """
    Normalise a role description before it is stored.

    Surrounding whitespace is stripped and a description which is empty afterwards
    is stored as NULL, so that passing an empty string clears the description.

    The length is not restricted here, since `roles.description` is an unbounded text column.

    :param description: The description as supplied by the caller.
    :returns: The description to store, or None if it should be cleared.
    :raises InputValidationError: If the description is not a string.
    """
    if description is None:
        return None

    if not isinstance(description, str):
        raise InputValidationError("Role description must be a string, got '%s'." % type(description).__name__)

    return description.strip() or None


def _normalize_expires_at(expires_at: Optional[Union[str, datetime]]) -> Optional[datetime]:
    """
    Normalise the `expires_at` of a role assignment before it is stored.

    The date may be given as a datetime, or as a string either in Rucio's date
    format ('%a, %d %b %Y %H:%M:%S UTC') or in ISO 8601. An empty string and None both
    mean that the assignment does not expire, which is stored as NULL.

    :param expires_at: The date as supplied by the caller.
    :returns: The date to store, or None if the assignment should not expire.
    :raises InputValidationError: If the expires_at is not a date Rucio understands.
    """
    if expires_at is None or isinstance(expires_at, datetime):
        return expires_at

    if not isinstance(expires_at, str):
        raise InputValidationError("'expires_at' must be a date, got '%s'." % type(expires_at).__name__)

    expires_at = expires_at.strip()
    if not expires_at:
        return None

    for parse in (str_to_date, datetime.fromisoformat):
        try:
            return parse(expires_at)
        except ValueError:
            continue

    raise InputValidationError("'expires_at' value '%s' is not a valid date, expected either the Rucio date format ('%s') or ISO 8601." % (expires_at, DATE_FORMAT))


def list_roles(session: "Session") -> list[dict[str, Any]]:
    """
    List all roles defined in the system, together with their description and locked state.
    """
    stmt = select(models.Roles.role, models.Roles.description, models.Roles.locked).order_by(models.Roles.role)
    return [{"role": role, "description": description, "locked": locked} for role, description, locked in session.execute(stmt).all()]


def add_role(role: str, description: Optional[str] = None, *, session: "Session") -> None:
    """
    Add a new role to the system.

    :param role: The name of the role to add.
    :param description: An optional description of the role. An empty description is stored as NULL.
    :param session: The database session.
    """
    new_role = models.Roles(role=role, description=_normalize_description(description))
    session.add(new_role)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise Duplicate("Role '%s' already exists." % role)


def set_role_description(role: str, description: Optional[str], *, session: "Session") -> Optional[str]:
    """
    Overwrite the description of an existing role.

    :param role: The role to update.
    :param description: The new description. An empty description clears the field (stored as NULL).
    :param session: The database session.
    :returns: The description as it was stored, or None if it was cleared.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    normalized = _normalize_description(description)
    role_obj.description = normalized
    session.commit()
    return normalized


def set_role_locked(role: str, locked: bool, *, session: "Session") -> bool:
    """
    Set the locked state of a role.

    A locked role cannot be altered by any external entity (e.g. an identity provider).

    :param role: The role to lock or unlock.
    :param locked: The requested locked state.
    :param session: The database session.
    :returns: True if the state was changed, False if the role already was in the requested state.
    :raises RoleNotFound: If the role does not exist.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    if role_obj.locked == locked:
        return False

    role_obj.locked = locked
    session.commit()
    return True


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


def list_account_roles(account: "InternalAccount", session: "Session") -> list[dict[str, Any]]:
    """
    List the roles assigned to an account, together with their expiry date and description.

    An `expires_at` of None means that the assignment does not expire.
    """
    stmt = (
        select(models.AccountRoleAssociation.role, models.AccountRoleAssociation.expires_at, models.Roles.description)
        .join(models.Roles, models.Roles.role == models.AccountRoleAssociation.role)
        .where(models.AccountRoleAssociation.account == account)
        .order_by(models.AccountRoleAssociation.role)
    )
    return [{"role": role, "expires_at": expires_at, "description": description} for role, expires_at, description in session.execute(stmt).all()]


def add_account_role(account: "InternalAccount", role: str, expires_at: Optional[Union[str, datetime]] = None, *, session: "Session") -> None:
    """
    Assign a role to an account.

    :param account: The account to assign the role to.
    :param role: The role to assign.
    :param expires_at: An optional date at which the assignment expires. None means that it does not expire.
    :param session: The database session.
    """
    session.add(models.AccountRoleAssociation(account=account, role=role, expires_at=_normalize_expires_at(expires_at)))
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        if _violates_constraint(error, "ACCOUNT_ROLE_MAP_ACCOUNT_FK"):
            raise AccountNotFound("Account '%s' does not exist." % account)
        if _violates_constraint(error, "ACCOUNT_ROLE_MAP_ROLE_FK"):
            raise RoleNotFound("Role '%s' does not exist." % role)
        if _violates_constraint(error, "ACCOUNT_ROLE_MAP_PK"):
            raise Duplicate("Account '%s' already has role '%s'." % (account, role))
        raise Duplicate("Either account '%s' or role '%s' does not exist, or account '%s' already has role '%s'." % (account, role, account, role))


def delete_account_role(account: "InternalAccount", role: str, session: "Session") -> None:
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    session.delete(mapping)
    session.commit()


def set_account_role_expires_at(account: "InternalAccount", role: str, expires_at: Optional[Union[str, datetime]], *, session: "Session") -> Optional[datetime]:
    """
    Overwrite the expiry date of a role assigned to an account.

    :param account: The account the role is assigned to.
    :param role: The role to set the `expires_at` of.
    :param expires_at: The new date. None (or an empty string) clears it, so that the assignment does not expire.
    :param session: The database session.
    :returns: The date as it was stored, or None if it was cleared.
    :raises RoleAssignmentNotFound: If the role is not assigned to the account.
    """
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    normalized = _normalize_expires_at(expires_at)
    mapping.expires_at = normalized
    session.commit()
    return normalized


def list_role_permissions(role: str, session: "Session") -> list[dict[str, str]]:
    stmt = select(models.RolePermissionAssociation).where(models.RolePermissionAssociation.role == role).order_by(models.RolePermissionAssociation.scope, models.RolePermissionAssociation.operation)
    return [{"operation": permission.operation.value, "scope": str(permission.scope.external)} for permission in session.execute(stmt).scalars()]


def add_role_permission(role: str, scope: "InternalScope", operation: "DatabaseOperationType", session: "Session") -> None:
    session.add(models.RolePermissionAssociation(role=role, scope=scope, operation=operation))
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        if _violates_constraint(error, "ROLE_PERMISSION_MAP_ROLE_FK"):
            raise RoleNotFound("Role '%s' does not exist." % role)
        if _violates_constraint(error, "ROLE_PERMISSION_MAP_SCOPE_FK"):
            raise ScopeNotFound("Scope '%s' does not exist." % scope)
        if _violates_constraint(error, "ROLE_PERMISSION_MAP_PK"):
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
    Returns True if the account has the specified operation permission
    on the given scope, according to the RBAC tables.

    This only check the RBAC tables and does not consider ownership or admin/root privileges.
    For checking ownership or admin/root privileges, use the :func:`has_scope_access` function instead.
    """
    exists_stmt = (
        select(1)
        .select_from(models.AccountRoleAssociation)
        .join(
            models.RolePermissionAssociation,
            models.RolePermissionAssociation.role == models.AccountRoleAssociation.role,
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
    Returns True if the account has the specified operation permission
    on the given scope, either through ownership, RBAC or admin/root privileges.
    """

    # Check for admin privileges
    if permission.has_permission(issuer=account, action="can_access_all_scopes", kwargs={"operation": operation}, session=session):
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
    scope_keyword: str = "scope",
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


def sync_roles_from_policy_package(session: "Session") -> None:
    """
    Synchronizes the internal roles with the roles defined by the policy package.
    """
    print("Syncing roles...")
    print("For now, not doing anything but reading the role definitions from the policy package")

    # Read the role definitions from the policy package (the `roles` attribute of its role module)
    # Step 1: Retrieve Roles from the policy package
    roles = permission.get_roles()
    print("Roles defined by the policy package: %s" % roles)

    # Step 2: Retreive all roles and their associated permissions (Roles, RolePermissionAssociation)
    # If a role is locked, don't touch it, it shouldn't be modified by the policy package




def sync_account_roles():
    pass
