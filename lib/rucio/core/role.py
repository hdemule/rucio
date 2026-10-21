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
Role-Based Access Control (RBAC).

The module is organised as follows:

- Roles: create, update, delete and list roles, including the reserved ones, see `RESERVED_ROLES`.
- Account role assignments: which account holds which role, from when and until when.
- Permission types: the types of the permissions a role can be granted, e.g. operations on scopes
  or limits on RSEs. Each type has its own `role_<type>_permission_map` table(s) and a
  :class:`PermissionTypeHandler` registered for it, and a :class:`PermissionRequest` describing what
  is checked against it if it decides whether an account may perform an operation.
- Role permissions: grant, remove and list the permissions of a role, of any type.
- Permission checks: tell whether an account may perform a request, of any checked permission type,
  with :func:`has_permission` as the single entry point, and filter listings accordingly.
- Synchronisation: of the roles with the policy package, and of an account's roles with an IdP.
"""

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Optional, TypeVar, Union, cast

from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.exc import IntegrityError

from rucio.common.config import config_get_bool
from rucio.common.constants import ADMIN_ROLE, DEFAULT_VO, RESERVED_ROLES, ROLE_QUOTA_NOCAP
from rucio.common.exception import (
    AccountNotFound,
    Duplicate,
    InputValidationError,
    InvalidRSEExpression,
    RoleAssignmentDisabled,
    RoleAssignmentNotFound,
    RoleInUse,
    RoleLocked,
    RoleNotFound,
    RolePermissionNotFound,
    RoleReserved,
)
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import DATE_FORMAT, str_to_date
from rucio.core import permission
from rucio.core.account import has_account_attribute
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.scope import is_scope_owner
from rucio.db.sqla import models
from rucio.db.sqla.constants import RolePermissionOperationType, RolePermissionType, ScopeOperationType

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from sqlalchemy.orm import InstrumentedAttribute, Session
    from sqlalchemy.sql.elements import ColumnElement


# Marks a date of a role assignment which is to be left as it is, see :func:`set_account_role_dates`.
KEEP: Any = object()


# ----------------------------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------------------------

def is_rbac_enabled() -> bool:
    return config_get_bool('rbac', 'enabled', raise_exception=False, default=False, check_config_table=False)


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------

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


def _normalize_date(date: Optional[Union[str, datetime]], field: str) -> Optional[datetime]:
    """
    Normalise a date of a role assignment (its `activates_at` or `expires_at`) before it is stored.

    The date may be given as a datetime, or as a string either in Rucio's date
    format ('%a, %d %b %Y %H:%M:%S UTC') or in ISO 8601. An empty string and None both
    mean that no date is given: the assignment then does not expire (`expires_at`), or is
    active from now on (`activates_at`).

    :param date: The date as supplied by the caller.
    :param field: The name of the date, for the error messages.
    :returns: The date to store, or None if no date is given.
    :raises InputValidationError: If the date is not a date Rucio understands.
    """
    if date is None or isinstance(date, datetime):
        return date

    if not isinstance(date, str):
        raise InputValidationError("'%s' must be a date, got '%s'." % (field, type(date).__name__))

    date = date.strip()
    if not date:
        return None

    for parse in (str_to_date, datetime.fromisoformat):
        try:
            return parse(date)
        except ValueError:
            continue

    raise InputValidationError("'%s' value '%s' is not a valid date, expected either the Rucio date format ('%s') or ISO 8601." % (field, date, DATE_FORMAT))


def _ensure_expires_after_activation(activates_at: datetime, expires_at: Optional[datetime]) -> None:
    """
    Mirror the ACCOUNT_ROLE_MAP_EXPIRES_CHK constraint, so that the caller gets a clear error.

    :raises InputValidationError: If the assignment would expire before, or when, it activates.
    """
    if expires_at is not None and expires_at <= activates_at:
        raise InputValidationError("'expires_at' (%s) must be after 'activates_at' (%s)." % (expires_at, activates_at))


def _assignment_active() -> "ColumnElement[bool]":
    """SQL condition keeping only the account role assignments which are active: activated already and not expired yet."""
    # the dates are stored as naive UTC datetimes, so compare them against a naive UTC now
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return and_(
        models.AccountRoleAssociation.activates_at <= now,
        or_(
            models.AccountRoleAssociation.expires_at.is_(None),
            models.AccountRoleAssociation.expires_at > now,
        ),
    )


def _ensure_role_exists(role: str, session: "Session") -> None:
    """
    :raises RoleNotFound: If the role does not exist.
    """
    if session.execute(select(models.Roles.role).where(models.Roles.role == role)).scalar_one_or_none() is None:
        raise RoleNotFound("Role '%s' does not exist." % role)


def _ensure_account_exists(account: "InternalAccount", session: "Session") -> None:
    """
    :raises AccountNotFound: If the account does not exist.
    """
    if session.execute(select(models.Account.account).where(models.Account.account == account)).scalar_one_or_none() is None:
        raise AccountNotFound("Account '%s' does not exist." % account)


def _ensure_unlocked(role: str, force: bool, session: "Session", action: str = "altered") -> None:
    """
    Refuse to touch a locked role, unless forced. Does nothing for a role which does not exist.

    :param role: The role about to be touched.
    :param force: Touch the role even if it is locked.
    :param session: The database session.
    :param action: What is about to be done to the role, for the error message.
    :raises RoleLocked: If the role is locked and `force` is not given.
    """
    if force:
        return

    stmt = select(models.Roles.locked).where(models.Roles.role == role)
    if session.execute(stmt).scalar_one_or_none():
        raise RoleLocked("Role '%s' is locked, so it cannot be %s." % (role, action))


def _role_not_assignable(role: str, session: "Session") -> bool:
    """Tell whether a role is not assignable. False (also) for a role which does not exist."""
    stmt = select(models.Roles.assignable).where(models.Roles.role == role)
    return session.execute(stmt).scalar_one_or_none() is False


def _is_root_or_admin(account: "InternalAccount", session: "Session") -> bool:
    """Tell whether the account is root or an admin, see :func:`is_admin`, either of which grants it every permission."""
    return account.external == "root" or is_admin(account=account, session=session)


# ----------------------------------------------------------------------------------------------
# Roles
# ----------------------------------------------------------------------------------------------

def is_reserved_role(role: str) -> bool:
    """Tell whether a role is reserved by Rucio, see `RESERVED_ROLES`."""
    return role in RESERVED_ROLES


def list_roles(session: "Session") -> list[dict[str, Any]]:
    """
    List all roles defined in the system, together with their description, assignable, locked and reserved state.
    """
    stmt = select(models.Roles.role, models.Roles.description, models.Roles.assignable, models.Roles.locked).order_by(models.Roles.role)
    return [
        {"role": role, "description": description, "assignable": assignable, "locked": locked, "reserved": is_reserved_role(role)}
        for role, description, assignable, locked in session.execute(stmt).all()
    ]


def add_role(role: str, description: Optional[str] = None, assignable: bool = True, locked: bool = False, *, session: "Session") -> None:
    """
    Add a new role to the system.

    :param role: The name of the role to add.
    :param description: An optional description of the role. An empty description is stored as NULL.
    :param assignable: Whether an identity provider may assign this role to, or take it away from, an account; if not, only Rucio itself alters who holds it.
    :param locked: Whether the role is locked, which prevents a policy package from altering or deleting it.
    :param session: The database session.
    :raises RoleReserved: If the role is reserved, see :func:`setup_reserved_roles`.
    """
    if is_reserved_role(role):
        raise RoleReserved("Role '%s' is reserved, so it cannot be added." % role)

    new_role = models.Roles(role=role, description=_normalize_description(description), assignable=assignable, locked=locked)
    session.add(new_role)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise Duplicate("Role '%s' already exists." % role)


def update_role(
        role: str,
        *,
        description: Optional[str] = None,
        assignable: Optional[bool] = None,
        locked: Optional[bool] = None,
        force: bool = False,
        session: "Session") -> dict[str, Any]:
    """
    Update the metadata of an existing role, changing only the parameters explicitly given.

    A locked role cannot have its description or its assignable state changed, unless `force`
    is given. Changing `locked` itself is always allowed, so that a role can be unlocked.
    A reserved role only ever has its assignable state changed, whether or not `force` is given.

    :param role: The role to update.
    :param description: The new description, or None to leave it untouched. An empty string clears it (stored as NULL).
    :param assignable: The new assignable state, or None to leave it untouched.
    :param locked: The new locked state, or None to leave it untouched.
    :param force: Change the description or the assignable state even if the role is locked.
    :param session: The database session.
    :returns: The role as it is stored after the update.
    :raises RoleNotFound: If the role does not exist.
    :raises RoleLocked: If the role is locked, `force` is not given and something besides `locked` is being changed.
    :raises RoleReserved: If the role is reserved and something besides `assignable` is being changed.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    if is_reserved_role(role):
        if description is not None or locked is not None:
            raise RoleReserved("Role '%s' is reserved, so only its assignable state can be changed." % role)
    elif description is not None or assignable is not None:
        _ensure_unlocked(role, force, session)

    if description is not None:
        role_obj.description = _normalize_description(description)
    if assignable is not None:
        role_obj.assignable = assignable
    if locked is not None:
        role_obj.locked = locked

    session.commit()
    return {
        "role": role,
        "description": role_obj.description,
        "assignable": role_obj.assignable,
        "locked": role_obj.locked,
    }


def delete_role(role: str, force: bool = False, *, session: "Session") -> None:
    """
    Delete an existing role from the system.

    A locked role is only deleted if `force` is given.

    :param role: The role to delete.
    :param force: Also remove the role from every account it is assigned to and drop its permissions,
                  instead of refusing to delete a role which is still in use, and delete it even if it is locked.
    :param session: The database session.
    :raises RoleNotFound: If the role does not exist.
    :raises RoleLocked: If the role is locked and `force` is not set.
    :raises RoleInUse: If the role is still in use and `force` is not set.
    :raises RoleReserved: If the role is reserved, whether or not `force` is set.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    if is_reserved_role(role):
        raise RoleReserved("Role '%s' is reserved, so it cannot be deleted." % role)

    _ensure_unlocked(role, force, session, action="deleted")

    if force:
        _remove_accounts_from_role(role, session=session)
        session.commit()
        return

    session.delete(role_obj)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise RoleInUse("Role '%s' is still assigned to accounts and cannot be deleted." % role)


def setup_reserved_roles(*, session: "Session") -> list[str]:
    """
    Create the reserved roles which do not exist yet, see `RESERVED_ROLES`.

    This is the only way to create a reserved role: it is created locked and not assignable, with
    the description given in `RESERVED_ROLES`. A reserved role which already exists is left
    untouched, and no role is ever deleted.

    :param session: The database session.
    :returns: The names of the roles which were created.
    """
    stmt = select(models.Roles.role).where(models.Roles.role.in_(RESERVED_ROLES))
    existing = set(session.execute(stmt).scalars().all())

    created = []
    for role, description in sorted(RESERVED_ROLES.items()):
        if role in existing:
            continue
        session.add(models.Roles(role=role, description=description, assignable=False, locked=True))
        created.append(role)
        logging.log(logging.INFO, "Created reserved role '%s' with description '%s', assignable=False and locked=True.", role, description)

    session.commit()
    return created


def _remove_accounts_from_role(role: str, *, session: "Session") -> int:
    """
    Delete a role together with its account assignments, without committing.

    `account_role_map.role` references `roles.role` with ON DELETE RESTRICT, so the account
    assignments are removed first. The permissions of the role go along with it, since the `role`
    of every `role_<type>_permission_map` table references `roles.role` with ON DELETE CASCADE.

    :param role: The role to delete.
    :param session: The database session.
    :returns: The number of account assignments removed along with the role.
    """
    result = session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role))
    unassigned = cast(Any, result).rowcount
    session.execute(delete(models.Roles).where(models.Roles.role == role))
    return unassigned


# ----------------------------------------------------------------------------------------------
# Account role assignments
# ----------------------------------------------------------------------------------------------

def list_account_roles(account: "InternalAccount", session: "Session") -> list[dict[str, Any]]:
    """
    List the roles assigned to an account, together with their activation and expiry dates, description and reserved state.

    An `expires_at` of None means that the assignment does not expire. An assignment whose `activates_at`
    is in the future is listed, although it does not grant the role yet.
    """
    stmt = (
        select(models.AccountRoleAssociation.role, models.AccountRoleAssociation.activates_at, models.AccountRoleAssociation.expires_at, models.Roles.description)
        .join(models.Roles, models.Roles.role == models.AccountRoleAssociation.role)
        .where(models.AccountRoleAssociation.account == account)
        .order_by(models.AccountRoleAssociation.role)
    )
    return [
        {"role": role, "activates_at": activates_at, "expires_at": expires_at, "description": description, "reserved": is_reserved_role(role)}
        for role, activates_at, expires_at, description in session.execute(stmt).all()
    ]


def list_role_accounts(role: str, session: "Session") -> list[dict[str, Any]]:
    """
    List the accounts a role is assigned to, together with the activation and expiry dates of each assignment.

    An `expires_at` of None means that the assignment does not expire. An assignment whose `activates_at`
    is in the future is listed, although it does not grant the role yet.

    :raises RoleNotFound: If the role does not exist.
    """
    _ensure_role_exists(role, session)

    stmt = (
        select(models.AccountRoleAssociation.account, models.AccountRoleAssociation.activates_at, models.AccountRoleAssociation.expires_at)
        .where(models.AccountRoleAssociation.role == role)
        .order_by(models.AccountRoleAssociation.account)
    )
    return [
        {"account": account, "activates_at": activates_at, "expires_at": expires_at}
        for account, activates_at, expires_at in session.execute(stmt).all()
    ]


def has_account_valid_role(account: "InternalAccount", role: str, session: "Session") -> bool:
    """
    Tell whether the account holds the role through an assignment which is active: activated already and not expired yet.

    :param account: The account to check.
    :param role: The role to check.
    :param session: The database session.
    """
    stmt = select(models.AccountRoleAssociation.role).where(
        models.AccountRoleAssociation.account == account,
        models.AccountRoleAssociation.role == role,
        _assignment_active(),
    )
    return session.execute(stmt).first() is not None


def is_admin(account: "InternalAccount", *, session: "Session") -> bool:
    """
    Tell whether the account is an admin: it holds the reserved admin role through an assignment which is active,
    or, if RBAC is disabled, it has the 'admin' account attribute, as in standard Rucio.

    :param account: The account to check.
    :param session: The database session.
    """
    # Retro-compatibility: if RBAC is disabled, the 'admin' account attribute still grants admin privileges.
    if not is_rbac_enabled():
        return has_account_attribute(account=account, key='admin', session=session)
    return has_account_valid_role(account=account, role=ADMIN_ROLE, session=session)


def add_account_role(
        account: "InternalAccount",
        role: str,
        expires_at: Optional[Union[str, datetime]] = None,
        force: bool = False,
        activates_at: Optional[Union[str, datetime]] = None,
        *,
        session: "Session") -> None:
    """
    Assign a role to an account.

    :param account: The account to assign the role to.
    :param role: The role to assign.
    :param expires_at: An optional date at which the assignment expires. None means that it does not expire.
    :param force: Assign the role even if it is not assignable.
    :param activates_at: An optional date from which the assignment grants the role. None means from now on.
    :param session: The database session.
    :raises RoleAssignmentDisabled: If the role is not assignable and `force` is not given.
    :raises InputValidationError: If a date is not valid, or if the assignment would expire before it activates.
    """
    if not force and _role_not_assignable(role, session):
        raise RoleAssignmentDisabled("Role '%s' is not assignable, so it cannot be assigned to an account." % role)

    expires_at = _normalize_date(expires_at, "expires_at")
    # set now explicitly rather than relying on the column default, so that it is the date checked against expires_at
    activates_at = _normalize_date(activates_at, "activates_at") or datetime.now(timezone.utc).replace(tzinfo=None)
    _ensure_expires_after_activation(activates_at, expires_at)

    session.add(models.AccountRoleAssociation(account=account, role=role, activates_at=activates_at, expires_at=expires_at))
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


def delete_account_role(account: "InternalAccount", role: str, force: bool = False, *, session: "Session") -> None:
    """
    Remove a role from an account.

    :param account: The account to remove the role from.
    :param role: The role to remove.
    :param force: Remove the role even if it is not assignable.
    :param session: The database session.
    :raises RoleAssignmentNotFound: If the account does not have the role assigned.
    :raises RoleAssignmentDisabled: If the role is not assignable and `force` is not given.
    """
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    if not force and _role_not_assignable(role, session):
        raise RoleAssignmentDisabled("Role '%s' is not assignable, so it cannot be removed from an account." % role)

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
    :raises InputValidationError: If the date is not valid, or if it is not after the `activates_at` of the assignment.
    """
    return set_account_role_dates(account, role, expires_at=expires_at, session=session)["expires_at"]


def set_account_role_activates_at(account: "InternalAccount", role: str, activates_at: Optional[Union[str, datetime]], *, session: "Session") -> datetime:
    """
    Overwrite the activation date of a role assigned to an account.

    :param account: The account the role is assigned to.
    :param role: The role to set the `activates_at` of.
    :param activates_at: The new date. None (or an empty string) sets it to now, so that the assignment is active right away.
    :param session: The database session.
    :returns: The date as it was stored.
    :raises RoleAssignmentNotFound: If the role is not assigned to the account.
    :raises InputValidationError: If the date is not valid, or if it is not before the `expires_at` of the assignment.
    """
    return set_account_role_dates(account, role, activates_at=activates_at, session=session)["activates_at"]


def set_account_role_dates(
        account: "InternalAccount",
        role: str,
        activates_at: Optional[Union[str, datetime]] = KEEP,
        expires_at: Optional[Union[str, datetime]] = KEEP,
        *,
        session: "Session") -> dict[str, Optional[datetime]]:
    """
    Overwrite the activation and/or expiry dates of a role assigned to an account, in one go.

    The dates are checked against each other as they will be stored, so that the whole period of
    an assignment can be moved at once, which setting one date after the other may refuse.

    :param account: The account the role is assigned to.
    :param role: The role to set the dates of.
    :param activates_at: The new activation date, or `KEEP` to leave it as it is. None (or an empty
                         string) sets it to now, so that the assignment is active right away.
    :param expires_at: The new expiry date, or `KEEP` to leave it as it is. None (or an empty
                       string) clears it, so that the assignment does not expire.
    :param session: The database session.
    :returns: The `activates_at` and `expires_at` of the assignment, as they were stored.
    :raises RoleAssignmentNotFound: If the role is not assigned to the account.
    :raises InputValidationError: If a date is not valid, or if the assignment would expire before it activates.
    """
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    if activates_at is not KEEP:
        activates_at = _normalize_date(activates_at, "activates_at") or datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        activates_at = mapping.activates_at
    expires_at = mapping.expires_at if expires_at is KEEP else _normalize_date(expires_at, "expires_at")
    _ensure_expires_after_activation(activates_at, expires_at)

    mapping.activates_at = activates_at
    mapping.expires_at = expires_at
    session.commit()
    return {"activates_at": activates_at, "expires_at": expires_at}


# ----------------------------------------------------------------------------------------------
# Permission types
#
# A role is granted permissions of several types. A permission is made of its role, its type, its
# target (e.g. a scope pattern) and the parameters of its type (e.g. the operation it grants on the
# scopes the pattern matches). Each permission type comes with:
#
# - a `RolePermissionType` member;
# - one or more `role_<type>_permission_map` tables, whose `role` references `roles.role` with
#   ON DELETE CASCADE;
# - a `PermissionTypeHandler` subclass, registered with `_register_permission_handler`, telling how
#   its permissions are validated, granted, removed and listed.
#
# A permission type deciding whether an account may perform an operation on a resource (e.g. on a
# scope) has a `CheckedPermissionTypeHandler`, together with a `PermissionRequest` subclass naming
# the resource and the operations it grants, its own subclass of `RolePermissionOperationType`
# (e.g. `ScopeOperationType` for scopes), see :func:`has_permission`. The other types are applied where they matter.
#
# Nothing else in this module has to change to support a new permission type.
# ----------------------------------------------------------------------------------------------

# the parameter of a permission granting an operation, see `CheckedPermissionTypeHandler`
OPERATION = "operation"

OperationT = TypeVar("OperationT", bound=RolePermissionOperationType)


def _normalize_operation(operation: Union[OperationT, str], operation_type: type[OperationT], permission_type: RolePermissionType) -> OperationT:
    """
    Turn an operation given as a member of the operation type of a permission type, or as its value, into that member.

    :param operation: The operation as supplied by the caller, e.g. `ScopeOperationType.READ` or 'read' for a scope permission.
    :param operation_type: The operations the permission type grants, a subclass of `RolePermissionOperationType`.
    :param permission_type: The permission type, for the error messages.
    :raises InputValidationError: If the operation is not one the permission type grants.
    """
    if isinstance(operation, operation_type):
        return operation
    try:
        return operation_type(operation)
    except ValueError:
        raise InputValidationError("Operation '%s' is not supported on a '%s' permission, expected one of: %s."
                                   % (getattr(operation, "value", operation), permission_type.value, ", ".join(op.value for op in operation_type)))


@dataclass(frozen=True)
class PermissionRequest:
    """
    A request to perform an operation on a concrete resource, checked by :func:`has_permission`.

    Each checked permission type subclasses it with the fields naming the resource, sets `permission_type`
    and narrows `operation` to the operations of its handler, e.g. `ScopeOperationType` for scopes.
    A request is hashable, so that a decision on it can be cached, see :func:`permission_checker`.
    """
    permission_type: ClassVar[RolePermissionType]
    operation: RolePermissionOperationType


RequestT = TypeVar("RequestT", bound=PermissionRequest)


class PermissionTypeHandler:
    """
    Everything the generic permission functions need to know about one permission type.

    A subclass names the parameter holding the target of a permission (`target_attribute`) and its
    tables (`tables`), and implements how a permission is validated, granted, removed and listed.
    The methods writing to the database do not commit.
    """
    permission_type: ClassVar[RolePermissionType]
    # the parameter holding the target of a permission, also its key in a listing
    target_attribute: ClassVar[str]
    # how the target is called in messages
    target_label: ClassVar[str]
    # the `role_<type>_permission_map` models
    tables: ClassVar[tuple[Any, ...]]

    def normalize_target(self, target: Any, *, session: "Session") -> Any:
        """
        Validate a target given when granting or removing a permission, and turn it into what is stored.

        :raises InputValidationError: If the target is not valid for this permission type.
        """
        return target

    def normalize_parameters(self, parameters: "Mapping[str, Any]", *, removing: bool) -> dict[str, Any]:
        """
        Validate the parameters given, besides the target, when granting a permission, or when `removing` one.

        :raises InputValidationError: If a parameter is missing, unknown or not valid.
        """
        raise NotImplementedError

    def describe(self, target: Any, parameters: "Mapping[str, Any]") -> str:
        """Render a permission for a message, e.g. "'read' permission on scope pattern 'data*'"."""
        raise NotImplementedError

    def list_permissions(self, role: str, *, vo: Optional[str], session: "Session") -> list[dict[str, Any]]:
        """List the permissions of this type of a role, each with its target under `target_attribute` and its parameters."""
        raise NotImplementedError

    def add(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, vo: Optional[str], session: "Session") -> None:
        """Grant a permission to a role, see :func:`add_role_permission`."""
        raise NotImplementedError

    def remove(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, vo: Optional[str], session: "Session") -> int:
        """Remove permissions from a role, see :func:`delete_role_permission`, and tell how many were removed."""
        raise NotImplementedError


class CheckedPermissionTypeHandler(PermissionTypeHandler, Generic[RequestT]):
    """
    A permission type granting operations on a resource, checked against a :class:`PermissionRequest`, see :func:`has_permission`.

    Its permissions are stored in a single table (`model`) holding `role`, `operation` and the target
    column named by `target_attribute`, which together form its primary key: a permission is
    identified by its target and its `operation`, its only parameter. A subclass names its request
    (`request_type`) and the operations it grants (`operation_type`), its own subclass of
    `RolePermissionOperationType`, and implements :meth:`matches`.
    """
    # the `role_<type>_permission_map` model
    model: ClassVar[Any]
    request_type: ClassVar[type[PermissionRequest]]
    # the operations this permission type grants, e.g. `ScopeOperationType`
    operation_type: ClassVar[type[RolePermissionOperationType]]

    @property
    def target_column(self) -> "InstrumentedAttribute[Any]":
        """The column of `model` holding the target of a permission."""
        return getattr(self.model, self.target_attribute)

    def normalize_parameters(self, parameters: "Mapping[str, Any]", *, removing: bool) -> dict[str, Any]:
        unknown = sorted(set(parameters) - {OPERATION})
        if unknown:
            raise InputValidationError("Parameter(s) %s not supported on a '%s' permission, expected: %s."
                                       % (", ".join(unknown), self.permission_type.value, OPERATION))
        if parameters.get(OPERATION) is None:
            raise InputValidationError("'%s' must be given for a '%s' permission." % (OPERATION, self.permission_type.value))
        return {OPERATION: _normalize_operation(parameters[OPERATION], self.operation_type, self.permission_type)}

    def describe(self, target: Any, parameters: "Mapping[str, Any]") -> str:
        return "'%s' permission on %s '%s'" % (parameters[OPERATION].value, self.target_label, target)

    def list_permissions(self, role: str, *, vo: Optional[str], session: "Session") -> list[dict[str, Any]]:
        stmt = (
            select(self.target_column, self.model.operation)
            .where(self.model.role == role)
            .order_by(self.target_column, self.model.operation)
        )
        return [{self.target_attribute: target, OPERATION: operation.value} for target, operation in session.execute(stmt).all()]

    def add(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, vo: Optional[str], session: "Session") -> None:
        session.add(self.model(role=role, operation=parameters[OPERATION], **{self.target_attribute: target}))

    def remove(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, vo: Optional[str], session: "Session") -> int:
        stmt = delete(self.model).where(
            self.model.role == role,
            self.target_column == target,
            self.model.operation == parameters[OPERATION],
        )
        return cast(Any, session.execute(stmt)).rowcount

    def granted_targets(self, account: "InternalAccount", operation: RolePermissionOperationType, *, session: "Session") -> list[Any]:
        """
        List the targets on which the account's roles grant an operation.

        Role assignments which are not active, i.e. whose `activates_at` is in the future or whose `expires_at` is in the past, are ignored.
        """
        stmt = (
            select(self.target_column)
            .select_from(models.AccountRoleAssociation)
            .join(self.model, self.model.role == models.AccountRoleAssociation.role)
            .where(
                models.AccountRoleAssociation.account == account,
                self.model.operation == operation,
                _assignment_active(),
            )
        )
        return list(session.execute(stmt).scalars())

    def matches(self, request: RequestT, target: Any, *, session: "Session") -> bool:
        """Tell whether a stored target covers the resource of the request."""
        raise NotImplementedError

    def implicit_access(self, account: "InternalAccount", request: RequestT, *, session: "Session") -> bool:
        """Tell whether the account may perform the request without holding any role, e.g. as the owner of the resource."""
        return False

    def access_without_rbac(self, request: RequestT) -> bool:
        """
        Tell whether the request is granted while RBAC is disabled, see :func:`is_rbac_enabled`.

        No role grants anything then, so this stands for what Rucio grants without RBAC, besides
        admin/root privileges and implicit access. Nothing by default.
        """
        return False


_PERMISSION_HANDLERS: dict[RolePermissionType, PermissionTypeHandler] = {}


def _register_permission_handler(handler_class: "type[PermissionTypeHandler]") -> "type[PermissionTypeHandler]":
    """Class decorator registering the handler of a permission type, see :class:`PermissionTypeHandler`."""
    _PERMISSION_HANDLERS[handler_class.permission_type] = handler_class()
    return handler_class


def _permission_handler(permission_type: Optional[Union[RolePermissionType, str]]) -> PermissionTypeHandler:
    """
    Find the handler of a permission type, given as a `RolePermissionType` or as its value (e.g. 'scope').

    :raises InputValidationError: If no handler is registered for the permission type.
    """
    try:
        return _PERMISSION_HANDLERS[RolePermissionType(permission_type)]
    except (ValueError, KeyError):
        raise InputValidationError("Permission type '%s' is not supported, expected one of: %s."
                                   % (getattr(permission_type, "value", permission_type), ", ".join(sorted(t.value for t in _PERMISSION_HANDLERS))))


def _request_handler(request: PermissionRequest) -> CheckedPermissionTypeHandler[Any]:
    """
    Find the handler a permission request is checked by.

    :raises InputValidationError: If the request is not one of a registered permission type which is checked against requests.
    """
    handler = _permission_handler(getattr(type(request), "permission_type", None))
    if not isinstance(handler, CheckedPermissionTypeHandler):
        raise InputValidationError("'%s' permissions are not checked against requests." % handler.permission_type.value)
    if not isinstance(request, handler.request_type):
        raise InputValidationError("A '%s' request must be a %s, got '%s'." % (handler.permission_type.value, handler.request_type.__name__, type(request).__name__))
    if not isinstance(request.operation, handler.operation_type):
        raise InputValidationError("A '%s' request must ask for a %s, got '%s'." % (handler.permission_type.value, handler.operation_type.__name__, request.operation))
    return handler


# --- Scopes -----------------------------------------------------------------------------------

# the only wildcard a scope pattern may use, see `_validate_scope_pattern`
SCOPE_WILDCARD = "*"


def _validate_scope_pattern(scope_pattern: str) -> str:
    """
    Validate a scope pattern of a role permission.

    A '*' is the only wildcard, and it is only accepted on its own ('*', every scope) or at
    the end of a scope ('data*', every scope starting with 'data'). A leading or embedded
    wildcard is refused, since it cannot be matched unambiguously against a concrete scope.
    The pattern is not checked against the scopes which currently exist: it is stored as
    given, and a scope created later is covered by it immediately.

    :param scope_pattern: The scope pattern as supplied by the caller.
    :returns: The scope pattern, stripped of surrounding whitespace.
    :raises InputValidationError: If the scope pattern is not a string, is empty, or uses the wildcard other than as a trailing '*'.
    """
    if not isinstance(scope_pattern, str):
        raise InputValidationError("scope pattern must be a string, got '%s'." % type(scope_pattern).__name__)

    scope_pattern = scope_pattern.strip()
    if not scope_pattern:
        raise InputValidationError("scope pattern must not be empty.")

    if scope_pattern.count(SCOPE_WILDCARD) > 1 or (SCOPE_WILDCARD in scope_pattern and not scope_pattern.endswith(SCOPE_WILDCARD)):
        raise InputValidationError(
            "scope pattern '%s' is not supported, a '*' may only stand on its own or close a scope, as in 'data*'." % scope_pattern)

    return scope_pattern


def _scope_pattern_matches(scope: "InternalScope", scope_pattern: str) -> bool:
    """
    Tell whether a concrete scope matches a role's scope pattern.

    The pattern is matched against the external (human-readable) name of the scope: '*' on
    its own matches every scope, a pattern ending in '*' matches every scope whose external
    name starts with the literal part that precedes it, and a pattern without '*' matches
    only that exact scope.

    :param scope: The concrete scope to check.
    :param scope_pattern: The scope pattern of a role permission, as stored.
    :returns: True if the scope matches the pattern.
    """
    external = str(scope.external)
    if scope_pattern.endswith(SCOPE_WILDCARD):
        return external.startswith(scope_pattern[:-1])
    return external == scope_pattern


@dataclass(frozen=True)
class ScopePermissionRequest(PermissionRequest):
    """A request to perform `operation` on the content of `scope`."""
    permission_type: ClassVar[RolePermissionType] = RolePermissionType.SCOPE
    operation: ScopeOperationType
    scope: InternalScope


@_register_permission_handler
class ScopePermissionHandler(CheckedPermissionTypeHandler[ScopePermissionRequest]):
    """
    Operations on scopes, granted on scope patterns, see :func:`_validate_scope_pattern`.

    The operations are those of `ScopeOperationType`: 'read', 'write' and 'delete'. The owner of a scope may perform any operation on it without holding any role.
    """
    permission_type = RolePermissionType.SCOPE
    model = models.RoleScopePermissionAssociation
    tables = (models.RoleScopePermissionAssociation,)
    request_type = ScopePermissionRequest
    operation_type = ScopeOperationType
    target_attribute = "scope_pattern"
    target_label = "scope pattern"

    def normalize_target(self, target: Any, *, session: "Session") -> str:
        return _validate_scope_pattern(target)

    def matches(self, request: ScopePermissionRequest, target: str, *, session: "Session") -> bool:
        return _scope_pattern_matches(request.scope, target)

    def implicit_access(self, account: "InternalAccount", request: ScopePermissionRequest, *, session: "Session") -> bool:
        return is_scope_owner(scope=request.scope, account=account, session=session)

    def access_without_rbac(self, request: ScopePermissionRequest) -> bool:
        # without RBAC every scope may be read, while writing and deleting are left to admin/root privileges and scope ownership
        return request.operation == ScopeOperationType.READ


# --- Limits -----------------------------------------------------------------------------------

# the length of `role_global_limit_permission_map.rse_expression`
RSE_EXPRESSION_LENGTH = 3000


class LimitLocality(Enum):
    """
    What a limit caps, like the local and global account limits.

    Its value is also the parameter of a limit permission giving its bytes, see :class:`LimitPermissionHandler`.
    """
    # the usage on one RSE
    LOCAL = 'local'
    # the usage summed over the RSEs an expression matches
    GLOBAL = 'global'


def _validate_rse_expression(rse_expression: str, *, session: "Session") -> str:
    """
    Validate the RSE expression of a limit.

    The expression must follow the RSE expression syntax, but it does not have to match any RSE,
    see :class:`LimitPermissionHandler` for what it must match.

    :param rse_expression: The RSE expression as supplied by the caller.
    :param session: The database session.
    :returns: The RSE expression, stripped of surrounding whitespace.
    :raises InputValidationError: If the RSE expression is not a string, is empty, is too long or does not follow the RSE expression syntax.
    """
    if not isinstance(rse_expression, str):
        raise InputValidationError("RSE expression must be a string, got '%s'." % type(rse_expression).__name__)

    rse_expression = rse_expression.strip()
    if not rse_expression:
        raise InputValidationError("RSE expression must not be empty.")
    if len(rse_expression) > RSE_EXPRESSION_LENGTH:
        raise InputValidationError("RSE expression must not be longer than %d characters." % RSE_EXPRESSION_LENGTH)

    try:
        parse_expression(rse_expression, session=session)
    except InvalidRSEExpression as error:
        # the parser refuses an expression which matches no RSE the same way as a malformed one, only the latter is refused here
        if "empty set" not in str(error):
            raise InputValidationError("RSE expression '%s' is not valid: %s" % (rse_expression, error))

    return rse_expression


def _resolve_rse_ids(rse_expression: str, vo: Optional[str], *, session: "Session") -> frozenset[str]:
    """
    Resolve the RSE expression of a limit into the ids of the RSEs it currently matches.

    :param rse_expression: The RSE expression, as stored.
    :param vo: Only resolve the RSEs of this VO, or those of every VO if None.
    :param session: The database session.
    :returns: The ids of the matching RSEs, empty if the expression currently matches none.
    """
    try:
        rses = parse_expression(rse_expression, filter_={'vo': vo} if vo else None, session=session)
    except InvalidRSEExpression:
        return frozenset()
    return frozenset(rse['id'] for rse in rses)


def _normalize_bytes(value: Any, attribute: str) -> int:
    """
    Validate a limit given in bytes.

    No cap is never implied: it must be given explicitly as `ROLE_QUOTA_NOCAP`, so that None (e.g.
    a null in a request body) is refused rather than taken for it.

    :param value: The limit as supplied by the caller: a non-negative integer, or `ROLE_QUOTA_NOCAP` for no cap.
    :param attribute: The name of the limit, for the error messages.
    :returns: The limit to store.
    :raises InputValidationError: If the limit is neither a non-negative integer nor `ROLE_QUOTA_NOCAP`.
    """
    # a bool is an int, but certainly not a size
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("'%s' must be a number of bytes, or %d for no cap, got '%s'." % (attribute, ROLE_QUOTA_NOCAP, type(value).__name__))
    if value < 0 and value != ROLE_QUOTA_NOCAP:
        raise InputValidationError("'%s' must not be negative, got %d. Use %d for no cap." % (attribute, value, ROLE_QUOTA_NOCAP))
    return value


@_register_permission_handler
class LimitPermissionHandler(PermissionTypeHandler):
    """
    Limits on RSEs, like the account limits: how many bytes each account holding the role may use.

    A limit is either local or global, given in bytes under its locality ('local' or 'global'),
    `ROLE_QUOTA_NOCAP` meaning no cap:

    - a local limit caps the usage on a single RSE, like a local account limit. Its RSE expression
      must match exactly one RSE, e.g. its name; it is stored by RSE and listed under its name;
    - a global limit caps the usage summed over the RSEs an expression matches, like a global
      account limit. Its expression must match several RSEs when it is set; it is stored as given
      and resolved whenever it is applied, so that it also covers the RSEs it matches later.

    A local and a global limit are therefore never set at once. Setting a limit which exists already
    overwrites it. Removing the limits on an RSE expression removes the local limit on the RSE it
    matches and the global limit on that very expression; the localities set to true restrict
    which, both being looked for if none is given. The RSEs are those of the VO given, of every VO
    if None.
    """
    permission_type = RolePermissionType.LIMIT
    tables = (models.RoleLocalLimitPermissionAssociation, models.RoleGlobalLimitPermissionAssociation)
    target_attribute = "rse_expression"
    target_label = "RSE expression"

    def normalize_target(self, target: Any, *, session: "Session") -> str:
        return _validate_rse_expression(target, session=session)

    def normalize_parameters(self, parameters: "Mapping[str, Any]", *, removing: bool) -> dict[str, Any]:
        localities = [locality.value for locality in LimitLocality]
        unknown = sorted(set(parameters) - set(localities))
        if unknown:
            raise InputValidationError("Parameter(s) %s not supported on a '%s' permission, expected: %s."
                                       % (", ".join(unknown), self.permission_type.value, " or ".join(localities)))
        if not removing:
            if len(parameters) != 1:
                raise InputValidationError("Exactly one of %s must be given to set a limit: a local limit is set on one RSE, a global one on an expression matching several."
                                           % " or ".join("'%s'" % name for name in localities))
            return {name: _normalize_bytes(value, name) for name, value in parameters.items()}

        for name, value in parameters.items():
            if not isinstance(value, bool):
                raise InputValidationError("'%s' must be true or false to remove a limit, got '%s'." % (name, type(value).__name__))
        if parameters and not any(parameters.values()):
            raise InputValidationError("At least one of %s must be true to remove a limit." % " or ".join("'%s'" % name for name in localities))
        # True for a locality explicitly asked for, False for one only looked for since none was given
        return {name: bool(parameters.get(name)) for name in localities if parameters.get(name, not parameters)}

    def describe(self, target: Any, parameters: "Mapping[str, Any]") -> str:
        localities = "/".join(locality.value for locality in LimitLocality if locality.value in parameters)
        return "%s limit on %s '%s'" % (localities, self.target_label, target)

    def list_permissions(self, role: str, *, vo: Optional[str], session: "Session") -> list[dict[str, Any]]:
        local, global_ = models.RoleLocalLimitPermissionAssociation, models.RoleGlobalLimitPermissionAssociation
        stmt = (
            select(models.RSE.rse, local.bytes)
            .select_from(local)
            .join(models.RSE, models.RSE.id == local.rse_id)
            .where(local.role == role, *([models.RSE.vo == vo] if vo else []))
        )
        limits = [{self.target_attribute: rse, LimitLocality.LOCAL.value: bytes_} for rse, bytes_ in session.execute(stmt).all()]

        stmt = select(global_.rse_expression, global_.bytes).where(global_.role == role)
        limits.extend({self.target_attribute: rse_expression, LimitLocality.GLOBAL.value: bytes_} for rse_expression, bytes_ in session.execute(stmt).all())
        return sorted(limits, key=lambda limit: limit[self.target_attribute])

    def add(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, vo: Optional[str], session: "Session") -> None:
        rse_ids = _resolve_rse_ids(target, vo, session=session)
        matched = len(rse_ids)
        if LimitLocality.LOCAL.value in parameters:
            if matched != 1:
                raise InputValidationError("A local limit is set on a single RSE, but RSE expression '%s' matches %s. Set a local limit on each RSE%s."
                                           % (target, "no RSE" if not matched else "%d RSEs" % matched, ", or a global limit on the expression" if matched else ""))
            [rse_id] = rse_ids
            session.merge(models.RoleLocalLimitPermissionAssociation(role=role, rse_id=rse_id, bytes=parameters[LimitLocality.LOCAL.value]))
        else:
            if matched < 2:
                raise InputValidationError("A global limit caps the usage summed over several RSEs, but RSE expression '%s' matches %s.%s"
                                           % (target, "no RSE" if not matched else "a single one", " Set a local limit on it instead." if matched else ""))
            session.merge(models.RoleGlobalLimitPermissionAssociation(role=role, rse_expression=target, bytes=parameters[LimitLocality.GLOBAL.value]))

    def remove(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, vo: Optional[str], session: "Session") -> int:
        local, global_ = models.RoleLocalLimitPermissionAssociation, models.RoleGlobalLimitPermissionAssociation
        removed = 0
        if LimitLocality.LOCAL.value in parameters:
            rse_ids = _resolve_rse_ids(target, vo, session=session)
            if len(rse_ids) == 1:
                removed += cast(Any, session.execute(delete(local).where(local.role == role, local.rse_id.in_(rse_ids)))).rowcount
            elif parameters[LimitLocality.LOCAL.value]:
                raise InputValidationError("A local limit is set on a single RSE, but RSE expression '%s' does not match exactly one." % target)
        if LimitLocality.GLOBAL.value in parameters:
            removed += cast(Any, session.execute(delete(global_).where(global_.role == role, global_.rse_expression == target))).rowcount
        return removed


# ----------------------------------------------------------------------------------------------
# Role permissions
# ----------------------------------------------------------------------------------------------

def _split_target(handler: PermissionTypeHandler, parameters: "Mapping[str, Any]") -> tuple[Any, dict[str, Any]]:
    """
    Take the target of a permission out of its parameters.

    :returns: The target, and the other parameters.
    :raises InputValidationError: If the target is not given.
    """
    parameters = dict(parameters)
    if handler.target_attribute not in parameters:
        raise InputValidationError("'%s' must be given for a '%s' permission." % (handler.target_attribute, handler.permission_type.value))
    return parameters.pop(handler.target_attribute), parameters


def _violates_table_constraint(error: IntegrityError, handler: PermissionTypeHandler, suffix: str) -> bool:
    """Tell whether the IntegrityError comes from the constraint of one of the tables of a permission type, e.g. its '_PK'."""
    return any(_violates_constraint(error, "%s_%s" % (table.__tablename__.upper(), suffix)) for table in handler.tables)


def list_role_permissions(role: str, vo: Optional[str] = None, *, session: "Session") -> list[dict[str, Any]]:
    """
    List the permissions granted to a role, of every type.

    Each permission is given as its `type`, its target under the key its type names it by, and its
    parameters, in the shape it is granted with, see :func:`add_role_permission`: e.g. a 'scope_pattern'
    and an 'operation' for a scope permission, an 'rse_expression' and its 'local' or 'global' bytes
    for a limit, a local limit being listed under the name of its RSE.

    :param role: The role whose permissions to list.
    :param vo: Only list the local limits on the RSEs of this VO, or on those of every VO if None.
    :param session: The database session.
    :raises RoleNotFound: If the role does not exist.
    """
    _ensure_role_exists(role, session)

    return [
        {"type": permission_type.value, **permission}
        for permission_type, handler in _PERMISSION_HANDLERS.items()
        for permission in handler.list_permissions(role, vo=vo, session=session)
    ]


def add_role_permission(
        role: str,
        permission_type: Union[RolePermissionType, str],
        parameters: "Mapping[str, Any]",
        force: bool = False,
        *,
        vo: Optional[str] = None,
        session: "Session") -> None:
    """
    Grant a role a permission of a type.

        add_role_permission(role, RolePermissionType.SCOPE, {'scope_pattern': 'data*', 'operation': 'read'}, session=session)
        add_role_permission(role, RolePermissionType.LIMIT, {'rse_expression': 'tier=1', 'global': 10**13}, session=session)

    A scope permission which exists already is refused, a limit which exists already is overwritten.

    :param role: The role to grant the permission to.
    :param permission_type: The type of the permission, e.g. `RolePermissionType.SCOPE`.
    :param parameters: The target of the permission under the key its type names it by, e.g. 'scope_pattern',
                       and its parameters, see the `PermissionTypeHandler` of the type.
    :param force: Grant the permission even if the role is locked.
    :param vo: The VO the RSE expression of a limit is resolved in, every VO if None.
    :param session: The database session.
    :raises InputValidationError: If the permission type, the target or a parameter is not valid.
    :raises RoleLocked: If the role is locked and `force` is not given.
    :raises RoleNotFound: If the role does not exist.
    :raises Duplicate: If the role already has that permission, and its type refuses it.
    :raises RoleReserved: If the role is reserved, whether or not `force` is given.
    """
    handler = _permission_handler(permission_type)
    target, parameters = _split_target(handler, parameters)
    target = handler.normalize_target(target, session=session)
    parameters = handler.normalize_parameters(parameters, removing=False)
    if is_reserved_role(role):
        raise RoleReserved("Role '%s' is reserved, so no permission can be granted to it." % role)
    _ensure_unlocked(role, force, session)

    try:
        handler.add(role, target, parameters, vo=vo, session=session)
        session.commit()
    except IntegrityError as error:
        session.rollback()
        described = handler.describe(target, parameters)
        if _violates_table_constraint(error, handler, "ROLE_FK"):
            raise RoleNotFound("Role '%s' does not exist." % role)
        if _violates_table_constraint(error, handler, "PK"):
            raise Duplicate("Role '%s' already has %s." % (role, described))
        raise Duplicate("Either role '%s' does not exist, or it already has %s." % (role, described))


def delete_role_permission(
        role: str,
        permission_type: Union[RolePermissionType, str],
        parameters: "Mapping[str, Any]",
        force: bool = False,
        *,
        vo: Optional[str] = None,
        session: "Session") -> int:
    """
    Remove permissions of a type from a role.

        delete_role_permission(role, RolePermissionType.SCOPE, {'scope_pattern': 'data*', 'operation': 'read'}, session=session)
        delete_role_permission(role, RolePermissionType.LIMIT, {'rse_expression': 'tier=1', 'global': True}, session=session)

    :param role: The role to remove the permissions from.
    :param permission_type: The type of the permissions, e.g. `RolePermissionType.SCOPE`.
    :param parameters: The target of the permissions under the key its type names it by, e.g. 'scope_pattern',
                       and the parameters identifying them, see the `PermissionTypeHandler` of the type.
    :param force: Remove the permissions even if the role is locked.
    :param vo: The VO the RSE expression of a local limit is resolved in, every VO if None.
    :param session: The database session.
    :returns: The number of permissions removed, e.g. both the local and the global limit on an RSE expression.
    :raises InputValidationError: If the permission type, the target or a parameter is not valid.
    :raises RoleLocked: If the role is locked and `force` is not given.
    :raises RolePermissionNotFound: If the role does not have any such permission.
    :raises RoleReserved: If the role is reserved, whether or not `force` is given.
    """
    handler = _permission_handler(permission_type)
    target, parameters = _split_target(handler, parameters)
    target = handler.normalize_target(target, session=session)
    parameters = handler.normalize_parameters(parameters, removing=True)
    if is_reserved_role(role):
        raise RoleReserved("Role '%s' is reserved, so no permission can be removed from it." % role)
    _ensure_unlocked(role, force, session)

    removed = handler.remove(role, target, parameters, vo=vo, session=session)
    if not removed:
        session.rollback()
        raise RolePermissionNotFound("Either role '%s' does not exist, or it does not have %s." % (role, handler.describe(target, parameters)))
    session.commit()
    return removed


# ----------------------------------------------------------------------------------------------
# Permission checks
# ----------------------------------------------------------------------------------------------

def has_role_permission(account: "InternalAccount", request: PermissionRequest, *, session: "Session") -> bool:
    """
    Tell whether the account's roles grant it the request, according to the RBAC tables only.

    At least one permission covering the request must come from a role assignment which is active:
    activated already and not expired yet. Neither admin/root privileges nor implicit access (e.g. scope ownership) are
    considered here, see :func:`has_permission` for that. If RBAC is disabled, the RBAC tables are not looked at and the
    request is decided by its permission type instead, see :meth:`CheckedPermissionTypeHandler.access_without_rbac`.

    :param account: The account to check.
    :param request: What the account asks to do, e.g. a :class:`ScopePermissionRequest`.
    :param session: The database session.
    :raises InputValidationError: If the request is not one of a registered permission type checked against requests.
    """
    handler = _request_handler(request)
    if not is_rbac_enabled():
        return handler.access_without_rbac(request)
    return any(handler.matches(request, target, session=session) for target in handler.granted_targets(account, request.operation, session=session))


def has_permission(account: "InternalAccount", request: PermissionRequest, *, session: "Session") -> bool:
    """
    Tell whether the account may perform the request, of any checked permission type.

    This is the single entry point of a permission check: an account may perform the request if
    it is root or admin, if it has implicit access to the resource (e.g. as the owner of a scope),
    or if one of its roles grants it, see :func:`has_role_permission`.

        has_permission(account, ScopePermissionRequest(operation=ScopeOperationType.READ, scope=scope), session=session)

    :param account: The account to check.
    :param request: What the account asks to do, e.g. a :class:`ScopePermissionRequest`.
    :param session: The database session.
    :raises InputValidationError: If the request is not one of a registered permission type checked against requests.
    """
    handler = _request_handler(request)
    if _is_root_or_admin(account, session):
        return True
    if handler.implicit_access(account, request, session=session):
        return True
    return has_role_permission(account, request, session=session)


def permission_checker(*, account: "InternalAccount", session: "Session") -> "Callable[[PermissionRequest], bool]":
    """
    Build a callable telling whether the account may perform a request, as :func:`has_permission` does.

    This is meant for checking many requests in a row, e.g. to filter a listing: admin/root
    privileges are looked up once, the targets granted by the account's roles once per permission type
    and operation, and each distinct request is decided once, for the lifetime of the callable.

    :param account: The account for which to check the requests.
    :param session: The database session.
    :returns: A callable taking a request and returning True if the account may perform it.
    """
    privileged = _is_root_or_admin(account, session)
    rbac_enabled = is_rbac_enabled()
    granted: dict[tuple[RolePermissionType, RolePermissionOperationType], list[Any]] = {}
    decisions: dict[PermissionRequest, bool] = {}

    def _decide(request: PermissionRequest) -> bool:
        handler = _request_handler(request)
        if privileged or handler.implicit_access(account, request, session=session):
            return True
        if not rbac_enabled:
            return handler.access_without_rbac(request)

        key = (handler.permission_type, request.operation)
        if key not in granted:
            granted[key] = handler.granted_targets(account, request.operation, session=session)
        return any(handler.matches(request, target, session=session) for target in granted[key])

    def _check(request: PermissionRequest) -> bool:
        if request not in decisions:
            decisions[request] = _decide(request)
        return decisions[request]

    return _check


def is_filter_disabled(account: "InternalAccount", filter_name: str, *, session: "Session") -> bool:
    """
    Tell whether the policy package disables a filter for the account.

    Filtering is the default: a filter is only disabled if the policy package of the account's VO
    lists it, from the most general to the most specific, in:

    - its `disable_filters_for_all_accounts`: for every account of the VO regardless of its roles,
      even for an account holding no role at all;
    - its `disable_filters_for_all_roles`: for every account holding at least one role;
    - the 'disable-filters' of a role: for every account holding that role.

    An account only holds a role through an assignment which is active. A reserved role
    never disables a filter, since the policy package cannot define it. The filters are documented
    in the role module of the policy package.

    :param account: The account the listing is filtered for.
    :param filter_name: The name of the filter, e.g. 'list_scopes'.
    :param session: The database session.
    :returns: True if the listing must not be filtered for the account.
    """
    if not is_rbac_enabled():
        return True

    if filter_name in permission.get_disabled_filters_for_all_accounts(vo=account.vo):
        return True

    if filter_name in permission.get_disabled_filters_for_all_roles(vo=account.vo):
        # any role disables the filter, so there is no need to look at the role definitions
        role_disables_filter = models.AccountRoleAssociation.role.not_in(list(RESERVED_ROLES))
    else:
        roles = [
            role for role, definition in permission.get_roles(vo=account.vo).items()
            if filter_name in definition.get('disable_filters', ()) and not is_reserved_role(role)
        ]
        if not roles:
            return False
        role_disables_filter = models.AccountRoleAssociation.role.in_(roles)

    stmt = select(models.AccountRoleAssociation.role).where(
        models.AccountRoleAssociation.account == account,
        role_disables_filter,
        _assignment_active(),
    )
    return session.execute(stmt).first() is not None


def scope_access_checker(
    *,
    account: "InternalAccount",
    session: "Session",
    operation: ScopeOperationType = ScopeOperationType.READ,
    skip_filtering: bool = False,
) -> "Callable[[Optional[InternalScope]], bool]":
    """
    Build a callable telling whether the account may perform an operation on a given scope, see :func:`permission_checker`.

    This is meant for responses where the scope is not stored under a single dictionary key
    (e.g. 'scope:name' strings or nested dictionaries), for which :func:`filter_iterable_by_scope_access` does not fit.

    :param account: The account for which to check access.
    :param session: The database session.
    :param operation: The type of operation to check access for.
    :param skip_filtering: Grant access to every scope, without checking it, see :func:`is_filter_disabled`.
    :returns: A callable taking a scope and returning True if the account may access it. A scope that is None or not an InternalScope is refused, unless `skip_filtering` is given.
    """
    if skip_filtering or not is_rbac_enabled():
        return lambda scope: True

    check = permission_checker(account=account, session=session)

    def _can_access(scope: "Optional[InternalScope]") -> bool:
        if scope is None or not isinstance(scope, InternalScope):
            return False
        return check(ScopePermissionRequest(operation=operation, scope=scope))

    return _can_access


def filter_iterable_by_scope_access(
    items: "Iterable[dict[str, Any]]",
    *,
    account: "InternalAccount",
    session: "Session",
    operation: ScopeOperationType = ScopeOperationType.READ,
    scope_keyword: str = "scope",
    skip_filtering: bool = False,
) -> "Iterator[dict[str, Any]]":
    """
    Yield only items whose scope the account may perform an operation on, see :func:`scope_access_checker`.

    :param items: An iterable of dictionaries representing items with associated scopes.
    :param account: The account for which to check access.
    :param session: The database session.
    :param operation: The type of operation to check access for.
    :param scope_keyword: The key in the item dictionaries that contains the associated scope.
    :param skip_filtering: Yield every item, without checking its scope, see :func:`is_filter_disabled`.
    :returns: An iterator over the items that the account has access to.
    """
    can_access = scope_access_checker(account=account, session=session, operation=operation, skip_filtering=skip_filtering)

    for item in items:
        if can_access(item.get(scope_keyword)):
            yield item


# ----------------------------------------------------------------------------------------------
# Synchronisation reports
# ----------------------------------------------------------------------------------------------

def _format_table(headers: list[str], rows: list[list[Any]], indent: str = "  ") -> list[str]:
    """Render a small left-aligned table as lines, or a placeholder if there is nothing to show."""
    if not rows:
        return ["%s(none)" % indent]

    cells = [["" if cell is None else str(cell) for cell in row] for row in rows]
    widths = [max([len(header)] + [len(row[index]) for row in cells]) for index, header in enumerate(headers)]
    lines = [
        indent + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        indent + "-+-".join("-" * width for width in widths),
    ]
    lines.extend(indent + " | ".join(row[index].ljust(widths[index]) for index in range(len(headers))) for row in cells)
    return lines


def _print_table(headers: list[str], rows: list[list[Any]], indent: str = "  ") -> None:
    """Print a small left-aligned table, or a placeholder if there is nothing to show."""
    for line in _format_table(headers, rows, indent):
        print(line)


def _format_expires_at(expires_at: Optional[datetime]) -> str:
    """Render the expiry date of a role assignment, 'never' if it does not expire."""
    return "never" if expires_at is None else str(expires_at)


# ----------------------------------------------------------------------------------------------
# Synchronisation with the policy package
# ----------------------------------------------------------------------------------------------

def sync_roles_from_policy_package_dry_run(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronizes the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an unlocked role (`assignable` True and
    `locked` False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not locked. A locked role
    (`locked` True) is never touched by the policy package, whether or not
    the policy package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`. A reserved role is never touched either, see
    :func:`setup_reserved_roles`.

    This is a dry run: it reports what the synchronisation would do and leaves the database
    untouched.

    :param vo: The VO whose policy package defines the roles.
    :param session: The database session.
    """
    print("Syncing roles... (dry run, nothing is written to the database)")

    # Step 1: Retrieve Roles from the policy package
    roles = permission.get_roles(vo=vo)

    print()
    print("Step 1: Retrieve Roles from the policy package")
    _print_table(["ROLE", "DESCRIPTION"], [[role, definition.get("description") or ""] for role, definition in sorted(roles.items())])

    # Step 2: Retrieve all roles currently known to Rucio
    current = {entry["role"]: entry for entry in list_roles(session=session)}

    print()
    print("Step 2: Retrieve all roles known to Rucio")
    _print_table(
        ["ROLE", "DESCRIPTION", "LOCKED"],
        [[role, entry["description"] or "", "yes" if entry["locked"] else "no"] for role, entry in sorted(current.items())],
    )

    print()
    print("Step 3: What the synchronisation would do")
    created, updated, unchanged, skipped_locked, skipped_reserved, deleted = 0, 0, 0, 0, 0, 0

    for role in sorted(roles):
        description = _normalize_description(roles[role].get("description"))

        if is_reserved_role(role):
            skipped_reserved += 1
            print("  Role '%s' is reserved, so it would be left untouched." % role)
            continue

        if role not in current:
            created += 1
            print("  Role '%s' does not exist yet, so it would be created with description %r." % (role, description))
            continue

        if current[role]["locked"]:
            skipped_locked += 1
            print("  Role '%s' is locked, so it would be left untouched." % role)
            continue

        if current[role]["description"] != description:
            updated += 1
            print("  Role '%s': description would change from %r to %r." % (role, current[role]["description"], description))
        else:
            unchanged += 1
            print("  Role '%s' is already in line with the policy package." % role)

    # a role which is not locked and which the policy package does not define goes, including
    # one that was created by hand through the CLI; a locked role is out of the policy
    # package's reach entirely, so it is left untouched even if the policy package does not define it
    for role in sorted(set(current) - set(roles)):
        if is_reserved_role(role):
            skipped_reserved += 1
            print("  Role '%s' is not defined by the policy package but is reserved, so it would be left untouched." % role)
        elif current[role]["locked"]:
            skipped_locked += 1
            print("  Role '%s' is not defined by the policy package but is locked, so it would be left untouched." % role)
        else:
            deleted += 1
            print("  Role '%s' is not defined by the policy package, so it would be deleted." % role)

    print()
    print("Summary: would create %d role(s), update %d, delete %d, leave %d unchanged, leave %d locked and %d reserved role(s) untouched."
          % (created, updated, deleted, unchanged, skipped_locked, skipped_reserved))


def sync_roles_from_policy_package(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronize the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an unlocked role (`assignable` True and
    `locked` False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not locked. A locked role
    (`locked` True) is never touched here, whether or not the policy
    package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`. Neither is a reserved role, see :func:`setup_reserved_roles`.
    A role which is not locked and which the policy
    package does not define is deleted, together with its permissions and account assignments.

    The whole synchronisation is a single transaction, so either all of it is applied or none of
    it is. See :func:`sync_roles_from_policy_package_dry_run` to report the changes instead of
    applying them.

    :param vo: The VO whose policy package defines the roles.
    :param session: The database session.
    """
    print("Syncing the roles of VO '%s' with the policy package..." % vo)

    # Step 1: Retrieve Roles from the policy package
    roles = permission.get_roles(vo=vo)

    # Step 2: Retrieve all roles currently known to Rucio
    current = {entry["role"]: entry for entry in list_roles(session=session)}

    created, updated, unchanged, skipped_locked, skipped_reserved, deleted = 0, 0, 0, 0, 0, 0
    revoked, unassigned = 0, 0

    try:
        # Step 3: Create the roles of the policy package and bring the existing, unlocked
        # ones in line with it. A locked or reserved role is left untouched.
        for role in sorted(roles):
            description = _normalize_description(roles[role].get("description"))

            if is_reserved_role(role):
                skipped_reserved += 1
                print("  Role '%s' is reserved, so it is left untouched." % role)
                continue

            if role not in current:
                session.add(models.Roles(role=role, description=description, assignable=True, locked=False))
                created += 1
                print("  Role '%s' created with description %r." % (role, description))
                continue

            if current[role]["locked"]:
                skipped_locked += 1
                print("  Role '%s' is locked, so it is left untouched." % role)
                continue

            if current[role]["description"] != description:
                session.execute(update(models.Roles).where(models.Roles.role == role).values(description=description))
                updated += 1
                print("  Role '%s': description changed from %r to %r." % (role, current[role]["description"], description))
            else:
                unchanged += 1

        # Step 4: Delete the roles the policy package does not define any more, including the
        # ones that were created by hand through the CLI, unless they are locked, which
        # takes them entirely out of the policy package's reach. Neither foreign key to `roles`
        # can be relied on to cascade, so each deleted role takes its permissions and its account
        # assignments along explicitly.
        for role in sorted(set(current) - set(roles)):
            if is_reserved_role(role):
                skipped_reserved += 1
                print("  Role '%s' is not defined by the policy package but is reserved, so it is left untouched." % role)
                continue

            if current[role]["locked"]:
                skipped_locked += 1
                print("  Role '%s' is not defined by the policy package but is locked, so it is left untouched." % role)
                continue

            role_unassigned = _remove_accounts_from_role(role, session=session)
            deleted += 1
            unassigned += role_unassigned
            print("  Role '%s' is not defined by the policy package, so it was deleted with its %d account assignment(s)."
                  % (role, role_unassigned))

        session.commit()
    except Exception:
        session.rollback()
        print("  The synchronisation failed, so nothing reported above was applied.")
        raise

    print()
    print("Summary: created %d role(s), updated %d, deleted %d, left %d unchanged, left %d locked and %d reserved role(s) untouched; removed %d permission(s) and %d account assignment(s) with the deleted roles."
          % (created, updated, deleted, unchanged, skipped_locked, skipped_reserved, revoked, unassigned))


# ----------------------------------------------------------------------------------------------
# Synchronisation with an IdP
# ----------------------------------------------------------------------------------------------

def _parse_idp_roles(roles: Any) -> dict[str, Optional[datetime]]:
    """
    Normalise the roles supplied by an IdP into a mapping of role name to expiry date.

    Accepted forms are a mapping of role name to expiry date, or an iterable of role names
    and/or dictionaries carrying a 'role' (or 'name') and an optional 'expires_at'. An
    expiry date of None means that the assignment does not expire.

    :param roles: The roles as supplied by the IdP.
    :returns: The expiry date of each role the account should hold.
    :raises InputValidationError: If the roles are not in one of the accepted forms.
    """
    if roles is None:
        return {}

    if isinstance(roles, Mapping):
        return {str(role): _normalize_date(expires_at, "expires_at") for role, expires_at in roles.items()}

    if isinstance(roles, (str, bytes)) or not isinstance(roles, Iterable):
        raise InputValidationError("The roles supplied by the IdP must be a mapping or a list, got '%s'." % type(roles).__name__)

    parsed: dict[str, Optional[datetime]] = {}
    for entry in roles:
        if isinstance(entry, str):
            parsed[entry.strip()] = None
            continue

        if not isinstance(entry, Mapping):
            raise InputValidationError("The role %r supplied by the IdP is neither a name nor a mapping." % (entry,))

        role = entry.get("role", entry.get("name"))
        if not isinstance(role, str) or not role.strip():
            raise InputValidationError("The role %r supplied by the IdP has no name." % (entry,))

        parsed[role.strip()] = _normalize_date(entry.get("expires_at"), "expires_at")

    return parsed


def _not_assignable(role: str, known_roles: dict[str, Any]) -> bool:
    """
    Tell whether a role is not assignable. False for a role which does not exist.

    The assignments of such a role may only be altered from within Rucio: an identity
    provider can neither have it assigned to an account nor taken away from one.
    """
    entry = known_roles.get(role)
    return bool(entry) and not entry["assignable"]


def _format_assignable(role: str, known_roles: dict[str, Any]) -> str:
    """Render whether a role is assignable, '-' if the role does not exist."""
    if role not in known_roles:
        return "-"
    return "no" if _not_assignable(role, known_roles) else "yes"


def _new_sync_report(
        account: "InternalAccount",
        dry_run: bool,
        now: datetime,
        desired: dict[str, Optional[datetime]],
        current: dict[str, Optional[datetime]],
        activations: dict[str, datetime],
        known_roles: dict[str, Any]) -> dict[str, Any]:
    """
    Start the report of a synchronisation of an account's roles with an IdP.

    The report is what :func:`sync_account_roles_from_idp` and its dry run return:

    - `account`, `dry_run`, `synced_at`: which account was synchronised, whether anything was
      written, and the time against which expiry dates were compared.
    - `supplied`: the roles supplied by the IdP, with their expiry date, whether Rucio knows them
      and whether they are assignable (None for a role Rucio does not know).
    - `current`: the roles the account held before the synchronisation, with their activation date.
    - `removed_expired`, `removed_unsupplied`, `added`, `updated`, `unchanged`: what was (or, in a
      dry run, would be) done to the assignments of the account.
    - `held_back`: the roles whose assignment was left alone because they are not assignable,
      each with the reason.
    - `ignored_expired`: the roles the IdP supplies with an expiry date which has already passed, or
      which is not after the activation date of the account's assignment.
    - `unknown`: the roles the IdP supplies which do not exist in Rucio.
    - `messages`: the human-readable account of the synchronisation, line by line.
    - `summary`: a one-line summary of the synchronisation.
    """
    def _assignable(role: str) -> Optional[bool]:
        return None if role not in known_roles else not _not_assignable(role, known_roles)

    return {
        "account": account.external,
        "dry_run": dry_run,
        "synced_at": now,
        "supplied": [
            {"role": role, "expires_at": expires_at, "known": role in known_roles, "assignable": _assignable(role)}
            for role, expires_at in sorted(desired.items())
        ],
        "current": [
            {"role": role, "activates_at": activations[role], "expires_at": expires_at, "assignable": _assignable(role)}
            for role, expires_at in sorted(current.items())
        ],
        "removed_expired": [],
        "removed_unsupplied": [],
        "added": [],
        "updated": [],
        "unchanged": [],
        "held_back": [],
        "ignored_expired": [],
        "unknown": [],
        "messages": [],
        "summary": "",
    }


def _hold_back(report: dict[str, Any], known_roles: dict[str, Any], role: str, message: str) -> bool:
    """
    Tell whether a role not being assignable keeps a change from being applied, and record
    it in the report the first time, so that the same role is not mentioned once per step.
    """
    if not _not_assignable(role, known_roles):
        return False
    if all(entry["role"] != role for entry in report["held_back"]):
        report["held_back"].append({"role": role, "reason": message.strip()})
        report["messages"].append(message)
    return True


def _sync_summary(report: dict[str, Any]) -> str:
    """Summarise a synchronisation of an account's roles with an IdP in one line."""
    removed = len(report["removed_expired"]) + len(report["removed_unsupplied"])
    if report["dry_run"]:
        template = ("Summary: would remove %d assignment(s) (%d expired, %d no longer supplied), add %d, change the expiry date of %d, leave %d unchanged; "
                    "%d role(s) held back because they are not assignable; %d role(s) supplied by the IdP with an already expired date, or one not after the activation date, ignored; %d role(s) supplied by the IdP are unknown to Rucio.")
    else:
        template = ("Summary: removed %d assignment(s) (%d expired, %d no longer supplied), added %d, changed the expiry date of %d, left %d unchanged; "
                    "%d role(s) held back because they are not assignable; %d role(s) supplied by the IdP with an already expired date, or one not after the activation date, ignored; %d role(s) supplied by the IdP are unknown to Rucio.")
    return template % (
        removed, len(report["removed_expired"]), len(report["removed_unsupplied"]), len(report["added"]), len(report["updated"]),
        len(report["unchanged"]), len(report["held_back"]), len(report["ignored_expired"]), len(report["unknown"]),
    )


def sync_account_roles_from_idp_dry_run(account: Union[str, "InternalAccount"], roles: Any, vo: str = DEFAULT_VO, *, session: "Session") -> dict[str, Any]:
    """
    Synchronize an account's role assignments with roles supplied by an IdP.

    A role which is not assignable is off limits to the identity provider: it is neither
    assigned to nor removed from an account here, and its expiry date is left as it is. Only
    Rucio itself can alter who holds such a role.

    Assignments of the account which have expired are removed. A role the IdP supplies with an
    expiry date which has already passed is ignored, whether the account holds it or not: it is
    neither assigned nor has its expiry date overwritten with a date in the past. Likewise, the
    expiry date of an assignment is not overwritten with a date which is not after its activation
    date. A role the IdP has assigned is active from the synchronisation on.

    This is a dry run: it reports what the synchronisation would do and leaves the database
    untouched.

    :param account: The account whose role assignments would be synchronised, as an
                    InternalAccount or as a plain account name.
    :param roles: The roles supplied by the IdP, in any of the forms :func:`_parse_idp_roles` accepts.
    :param vo: The VO the account belongs to, used when the account is given by name.
    :param session: The database session.
    :returns: The report of what the synchronisation would do, see :func:`_new_sync_report`.
    :raises AccountNotFound: If the account does not exist.
    :raises InputValidationError: If the roles supplied by the IdP are not in one of the accepted forms.
    """
    # ! Check if the account retrieval should be done here or in a specialized cron job.
    # ! If so, just change this function to sync one account with its roles

    # an account name is accepted as well, so that a tool or a daemon does not have to build
    # an InternalAccount of its own
    if isinstance(account, str):
        account = InternalAccount(account, vo=vo)
    _ensure_account_exists(account, session)

    desired = _parse_idp_roles(roles)
    known_roles = {entry["role"]: entry for entry in list_roles(session=session)}
    # Step 1: Retrieve the roles assigned to the account (AccountRoleAssociation)
    account_roles = list_account_roles(account, session=session)
    current = {entry["role"]: entry["expires_at"] for entry in account_roles}
    activations = {entry["role"]: entry["activates_at"] for entry in account_roles}
    # the dates are stored as naive UTC datetimes, so compare them against a naive UTC now
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = _new_sync_report(account, True, now, desired, current, activations, known_roles)
    say = report["messages"].append

    say("Syncing the roles of account '%s'... (dry run, nothing is written to the database)" % account)
    say("")
    say("Roles supplied by the IdP")
    report["messages"].extend(_format_table(
        ["ROLE", "EXPIRES AT", "KNOWN TO RUCIO", "ASSIGNABLE"],
        [
            [role, _format_expires_at(expires_at), "yes" if role in known_roles else "no", _format_assignable(role, known_roles)]
            for role, expires_at in sorted(desired.items())
        ],
    ))

    say("")
    say("Step 1: Retrieve the roles assigned to the account")
    report["messages"].extend(_format_table(
        ["ROLE", "ACTIVATES AT", "EXPIRES AT", "ASSIGNABLE"],
        [
            [role, str(activations[role]), _format_expires_at(expires_at), _format_assignable(role, known_roles)]
            for role, expires_at in sorted(current.items())
        ],
    ))

    # Step 2: Cleaning:
    # A role which is not assignable is skipped at every step below, since an identity
    # provider must not alter who holds it.
    say("")
    say("Step 2: Cleaning, as of %s" % now)

    # 2.1 Remove expired roles from the account (AccountRoleAssociation) (expires_at < now)
    expired: set[str] = set()
    for role, expires_at in sorted(current.items()):
        if expires_at is None or expires_at >= now:
            continue
        if _hold_back(report, known_roles, role, "  2.1 Role '%s' expired at %s but is not assignable, so the assignment would be left untouched." % (role, expires_at)):
            continue
        expired.add(role)
        report["removed_expired"].append({"role": role, "expires_at": expires_at})
        say("  2.1 Role '%s' expired at %s, so the assignment would be removed." % (role, expires_at))

    # what is left after 2.1 is what the remaining steps compare against
    remaining = {role: expires_at for role, expires_at in current.items() if role not in expired}

    # 2.2 Remove roles from the account that are not in the list of roles from the IDP (AccountRoleAssociation)
    for role in sorted(set(remaining) - set(desired)):
        if _hold_back(report, known_roles, role, "  2.2 Role '%s' is not supplied by the IdP but is not assignable, so the assignment would be kept." % role):
            continue
        report["removed_unsupplied"].append({"role": role, "expires_at": remaining[role]})
        say("  2.2 Role '%s' is not supplied by the IdP, so the assignment would be removed." % role)

    # A role the IdP supplies with an expiry date which has already passed is ignored in 2.3 and 2.4:
    # assigning it, or moving an existing assignment to that date, would only produce an assignment
    # which is expired from the start and removed again by 2.1 on the next synchronisation. The role
    # still counts as supplied in 2.2, so an existing assignment which is still valid is kept.
    # A new assignment activates now, so its expiry date must be strictly after now.
    def _supplied_expired(role: str) -> bool:
        """Tell whether the IdP supplies the role with an expiry date which has already passed."""
        expires_at = desired[role]
        return expires_at is not None and expires_at <= now

    def _supplied_before_activation(role: str) -> bool:
        """Tell whether the IdP supplies the role with an expiry date which is not after the activation date of the account's assignment."""
        expires_at = desired[role]
        return expires_at is not None and expires_at <= activations[role]

    # 2.3 Add roles to the account that are in the list of roles from the IDP but not in the account's current roles (AccountRoleAssociation)
    for role in sorted(set(desired) - set(remaining)):
        if role not in known_roles:
            report["unknown"].append(role)
            say("  2.3 Role '%s' is supplied by the IdP but does not exist in Rucio, so it cannot be assigned." % role)
            continue
        if _hold_back(report, known_roles, role, "  2.3 Role '%s' is not assignable, so the IdP cannot have it assigned to the account." % role):
            continue
        if _supplied_expired(role):
            report["ignored_expired"].append({"role": role, "expires_at": desired[role]})
            say("  2.3 Role '%s' is supplied by the IdP with an expiry date of %s which has already passed, so it would not be assigned." % (role, desired[role]))
            continue
        report["added"].append({"role": role, "expires_at": desired[role]})
        say("  2.3 Role '%s' would be assigned, expiring %s." % (role, _format_expires_at(desired[role])))

    # 2.4 Update the expires_at of the roles that are in both the account's current roles and the list of roles from the IDP (AccountRoleAssociation)
    for role in sorted(set(desired) & set(remaining)):
        if desired[role] == remaining[role]:
            report["unchanged"].append({"role": role, "expires_at": remaining[role]})
            continue
        if _hold_back(report, known_roles, role, "  2.4 Role '%s' is not assignable, so its expiry date of %s would be kept instead of %s."
                      % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role]))):
            continue
        if _supplied_expired(role):
            report["ignored_expired"].append({"role": role, "expires_at": desired[role]})
            say("  2.4 Role '%s' is supplied by the IdP with an expiry date of %s which has already passed, so the current expiry date of %s would be kept."
                % (role, desired[role], _format_expires_at(remaining[role])))
            continue
        if _supplied_before_activation(role):
            report["ignored_expired"].append({"role": role, "expires_at": desired[role]})
            say("  2.4 Role '%s' is supplied by the IdP with an expiry date of %s which is not after the activation date of %s, so the current expiry date of %s would be kept."
                % (role, desired[role], activations[role], _format_expires_at(remaining[role])))
            continue
        report["updated"].append({"role": role, "previous_expires_at": remaining[role], "expires_at": desired[role]})
        say("  2.4 Role '%s' would have its expiry date changed from %s to %s."
            % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role])))

    report["summary"] = _sync_summary(report)
    say("")
    say(report["summary"])
    return report


def sync_account_roles_from_idp(account: Union[str, "InternalAccount"], roles: Any, vo: str = DEFAULT_VO, *, session: "Session") -> dict[str, Any]:
    """
    Synchronize an account's role assignments with roles supplied by an IdP.

    A role which is not assignable is off limits to the identity provider: it is neither
    assigned to nor removed from an account here, and its expiry date is left as it is. Only
    Rucio itself can alter who holds such a role.

    Assignments of the account which have expired are removed. A role the IdP supplies with an
    expiry date which has already passed is ignored, whether the account holds it or not: it is
    neither assigned nor has its expiry date overwritten with a date in the past. Likewise, the
    expiry date of an assignment is not overwritten with a date which is not after its activation
    date. A role the IdP has assigned is active from the synchronisation on.

    The whole synchronisation is a single transaction, so either all of it is applied or none of
    it is. See :func:`sync_account_roles_from_idp_dry_run` to report the changes instead of
    applying them.

    :param account: The account whose role assignments are synchronised, as an
                    InternalAccount or as a plain account name.
    :param roles: The roles supplied by the IdP, in any of the forms :func:`_parse_idp_roles` accepts.
    :param vo: The VO the account belongs to, used when the account is given by name.
    :param session: The database session.
    :returns: The report of what the synchronisation did, see :func:`_new_sync_report`.
    :raises AccountNotFound: If the account does not exist.
    :raises InputValidationError: If the roles supplied by the IdP are not in one of the accepted forms.
    """
    if isinstance(account, str):
        account = InternalAccount(account, vo=vo)
    _ensure_account_exists(account, session)

    desired = _parse_idp_roles(roles)
    known_roles = {entry["role"]: entry for entry in list_roles(session=session)}
    account_roles = list_account_roles(account, session=session)
    current = {entry["role"]: entry["expires_at"] for entry in account_roles}
    activations = {entry["role"]: entry["activates_at"] for entry in account_roles}

    # the dates are stored as naive UTC datetimes, so compare them against a naive UTC now
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = _new_sync_report(account, False, now, desired, current, activations, known_roles)
    say = report["messages"].append
    say("Syncing the roles of account '%s'..." % account)

    def _delete_assignment(role: str) -> None:
        session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.account == account, models.AccountRoleAssociation.role == role))

    try:
        # Step 1: Remove the expired roles from the account (expires_at < now)
        expired: set[str] = set()
        for role, expires_at in sorted(current.items()):
            if expires_at is None or expires_at >= now:
                continue
            if _hold_back(report, known_roles, role, "  Role '%s' expired at %s but is not assignable, so the assignment is left untouched." % (role, expires_at)):
                continue
            _delete_assignment(role)
            expired.add(role)
            report["removed_expired"].append({"role": role, "expires_at": expires_at})
            say("  Role '%s' expired at %s, so the assignment was removed." % (role, expires_at))

        remaining = {role: expires_at for role, expires_at in current.items() if role not in expired}

        # Step 2: Remove the roles which the IdP does not supply
        for role in sorted(set(remaining) - set(desired)):
            if _hold_back(report, known_roles, role, "  Role '%s' is not supplied by the IdP but is not assignable, so the assignment is kept." % role):
                continue
            _delete_assignment(role)
            report["removed_unsupplied"].append({"role": role, "expires_at": remaining[role]})
            say("  Role '%s' is not supplied by the IdP, so the assignment was removed." % role)

        # Step 3: Assign the roles which the IdP supplies and the account does not hold
        for role in sorted(set(desired) - set(remaining)):
            expires_at = desired[role]
            if role not in known_roles:
                report["unknown"].append(role)
                say("  Role '%s' is supplied by the IdP but does not exist in Rucio, so it cannot be assigned." % role)
                continue
            if _hold_back(report, known_roles, role, "  Role '%s' is not assignable, so the IdP cannot have it assigned to the account." % role):
                continue
            # the new assignment activates now, so its expiry date must be strictly after now
            if expires_at is not None and expires_at <= now:
                report["ignored_expired"].append({"role": role, "expires_at": expires_at})
                say("  Role '%s' is supplied by the IdP with an expiry date of %s which has already passed, so it was not assigned." % (role, expires_at))
                continue
            session.add(models.AccountRoleAssociation(account=account, role=role, activates_at=now, expires_at=expires_at))
            report["added"].append({"role": role, "expires_at": expires_at})
            say("  Role '%s' assigned, expiring %s." % (role, _format_expires_at(expires_at)))

        # Step 4: Update the expiry date of the roles which both the IdP supplies and the account holds
        for role in sorted(set(desired) & set(remaining)):
            if desired[role] == remaining[role]:
                report["unchanged"].append({"role": role, "expires_at": remaining[role]})
                continue
            if _hold_back(report, known_roles, role, "  Role '%s' is not assignable, so its expiry date of %s is kept instead of %s."
                          % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role]))):
                continue
            expires_at = desired[role]
            if expires_at is not None and expires_at <= now:
                report["ignored_expired"].append({"role": role, "expires_at": expires_at})
                say("  Role '%s' is supplied by the IdP with an expiry date of %s which has already passed, so the current expiry date of %s is kept."
                    % (role, expires_at, _format_expires_at(remaining[role])))
                continue
            if expires_at is not None and expires_at <= activations[role]:
                report["ignored_expired"].append({"role": role, "expires_at": expires_at})
                say("  Role '%s' is supplied by the IdP with an expiry date of %s which is not after the activation date of %s, so the current expiry date of %s is kept."
                    % (role, expires_at, activations[role], _format_expires_at(remaining[role])))
                continue
            session.execute(
                update(models.AccountRoleAssociation)
                .where(models.AccountRoleAssociation.account == account, models.AccountRoleAssociation.role == role)
                .values(expires_at=expires_at)
            )
            report["updated"].append({"role": role, "previous_expires_at": remaining[role], "expires_at": expires_at})
            say("  Role '%s' had its expiry date changed from %s to %s." % (role, _format_expires_at(remaining[role]), _format_expires_at(expires_at)))

        session.commit()
    except Exception:
        session.rollback()
        raise

    report["summary"] = _sync_summary(report)
    say("")
    say(report["summary"])
    return report
