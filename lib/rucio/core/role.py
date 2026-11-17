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
- Permission types: the permissions a role can be granted, each type with its own table and
  :class:`PermissionTypeHandler`: DID permissions grant operations on the DIDs a pattern matches.
- Role permissions: grant, remove and list the permissions of a role.
- Permission checks: tell what the roles of an account grant, e.g. :func:`has_did_permission`. The permission
  policy combines it with root and admin privileges and ownership, also to filter listings, see
  :mod:`rucio.core.permission.generic`.
- Synchronisation: of the roles with the policy package, and of an account's roles with an IdP.
- Cleaning: remove the expired role assignments of every account.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar, Optional, TypeVar, Union, cast

from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.exc import IntegrityError

from rucio.common.config import config_get_bool
from rucio.common.constants import ADMIN_ROLE, DEFAULT_VO, RESERVED_ROLES
from rucio.common.exception import (
    AccountNotFound,
    Duplicate,
    InputValidationError,
    RoleAssignmentDisabled,
    RoleAssignmentNotFound,
    RoleInUse,
    RoleLocked,
    RoleNotFound,
    RolePermissionNotFound,
    RoleReserved,
)
from rucio.common.schema import get_schema_value
from rucio.common.types import InternalAccount
from rucio.common.utils import DATE_FORMAT, str_to_date
from rucio.core import permission
from rucio.db.sqla import models
from rucio.db.sqla.constants import DidOperationType, RolePermissionOperationType, RolePermissionType

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session
    from sqlalchemy.sql.elements import ColumnElement

    from rucio.common.types import InternalScope

# Marks a date of a role assignment which is to be left as it is, see :func:`set_account_role_dates`.
KEEP: Any = object()


# ----------------------------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------------------------

def is_rbac_enabled() -> bool:
    """
    Tell whether RBAC is enabled in this instance.

    This is the only function of this module reading the flag: every other one answers what the roles
    grant, whether RBAC is enabled or not. Deciding whether that answer applies is up to the caller,
    e.g. the permission policy, see :mod:`rucio.core.permission.generic`, or the gateway filtering a listing.
    """
    return config_get_bool('rbac', 'enabled', raise_exception=False, default=False, check_config_table=True)


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------

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


def add_role(role: str, description: Optional[str] = None, assignable: bool = True, locked: bool = True, *, session: "Session") -> None:
    """
    Add a new role to the system.

    :param role: The name of the role to add.
    :param description: An optional description of the role. An empty description is stored as NULL.
    :param assignable: Whether an identity provider may assign this role to, or take it away from, an account; if not, only Rucio itself alters who holds it.
    :param locked: Whether the role is locked, which prevents a policy package from altering or deleting it.
    :param session: The database session.
    :raises RoleReserved: If the role is reserved, see `RESERVED_ROLES`.
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


def _remove_accounts_from_role(role: str, *, session: "Session") -> int:
    """
    Delete a role together with its account assignments, without committing.

    `account_role_map.role` references `roles.role` with no ON DELETE action, so the account
    assignments are removed first. The permissions of the role go along with it, since the `role`
    of every `role_<type>_permission_map` table references `roles.role` with ON DELETE CASCADE.

    :param role: The role to delete.
    :param session: The database session.
    :returns: The number of account assignments removed along with the role.
    """
    result = session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role))
    unassigned = cast('Any', result).rowcount
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


def has_account_active_role(account: "InternalAccount", role: str, session: "Session") -> bool:
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


def has_account_admin_role(account: "InternalAccount", *, session: "Session") -> bool:
    """
    Tell whether the account holds the reserved admin role through an assignment which is active.

    Without RBAC, admins are the accounts with the 'admin' account attribute instead: choosing between the two is up to the caller.

    :param account: The account to check.
    :param session: The database session.
    """
    return has_account_active_role(account=account, role=ADMIN_ROLE, session=session)


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
    :raises AccountNotFound: If the account does not exist.
    :raises RoleNotFound: If the role does not exist.
    :raises Duplicate: If the account already has the role assigned.
    :raises RoleAssignmentDisabled: If the role is not assignable and `force` is not given.
    :raises InputValidationError: If a date is not valid, or if the assignment would expire before it activates.
    """
    if not force and _role_not_assignable(role, session):
        raise RoleAssignmentDisabled("Role '%s' is not assignable, so it cannot be assigned to an account." % role)

    expires_at = _normalize_date(expires_at, "expires_at")
    # set now explicitly rather than relying on the column default, so that it is the date checked against expires_at,
    # in whole seconds: MySQL rounds the fractional seconds of a DATETIME, which could push now into the future
    activates_at = _normalize_date(activates_at, "activates_at") or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    _ensure_expires_after_activation(activates_at, expires_at)

    session.add(models.AccountRoleAssociation(account=account, role=role, activates_at=activates_at, expires_at=expires_at))
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        # look the account and the role up rather than parsing the error, since SQLite does not name the violated constraint
        if session.execute(select(models.Account.account).where(models.Account.account == account)).scalar_one_or_none() is None:
            raise AccountNotFound("Account '%s' does not exist." % account)
        _ensure_role_exists(role, session)
        raise Duplicate("Account '%s' already has role '%s'." % (account, role))


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
    # an activation date is always stored, None meaning now, see :func:`set_account_role_dates`
    return cast("datetime", set_account_role_dates(account, role, activates_at=activates_at, session=session)["activates_at"])


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
        activates_at = _normalize_date(activates_at, "activates_at") or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
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
# A permission is made of its role, its type, its target (e.g. a DID pattern) and the parameters of
# its type (e.g. the operations it grants). Each permission type has a `RolePermissionType` member, a
# `role_<type>_permission_map` table whose `role` references `roles.role` with ON DELETE CASCADE, and
# a `PermissionTypeHandler` subclass, registered with `_register_permission_handler`, telling how its
# permissions are validated, granted, removed and listed, see :func:`add_role_permission`.
# ----------------------------------------------------------------------------------------------

# the parameter of a DID permission giving the operations it grants, see `DidPermissionHandler`
OPERATIONS = "operations"

OperationT = TypeVar("OperationT", bound=RolePermissionOperationType)


def _normalize_operations(operations: Any, operation_type: type[OperationT], permission_type: RolePermissionType) -> frozenset[OperationT]:
    """
    Validate the operations a permission grants: a list of members of the operation type of the permission type, or of
    their values (e.g. ['read', 'write']), possibly empty to grant none.

    :raises InputValidationError: If it is not a list, or one of its items is not an operation of the permission type.
    """
    if isinstance(operations, (str, RolePermissionOperationType)) or not isinstance(operations, (list, tuple, set, frozenset)):
        raise InputValidationError("'%s' must be a list of operations of a '%s' permission, e.g. ['%s'], or an empty list to grant none."
                                   % (OPERATIONS, permission_type.value, "', '".join(op.value for op in operation_type)))
    normalized = set()
    for operation in operations:
        try:
            normalized.add(operation_type(operation))
        except ValueError:
            raise InputValidationError("Operation '%s' is not supported on a '%s' permission, expected one of: %s."
                                       % (getattr(operation, "value", operation), permission_type.value, ", ".join(op.value for op in operation_type)))
    return frozenset(normalized)


def _complete_operations(operations: "Iterable[OperationT]", included: "Mapping[OperationT, frozenset[OperationT]]") -> frozenset[OperationT]:
    """
    Add to the operations of a permission those they include, e.g. READ to WRITE: none stays none.

    :param operations: The operations given, members of the operation type of the permission type.
    :param included: The operations each operation of the type includes, e.g. `_INCLUDED_DID_OPERATIONS`.
    """
    operations = frozenset(operations)
    return operations.union(*(included[operation] for operation in operations))


def _describe_operations(operations: "Iterable[RolePermissionOperationType]", operation_type: "type[RolePermissionOperationType]") -> str:
    """Render the operations of a permission as the letters of the CLI, a dash for each operation not granted, e.g. 'r-d' or '---'."""
    operations = set(operations)
    return "".join(operation.value[0] if operation in operations else "-" for operation in operation_type)


class PermissionTypeHandler:
    """
    Everything the generic permission functions need to know about one permission type.

    A subclass names the parameter holding the target of a permission (`target_attribute`),
    and implements how a permission is validated, granted, removed and listed.
    The methods writing to the database do not commit.
    """
    permission_type: ClassVar[RolePermissionType]
    # the parameter holding the target of a permission, also its key in a listing
    target_attribute: ClassVar[str]
    # how the target is called in messages
    target_label: ClassVar[str]

    def normalize_target(self, target: Any) -> Any:
        """
        Validate a target given when granting or removing a permission, and turn it into what is stored.

        :raises InputValidationError: If the target is not valid for this permission type.
        """
        raise NotImplementedError

    def normalize_parameters(self, parameters: "Mapping[str, Any]", *, removing: bool) -> dict[str, Any]:
        """
        Validate the parameters given, besides the target, when granting a permission, or when `removing` one.

        :raises InputValidationError: If a parameter is missing, unknown or not valid.
        """
        raise NotImplementedError

    def describe(self, target: Any, parameters: "Mapping[str, Any]") -> str:
        """Render a permission for a message, e.g. "'read' permission on DID pattern 'data*:*'"."""
        raise NotImplementedError

    def list_permissions(self, role: str, *, session: "Session") -> list[dict[str, Any]]:
        """List the permissions of this type of a role, each with its target under `target_attribute` and its parameters."""
        raise NotImplementedError

    def add(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, session: "Session") -> None:
        """Grant a permission to a role, see :func:`add_role_permission`."""
        raise NotImplementedError

    def remove(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, session: "Session") -> int:
        """Remove permissions from a role, see :func:`delete_role_permission`, and tell how many were removed."""
        raise NotImplementedError


_PERMISSION_HANDLERS: dict[RolePermissionType, PermissionTypeHandler] = {}


def _register_permission_handler(handler_class: "type[PermissionTypeHandler]") -> "type[PermissionTypeHandler]":
    """Class decorator registering the handler of a permission type, see :class:`PermissionTypeHandler`."""
    _PERMISSION_HANDLERS[handler_class.permission_type] = handler_class()
    return handler_class


def _permission_handler(permission_type: Optional[Union[RolePermissionType, str]]) -> PermissionTypeHandler:
    """
    Find the handler of a permission type, given as a `RolePermissionType` or as its value (e.g. 'did').

    :raises InputValidationError: If no handler is registered for the permission type.
    """
    try:
        return _PERMISSION_HANDLERS[RolePermissionType(permission_type)]
    except (ValueError, KeyError):
        raise InputValidationError("Permission type '%s' is not supported, expected one of: %s."
                                   % (getattr(permission_type, "value", permission_type), ", ".join(sorted(t.value for t in _PERMISSION_HANDLERS))))


# --- DIDs -------------------------------------------------------------------------------------
#
# A DID permission grants READ, WRITE and DELETE on the DIDs a DID pattern matches, see :func:`_validate_did_pattern`.
# A pattern matches the DID itself only: there is no inheritance from the collections a DID is attached to.
#
# The operations are levels, each including the ones below it: WRITE includes READ, and DELETE includes WRITE and
# READ, so a permission grants none ('---'), READ ('r--'), WRITE ('rw-') or DELETE ('rwd'). They are completed when
# the permission is granted, see :func:`_complete_operations`: what is stored, and listed, is what applies.
#
# Within a role, the most specific pattern decides: for a DID, the row of the role whose pattern matches it and is
# the most specific (see :func:`_did_pattern_specificity`) gives every operation the role grants on it, the other
# rows matching it are not looked at. A row granting no operation therefore withdraws the DIDs it matches from a
# less specific row of its role, e.g. 'rwd' on 'data:*' and 'r' on 'data:raw*' keep the raw DIDs read-only. Across
# roles, what they grant adds up: a role never takes away what another grants. See :class:`DidAccess`.

# the only wildcard a DID pattern may use, see `_validate_did_pattern`
DID_WILDCARD = "*"
# separates the scope part from the name part of a DID pattern
DID_SEPARATOR = ":"


def _validate_did_pattern(did_pattern: str) -> str:
    """
    Validate a DID pattern of a role permission, and bring it to the form it is stored and listed in.

    A DID pattern is always stored as a scope part and a name part, so that a scope is never
    mistaken for the name of a DID:

    - 'data*:*': every DID of every scope starting with 'data' ('*:*' for every scope);
    - 'data:*': every DID of the scope 'data';
    - 'data:raw*': every DID of the scope 'data' whose name starts with 'raw';
    - 'data:raw1': the DID 'data:raw1'.

    A pattern given without a name part ('data', 'data*', '*') stands for the whole scope(s), and is
    stored with the '*' name part ('data:*', 'data*:*', '*:*').

    A '*' is the only wildcard, and it is only accepted at the end of either part: a leading or
    embedded wildcard is refused, since it cannot be matched unambiguously, and so is a wildcard
    scope part followed by anything but the '*' name part. The pattern is not checked against the
    scopes and DIDs which currently exist: it is stored as given, and a DID created later is covered
    by it immediately.

    :param did_pattern: The DID pattern as supplied by the caller.
    :returns: The DID pattern, stripped of surrounding whitespace, with its name part.
    :raises InputValidationError: If the DID pattern is not a string, is empty, is too long, or does not have one of the forms above.
    """
    if not isinstance(did_pattern, str):
        raise InputValidationError("DID pattern must be a string, got '%s'." % type(did_pattern).__name__)

    did_pattern = did_pattern.strip()
    if not did_pattern:
        raise InputValidationError("DID pattern must not be empty.")

    scope_pattern, separator, name_pattern = did_pattern.partition(DID_SEPARATOR)
    if not separator:
        name_pattern = DID_WILDCARD
    if not scope_pattern or not name_pattern or DID_SEPARATOR in name_pattern:
        raise InputValidationError(
            "DID pattern '%s' is not supported, expected a scope part and a name part separated by a single '%s', as in 'data:raw*'." % (did_pattern, DID_SEPARATOR))

    for part in (scope_pattern, name_pattern):
        if part.count(DID_WILDCARD) > 1 or (DID_WILDCARD in part and not part.endswith(DID_WILDCARD)):
            raise InputValidationError(
                "DID pattern '%s' is not supported, a '*' may only close the scope part or the name part, as in 'data*:*' or 'data:raw*'." % did_pattern)
    if DID_WILDCARD in scope_pattern and name_pattern != DID_WILDCARD:
        raise InputValidationError(
            "DID pattern '%s' is not supported, a wildcard scope part may only be followed by the '*' name part, as in 'data*:*'." % did_pattern)

    if len(scope_pattern) > get_schema_value('SCOPE_LENGTH') or len(name_pattern) > get_schema_value('NAME_LENGTH'):
        raise InputValidationError("DID pattern '%s' is too long for a scope or a name." % did_pattern)

    return scope_pattern + DID_SEPARATOR + name_pattern


# the operations each DID operation includes, see the comment of the DID permissions above
_INCLUDED_DID_OPERATIONS: dict[DidOperationType, frozenset[DidOperationType]] = {
    DidOperationType.READ: frozenset(),
    DidOperationType.WRITE: frozenset({DidOperationType.READ}),
    DidOperationType.DELETE: frozenset({DidOperationType.WRITE, DidOperationType.READ}),
}


def _prefix_pattern_matches(value: str, pattern: str) -> bool:
    """Tell whether a value matches a pattern ending in '*', which matches every value starting with what precedes it, or equals a pattern without '*'."""
    if pattern.endswith(DID_WILDCARD):
        return value.startswith(pattern[:-1])
    return value == pattern


def _did_pattern_matches(scope: "InternalScope", name: Optional[str], did_pattern: str) -> bool:
    """
    Tell whether a concrete DID, or a whole scope, matches a role's DID pattern, see :func:`_validate_did_pattern`.

    The scope is matched by its external (human-readable) name. A pattern with the '*' name part
    ('data:*', 'data*:*') matches every DID of the scopes its scope part matches, and the scopes
    themselves. Any other pattern only matches the DIDs of its scope whose name matches its name part:
    it never matches a whole scope (`name` is None).

    :param scope: The scope of the DID, or the scope to check.
    :param name: The name of the DID, or None to check the whole scope.
    :param did_pattern: The DID pattern of a role permission, as stored.
    :returns: True if the DID, or the whole scope, matches the pattern.
    """
    external = str(scope.external)
    scope_pattern, _, name_pattern = did_pattern.partition(DID_SEPARATOR)
    if name_pattern == DID_WILDCARD:
        return _prefix_pattern_matches(external, scope_pattern)
    return name is not None and external == scope_pattern and _prefix_pattern_matches(name, name_pattern)


def _did_pattern_specificity(did_pattern: str) -> tuple[int, int]:
    """
    Rank a DID pattern by how specific it is, the higher the more, to decide between the rows of a role matching a DID.

    From the most to the least specific: a single DID ('data:raw1'), a name pattern ('data:raw*', the longer the
    more specific), a whole scope ('data:*'), a scope pattern ('data*:*', the longer the more specific). Two
    different patterns of the same rank and length never match the same DID.

    :param did_pattern: The DID pattern of a role permission, as stored, see :func:`_validate_did_pattern`.
    :returns: The rank of the pattern, and the length of what it fixes within that rank.
    """
    scope_pattern, _, name_pattern = did_pattern.partition(DID_SEPARATOR)
    if name_pattern != DID_WILDCARD:
        if name_pattern.endswith(DID_WILDCARD):
            return 2, len(name_pattern) - 1
        return 3, len(name_pattern)
    if scope_pattern.endswith(DID_WILDCARD):
        return 0, len(scope_pattern) - 1
    return 1, len(scope_pattern)


@dataclass(frozen=True)
class _DidRow:
    """A DID permission of a role, as stored: its pattern and the operations it grants, possibly none."""
    did_pattern: str
    operations: frozenset[DidOperationType]

    @property
    def scope_part(self) -> str:
        """The scope part of the pattern, e.g. 'data' for 'data:raw*', 'data*' for 'data*:*'."""
        return self.did_pattern.partition(DID_SEPARATOR)[0]

    @property
    def is_name_pattern(self) -> bool:
        """Whether the pattern names DIDs of a single scope ('data:raw*', 'data:raw1') rather than whole scopes ('data:*', 'data*:*')."""
        return self.did_pattern.partition(DID_SEPARATOR)[2] != DID_WILDCARD


class DidAccess:
    """
    What the DID permissions of the active roles of an account grant, see the comment of the DID permissions above.

    The DID permissions are read once, when it is built, and each request is decided from them, so that a listing
    is decided without querying the database again. Only the roles are looked at: not whether RBAC is enabled,
    root and admin privileges, nor the owners of the scope or of the DID.
    """

    def __init__(self, account: "InternalAccount", *, session: "Session") -> None:
        association, model = models.AccountRoleAssociation, models.RoleDidPermissionAssociation
        stmt = (
            select(association.role, model.did_pattern, *(getattr(model, operation.column) for operation in DidOperationType))
            .join(model, model.role == association.role)
            .where(association.account == account, _assignment_active())
        )
        self._rows: dict[str, list[_DidRow]] = {}
        for role, did_pattern, *granted in session.execute(stmt).all():
            operations = frozenset(operation for operation, flag in zip(DidOperationType, granted) if flag)
            self._rows.setdefault(role, []).append(_DidRow(did_pattern, operations))

    def _deciding_row(self, role: str, scope: "InternalScope", name: Optional[str]) -> Optional[_DidRow]:
        """The row of a role deciding a DID, or a whole scope without `name`: the most specific pattern matching it; None if no row matches."""
        rows = [row for row in self._rows.get(role, ()) if _did_pattern_matches(scope, name, row.did_pattern)]
        return max(rows, key=lambda row: _did_pattern_specificity(row.did_pattern)) if rows else None

    def _name_rows(self, role: str, scope: "InternalScope") -> "Iterator[_DidRow]":
        """The rows of a role on DIDs of a scope by their names ('data:raw*', 'data:raw1')."""
        external = str(scope.external)
        return (row for row in self._rows.get(role, ()) if row.is_name_pattern and row.scope_part == external)

    def role_grants(self, role: str, scope: "InternalScope", name: Optional[str], operation: DidOperationType) -> bool:
        """
        Tell whether a role grants an operation on a DID, or on a whole scope without `name`.

        A DID is decided by the most specific pattern of the role matching it. A whole scope is granted by the most
        specific pattern of the role covering the whole scope, provided no name pattern of the role in that scope
        withdraws the operation from some of its DIDs: what stands for the whole scope must not tell about them.
        """
        row = self._deciding_row(role, scope, name)
        if row is None or operation not in row.operations:
            return False
        return name is not None or all(operation in name_row.operations for name_row in self._name_rows(role, scope))

    def grants(self, scope: "InternalScope", name: Optional[str], operation: DidOperationType) -> bool:
        """Tell whether a role grants an operation on a DID, or on a whole scope without `name`: the roles add up."""
        return any(self.role_grants(role, scope, name, operation) for role in self._rows)

    def role_grants_some_did(self, role: str, scope: "InternalScope", operation: DidOperationType) -> bool:
        """
        Tell whether a role grants an operation on at least one DID of a scope, whatever its name: its pattern deciding
        the whole scope grants it, or one of its name patterns in the scope does.
        """
        row = self._deciding_row(role, scope, None)
        return (row is not None and operation in row.operations) or any(operation in name_row.operations for name_row in self._name_rows(role, scope))

    def grants_some_did(self, scope: "InternalScope", operation: DidOperationType) -> bool:
        """Tell whether a role grants an operation on at least one DID of a scope, whatever its name: the roles add up."""
        return any(self.role_grants_some_did(role, scope, operation) for role in self._rows)


@_register_permission_handler
class DidPermissionHandler(PermissionTypeHandler):
    """
    Operations on DIDs, granted on DID patterns, see the comment of the DID permissions above.

    A permission is given as its 'did_pattern' and its 'operations', a list of `DidOperationType` values, possibly empty.
    It is stored as one row per role and pattern, with one boolean column per operation: granting it replaces the
    operations of its row, even with none, and removing it deletes the row.
    """
    permission_type = RolePermissionType.DID
    model = models.RoleDidPermissionAssociation
    target_attribute = "did_pattern"
    target_label = "DID pattern"

    def normalize_target(self, target: Any) -> str:
        return _validate_did_pattern(target)

    def _permission_row(self, role: str, did_pattern: str, *, session: "Session") -> Optional[Any]:
        """The row holding the operations a role is granted on a DID pattern, locked for update, if any."""
        stmt = (
            select(self.model)
            .where(self.model.role == role, self.model.did_pattern == did_pattern)
            .with_for_update()
        )
        return session.execute(stmt).scalar_one_or_none()

    def normalize_parameters(self, parameters: "Mapping[str, Any]", *, removing: bool) -> dict[str, Any]:
        expected = set() if removing else {OPERATIONS}
        unknown = sorted(set(parameters) - expected)
        if unknown:
            raise InputValidationError("Parameter(s) %s not supported %s a '%s' permission%s."
                                       % (", ".join(unknown), "when removing" if removing else "on", self.permission_type.value,
                                          ", only its %s is given" % self.target_attribute if removing else ", expected: %s" % OPERATIONS))
        if removing:
            return {}
        if parameters.get(OPERATIONS) is None:
            raise InputValidationError("'%s' must be given for a '%s' permission, an empty list to grant none." % (OPERATIONS, self.permission_type.value))
        return {OPERATIONS: _complete_operations(_normalize_operations(parameters[OPERATIONS], DidOperationType, self.permission_type), _INCLUDED_DID_OPERATIONS)}

    def describe(self, target: Any, parameters: "Mapping[str, Any]") -> str:
        operations = parameters.get(OPERATIONS)
        granted = "" if operations is None else "'%s' " % _describe_operations(operations, DidOperationType)
        return "%spermission on %s '%s'" % (granted, self.target_label, target)

    def list_permissions(self, role: str, *, session: "Session") -> list[dict[str, Any]]:
        stmt = (
            select(self.model)
            .where(self.model.role == role)
            .order_by(self.model.did_pattern)
        )
        return [{self.target_attribute: row.did_pattern,
                 OPERATIONS: [operation.value for operation in DidOperationType if getattr(row, operation.column)]}
                for row in session.execute(stmt).scalars()]

    def add(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, session: "Session") -> None:
        columns = {operation.column: operation in parameters[OPERATIONS] for operation in DidOperationType}
        row = self._permission_row(role, target, session=session)
        if row is None:
            # a missing role is told by the foreign key, see :func:`add_role_permission`
            session.add(self.model(role=role, did_pattern=target, **columns))
        else:
            for column, granted in columns.items():
                setattr(row, column, granted)
        session.flush()

    def remove(self, role: str, target: Any, parameters: "Mapping[str, Any]", *, session: "Session") -> int:
        row = self._permission_row(role, target, session=session)
        if row is None:
            return 0
        session.delete(row)
        session.flush()
        return 1


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


def list_role_permissions(role: str, *, session: "Session") -> list[dict[str, Any]]:
    """
    List the permissions granted to a role.

    Each permission is given as its `type`, its target under the key its type names it by, and its
    parameters, in the shape it is granted with, see :func:`add_role_permission`: e.g. a 'did_pattern'
    and its list of 'operations' for a DID permission.

    :param role: The role whose permissions to list.
    :param session: The database session.
    :raises RoleNotFound: If the role does not exist.
    """
    _ensure_role_exists(role, session)

    return [
        {"type": permission_type.value, **permission}
        for permission_type, handler in _PERMISSION_HANDLERS.items()
        for permission in handler.list_permissions(role, session=session)
    ]


def add_role_permission(
        role: str,
        permission_type: Union[RolePermissionType, str],
        parameters: "Mapping[str, Any]",
        force: bool = False,
        *,
        session: "Session") -> None:
    """
    Grant a role a permission of a type.

        add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data*:*', 'operations': ['read']}, session=session)
        add_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data:tmp*', 'operations': []}, session=session)

    A permission which exists already is overwritten: a DID permission gets exactly the operations given.

    :param role: The role to grant the permission to.
    :param permission_type: The type of the permission, e.g. `RolePermissionType.DID`.
    :param parameters: The target of the permission under the key its type names it by, e.g. 'did_pattern',
                       and its parameters, see the `PermissionTypeHandler` of the type.
    :param force: Grant the permission even if the role is locked.
    :param session: The database session.
    :raises InputValidationError: If the permission type, the target or a parameter is not valid.
    :raises RoleLocked: If the role is locked and `force` is not given.
    :raises RoleNotFound: If the role does not exist.
    :raises Duplicate: If the same permission is granted concurrently.
    :raises RoleReserved: If the role is reserved, whether or not `force` is given.
    """
    handler = _permission_handler(permission_type)
    target, parameters = _split_target(handler, parameters)
    target = handler.normalize_target(target)
    parameters = handler.normalize_parameters(parameters, removing=False)
    if is_reserved_role(role):
        raise RoleReserved("Role '%s' is reserved, so no permission can be granted to it." % role)
    _ensure_unlocked(role, force, session)

    try:
        handler.add(role, target, parameters, session=session)
        session.commit()
    except IntegrityError:
        session.rollback()
        # look the role up rather than parsing the error, since SQLite does not name the violated constraint
        _ensure_role_exists(role, session)
        raise Duplicate("Role '%s' already has %s." % (role, handler.describe(target, parameters)))


def delete_role_permission(
        role: str,
        permission_type: Union[RolePermissionType, str],
        parameters: "Mapping[str, Any]",
        force: bool = False,
        *,
        session: "Session") -> int:
    """
    Remove permissions of a type from a role.

        delete_role_permission(role, RolePermissionType.DID, {'did_pattern': 'data*:*'}, session=session)

    :param role: The role to remove the permissions from.
    :param permission_type: The type of the permissions, e.g. `RolePermissionType.DID`.
    :param parameters: The target of the permissions under the key its type names it by, e.g. 'did_pattern',
                       and the parameters identifying them, see the `PermissionTypeHandler` of the type.
    :param force: Remove the permissions even if the role is locked.
    :param session: The database session.
    :returns: The number of permissions removed.
    :raises InputValidationError: If the permission type, the target or a parameter is not valid.
    :raises RoleLocked: If the role is locked and `force` is not given.
    :raises RolePermissionNotFound: If the role does not have any such permission.
    :raises RoleReserved: If the role is reserved, whether or not `force` is given.
    """
    handler = _permission_handler(permission_type)
    target, parameters = _split_target(handler, parameters)
    target = handler.normalize_target(target)
    parameters = handler.normalize_parameters(parameters, removing=True)
    if is_reserved_role(role):
        raise RoleReserved("Role '%s' is reserved, so no permission can be removed from it." % role)
    _ensure_unlocked(role, force, session)

    removed = handler.remove(role, target, parameters, session=session)
    if not removed:
        session.rollback()
        raise RolePermissionNotFound("Either role '%s' does not exist, or it does not have %s." % (role, handler.describe(target, parameters)))
    session.commit()
    return removed


# ----------------------------------------------------------------------------------------------
# Permission checks
# ----------------------------------------------------------------------------------------------

def has_did_permission(account: "InternalAccount", scope: "InternalScope", name: Optional[str], operation: DidOperationType, *, session: "Session") -> bool:
    """
    Tell whether the active roles of the account grant it an operation on a DID, or on the whole scope if `name` is
    None, see :meth:`DidAccess.grants`. Only the roles are looked at, see :mod:`rucio.core.permission.generic`.

    :param account: The account to check.
    :param scope: The scope of the DID, or the scope to check.
    :param name: The name of the DID, None to check the whole scope.
    :param operation: The operation, e.g. `DidOperationType.READ`.
    :param session: The database session.
    """
    return DidAccess(account, session=session).grants(scope, name, operation)


def has_any_scope_prefix_access(account: "InternalAccount", scope: "InternalScope", operation: DidOperationType, *, session: "Session") -> bool:
    """
    Tell whether RBAC grants the account an operation on at least one DID of a scope, whatever its name, see
    :meth:`DidAccess.grants_some_did`: within a role, the pattern deciding the whole scope grants it, or one of the
    name patterns of the role in the scope does.

    For the scope 'data', 'r' on 'data:raw1', 'data:raw*', 'data:*', 'da*:*' or '*:*' all count, 'r' on 'other:*' does not,
    nor does 'r' on 'da*:*' in a role which has '---' on 'data:*'.
    Like :func:`has_did_permission`, only the roles are looked at: not whether RBAC is enabled, root and admin privileges, nor the owner of the scope.

    :param account: The account to check.
    :param scope: The scope.
    :param operation: The operation, e.g. `DidOperationType.READ`.
    :param session: The database session.
    :returns: True if the account's roles grant the operation on some DIDs of the scope.
    """
    return DidAccess(account, session=session).grants_some_did(scope, operation)


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

def sync_roles_from_policy_package_dry_run(*, session: "Session") -> None:
    """
    Synchronizes the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an unlocked role (`assignable` True and
    `locked` False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not locked. A locked role
    (`locked` True) is never touched by the policy package, whether or not
    the policy package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`. A reserved role is never touched either, see `RESERVED_ROLES`.

    This is a dry run: it reports what the synchronisation would do and leaves the database
    untouched.

    :param session: The database session.
    """
    print("Syncing roles... (dry run, nothing is written to the database)")

    # Step 1: Retrieve Roles from the policy package
    roles = permission.get_roles()

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


def sync_roles_from_policy_package(*, session: "Session") -> None:
    """
    Synchronize the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an unlocked role (`assignable` True and
    `locked` False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not locked. A locked role
    (`locked` True) is never touched here, whether or not the policy
    package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`. Neither is a reserved role, see `RESERVED_ROLES`.
    A role which is not locked and which the policy
    package does not define is deleted, together with its permissions and account assignments.

    The whole synchronisation is a single transaction, so either all of it is applied or none of
    it is. See :func:`sync_roles_from_policy_package_dry_run` to report the changes instead of
    applying them.

    :param session: The database session.
    """
    print("Syncing the roles with the policy package...")

    # Step 1: Retrieve Roles from the policy package
    roles = permission.get_roles()

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


# ----------------------------------------------------------------------------------------------
# Cleaning of expired assignments
# ----------------------------------------------------------------------------------------------

def clean_expired_account_roles(dry_run: bool = False, *, session: "Session") -> dict[str, Any]:
    """
    Remove the expired role assignments of every account.

    An expired assignment grants nothing, but it stays in the database until the assignment is
    removed or the account is synchronised with its IdP again, which may never happen. This removes
    all of them at once, whatever the role, since it is Rucio itself, and not an IdP, that does it.

    :param dry_run: Only report what would be removed, without writing to the database.
    :param session: The database session.
    :returns: The report of the cleaning:
              - `dry_run`, `cleaned_at`: whether anything was written, and the time against which the
                expiry dates were compared.
              - `removed`: the expired assignments which were (or would be) removed, each with its
                account, role and expiry date.
              - `summary`: a one-line summary of the cleaning.
    """
    # the dates are stored as naive UTC datetimes, so compare them against a naive UTC now
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    stmt = (
        select(models.AccountRoleAssociation.account, models.AccountRoleAssociation.role, models.AccountRoleAssociation.expires_at)
        .where(models.AccountRoleAssociation.expires_at.is_not(None), models.AccountRoleAssociation.expires_at < now)
        .order_by(models.AccountRoleAssociation.account, models.AccountRoleAssociation.role)
    )
    expired = session.execute(stmt).all()

    if not dry_run:
        for account, role, _ in expired:
            session.execute(
                delete(models.AccountRoleAssociation)
                .where(models.AccountRoleAssociation.account == account, models.AccountRoleAssociation.role == role)
            )

    verb = "Would remove" if dry_run else "Removed"
    return {
        "dry_run": dry_run,
        "cleaned_at": now,
        "removed": [{"account": account.external, "role": role, "expires_at": expires_at} for account, role, expires_at in expired],
        "summary": "%s %d expired role assignment(s), as of %s." % (verb, len(expired), now),
    }
