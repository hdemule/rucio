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
- Cleaning: remove the expired role assignments of every account.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional, Union, cast

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.exc import IntegrityError

from rucio.common.config import config_get_bool
from rucio.common.constants import ADMIN_ROLE, RESERVED_ROLES
from rucio.common.exception import (
    AccountNotFound,
    Duplicate,
    InputValidationError,
    RoleAssignmentDisabled,
    RoleAssignmentNotFound,
    RoleInUse,
    RoleLocked,
    RoleNotFound,
    RoleReserved,
)
from rucio.common.utils import DATE_FORMAT, str_to_date
from rucio.db.sqla import models

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from sqlalchemy.sql.elements import ColumnElement

    from rucio.common.types import InternalAccount


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
    :param locked: Whether the role is locked, which prevents it from being altered or deleted without `force`.
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
# Cleaning of expired assignments
# ----------------------------------------------------------------------------------------------

def clean_expired_account_roles(dry_run: bool = False, *, session: "Session") -> dict[str, Any]:
    """
    Remove the expired role assignments of every account.

    An expired assignment grants nothing, but it stays in the database until the assignment is
    removed, which may never happen. This removes all of them at once, whatever the role, since it
    is Rucio itself that does it.

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
