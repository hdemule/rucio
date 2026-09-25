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

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy import delete, or_, select, update
from sqlalchemy.exc import IntegrityError

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccountNotFound, Duplicate, InputValidationError, RoleAssignmentDisabled, RoleAssignmentNotFound, RoleInUse, RoleNotFound, RolePermissionNotFound, RoleProtected
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import DATE_FORMAT, str_to_date
from rucio.core import permission
from rucio.core.scope import is_scope_owner
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from sqlalchemy.orm import Session


# the only wildcard a scope pattern may use, see `_validate_scope_pattern`
SCOPE_WILDCARD = "*"


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
    List all roles defined in the system, together with their description, assignable and protected state.
    """
    stmt = select(models.Roles.role, models.Roles.description, models.Roles.assignable, models.Roles.protected).order_by(models.Roles.role)
    return [
        {"role": role, "description": description, "assignable": assignable, "protected": protected}
        for role, description, assignable, protected in session.execute(stmt).all()
    ]


def add_role(role: str, description: Optional[str] = None, assignable: bool = True, protected: bool = False, *, session: "Session") -> None:
    """
    Add a new role to the system.

    :param role: The name of the role to add.
    :param description: An optional description of the role. An empty description is stored as NULL.
    :param assignable: Whether an identity provider may assign this role to, or take it away from, an account; if not, only Rucio itself alters who holds it.
    :param protected: Whether the role is protected, which prevents a policy package from altering or deleting it.
    :param session: The database session.
    """
    new_role = models.Roles(role=role, description=_normalize_description(description), assignable=assignable, protected=protected)
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
        protected: Optional[bool] = None,
        force: bool = False,
        session: "Session") -> dict[str, Any]:
    """
    Update the metadata of an existing role, changing only the parameters explicitly given.

    A protected role cannot have its description or its assignable state changed, unless `force`
    is given. Changing `protected` itself is always allowed, so that a role can be unprotected.

    :param role: The role to update.
    :param description: The new description, or None to leave it untouched. An empty string clears it (stored as NULL).
    :param assignable: The new assignable state, or None to leave it untouched.
    :param protected: The new protected state, or None to leave it untouched.
    :param force: Change the description or the assignable state even if the role is protected.
    :param session: The database session.
    :returns: The role as it is stored after the update.
    :raises RoleNotFound: If the role does not exist.
    :raises RoleProtected: If the role is protected, `force` is not given and something besides `protected` is being changed.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    if description is not None or assignable is not None:
        _ensure_unprotected(role, force, session)

    if description is not None:
        role_obj.description = _normalize_description(description)
    if assignable is not None:
        role_obj.assignable = assignable
    if protected is not None:
        role_obj.protected = protected

    session.commit()
    return {
        "role": role,
        "description": role_obj.description,
        "assignable": role_obj.assignable,
        "protected": role_obj.protected,
    }


def delete_role(role: str, force: bool = False, *, session: "Session") -> None:
    """
    Delete an existing role from the system.

    A protected role is only deleted if `force` is given.

    :param role: The role to delete.
    :param force: Also remove the role from every account it is assigned to and drop its permissions,
                  instead of refusing to delete a role which is still in use, and delete it even if it is protected.
    :param session: The database session.
    :raises RoleNotFound: If the role does not exist.
    :raises RoleProtected: If the role is protected and `force` is not set.
    :raises RoleInUse: If the role is still in use and `force` is not set.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    _ensure_unprotected(role, force, session, action="deleted")

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


def list_role_accounts(role: str, session: "Session") -> list[dict[str, Any]]:
    """
    List the accounts a role is assigned to, together with the expiry date of each assignment.

    An `expires_at` of None means that the assignment does not expire.

    :raises RoleNotFound: If the role does not exist.
    """
    if session.execute(select(models.Roles.role).where(models.Roles.role == role)).scalar_one_or_none() is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    stmt = (
        select(models.AccountRoleAssociation.account, models.AccountRoleAssociation.expires_at)
        .where(models.AccountRoleAssociation.role == role)
        .order_by(models.AccountRoleAssociation.account)
    )
    return [{"account": account, "expires_at": expires_at} for account, expires_at in session.execute(stmt).all()]


def _ensure_unprotected(role: str, force: bool, session: "Session", action: str = "altered") -> None:
    """
    Refuse to touch a protected role, unless forced. Does nothing for a role which does not exist.

    :param role: The role about to be touched.
    :param force: Touch the role even if it is protected.
    :param session: The database session.
    :param action: What is about to be done to the role, for the error message.
    :raises RoleProtected: If the role is protected and `force` is not given.
    """
    if force:
        return

    stmt = select(models.Roles.protected).where(models.Roles.role == role)
    if session.execute(stmt).scalar_one_or_none():
        raise RoleProtected("Role '%s' is protected, so it cannot be %s." % (role, action))


def _role_not_assignable(role: str, session: "Session") -> bool:
    """Tell whether a role is not assignable. False (also) for a role which does not exist."""
    stmt = select(models.Roles.assignable).where(models.Roles.role == role)
    return session.execute(stmt).scalar_one_or_none() is False


def add_account_role(account: "InternalAccount", role: str, expires_at: Optional[Union[str, datetime]] = None, force: bool = False, *, session: "Session") -> None:
    """
    Assign a role to an account.

    :param account: The account to assign the role to.
    :param role: The role to assign.
    :param expires_at: An optional date at which the assignment expires. None means that it does not expire.
    :param force: Assign the role even if it is not assignable.
    :param session: The database session.
    :raises RoleAssignmentDisabled: If the role is not assignable and `force` is not given.
    """
    if not force and _role_not_assignable(role, session):
        raise RoleAssignmentDisabled("Role '%s' is not assignable, so it cannot be assigned to an account." % role)

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
    """
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    normalized = _normalize_expires_at(expires_at)
    mapping.expires_at = normalized
    session.commit()
    return normalized


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


def list_role_permissions(role: str, session: "Session") -> list[dict[str, str]]:
    """
    List the permissions granted to a role, each as an operation on a scope pattern.

    :raises RoleNotFound: If the role does not exist.
    """
    if session.execute(select(models.Roles.role).where(models.Roles.role == role)).scalar_one_or_none() is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    stmt = (
        select(models.RolePermissionAssociation)
        .where(models.RolePermissionAssociation.role == role)
        .order_by(models.RolePermissionAssociation.scope_pattern, models.RolePermissionAssociation.operation)
    )
    return [{"operation": permission.operation.value, "scope_pattern": permission.scope_pattern} for permission in session.execute(stmt).scalars()]


def add_role_permission(role: str, scope_pattern: str, operation: "DatabaseOperationType", force: bool = False, *, session: "Session") -> None:
    """
    Grant a role a permission on a scope pattern.

    :param role: The role to grant the permission to.
    :param scope_pattern: The scope pattern to grant the permission on; only a trailing '*' wildcard is accepted, see :func:`_validate_scope_pattern`.
    :param operation: The operation to grant.
    :param force: Grant the permission even if the role is protected.
    :param session: The database session.
    :raises InputValidationError: If the scope pattern is not a trailing wildcard.
    :raises RoleProtected: If the role is protected and `force` is not given.
    :raises RoleNotFound: If the role does not exist.
    :raises Duplicate: If the role already has that permission on that scope pattern.
    """
    scope_pattern = _validate_scope_pattern(scope_pattern)
    _ensure_unprotected(role, force, session)

    session.add(models.RolePermissionAssociation(role=role, scope_pattern=scope_pattern, operation=operation))
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        if _violates_constraint(error, "ROLE_PERMISSION_MAP_ROLE_FK"):
            raise RoleNotFound("Role '%s' does not exist." % role)
        if _violates_constraint(error, "ROLE_PERMISSION_MAP_PK"):
            raise Duplicate("Role '%s' already has '%s' permission on scope pattern '%s'." % (role, operation.value, scope_pattern))
        raise Duplicate("Either role '%s' does not exist, or it already has '%s' permission on scope pattern '%s'." % (role, operation.value, scope_pattern))


def delete_role_permission(role: str, scope_pattern: str, operation: "DatabaseOperationType", force: bool = False, *, session: "Session") -> None:
    """
    Remove a permission from a role.

    :param role: The role to remove the permission from.
    :param scope_pattern: The scope pattern of the permission.
    :param operation: The operation of the permission.
    :param force: Remove the permission even if the role is protected.
    :param session: The database session.
    :raises RoleProtected: If the role is protected and `force` is not given.
    :raises RolePermissionNotFound: If the role does not have that permission.
    """
    _ensure_unprotected(role, force, session)

    mapping = session.get(models.RolePermissionAssociation, (role, scope_pattern, operation))
    if mapping is None:
        raise RolePermissionNotFound("Either role '%s' does not exist, or it does not have '%s' permission on scope pattern '%s'." % (role, operation.value, scope_pattern))

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

    A role's permission is granted on a scope pattern rather than a single scope, so this
    matches the given scope against the patterns of the account's roles in Python, see
    :func:`_scope_pattern_matches`.

    Role assignments whose `expires_at` is in the past are ignored, so at least one
    matching permission must come from a role assignment that has not expired yet.

    This only check the RBAC tables and does not consider ownership or admin/root privileges.
    For checking ownership or admin/root privileges, use the :func:`has_scope_access` function instead.
    """
    stmt = (
        select(models.RolePermissionAssociation.scope_pattern)
        .select_from(models.AccountRoleAssociation)
        .join(
            models.RolePermissionAssociation,
            models.RolePermissionAssociation.role == models.AccountRoleAssociation.role,
        )
        .where(
            models.AccountRoleAssociation.account == account,
            models.RolePermissionAssociation.operation == operation,
            or_(
                models.AccountRoleAssociation.expires_at.is_(None),
                # expires_at is stored as a naive UTC datetime, so compare it against a naive UTC now
                models.AccountRoleAssociation.expires_at > datetime.now(timezone.utc).replace(tzinfo=None),
            ),
        )
    )

    return any(_scope_pattern_matches(scope, scope_pattern) for scope_pattern in session.execute(stmt).scalars())


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


def scope_access_checker(
    *,
    account: "InternalAccount",
    session: "Session",
    operation: "DatabaseOperationType" = DatabaseOperationType.READ,
) -> "Callable[[Optional[InternalScope]], bool]":
    """
    Build a callable telling whether the account may access a given scope in terms of RBAC, ownership and admin/root privileges.

    Access decisions are cached for the lifetime of the returned callable, so each
    distinct scope is checked at most once. This is meant for responses where the
    scope is not stored under a single dictionary key (e.g. 'scope:name' strings or
    nested dictionaries), for which :func:`filter_iterable_by_scope_access` does not fit.

    :param account: The account for which to check access.
    :param session: The database session.
    :param operation: The type of operation to check access for.
    :returns: A callable taking a scope and returning True if the account may access it. A scope that is None or not an InternalScope is refused.
    """
    access_by_scope: dict["InternalScope", bool] = {}

    def _can_access(scope: "Optional[InternalScope]") -> bool:
        if scope is None or not isinstance(scope, InternalScope):
            return False

        if scope not in access_by_scope:
            access_by_scope[scope] = has_scope_access(
                account=account,
                scope=scope,
                operation=operation,
                session=session,
            )
        return access_by_scope[scope]

    return _can_access


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
    can_access = scope_access_checker(account=account, session=session, operation=operation)

    for item in items:
        if can_access(item.get(scope_keyword)):
            yield item


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
        return {str(role): _normalize_expires_at(expires_at) for role, expires_at in roles.items()}

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

        parsed[role.strip()] = _normalize_expires_at(entry.get("expires_at"))

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


def sync_roles_from_policy_package_dry_run(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronizes the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an unprotected role (`assignable` True and
    `protected` False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not protected. A protected role
    (`protected` True) is never touched by the policy package, whether or not
    the policy package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`.

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
        ["ROLE", "DESCRIPTION", "PROTECTED"],
        [[role, entry["description"] or "", "yes" if entry["protected"] else "no"] for role, entry in sorted(current.items())],
    )

    print()
    print("Step 3: What the synchronisation would do")
    created, updated, unchanged, skipped_protected, deleted = 0, 0, 0, 0, 0

    for role in sorted(roles):
        description = _normalize_description(roles[role].get("description"))

        if role not in current:
            created += 1
            print("  Role '%s' does not exist yet, so it would be created with description %r." % (role, description))
            continue

        if current[role]["protected"]:
            skipped_protected += 1
            print("  Role '%s' is protected, so it would be left untouched." % role)
            continue

        if current[role]["description"] != description:
            updated += 1
            print("  Role '%s': description would change from %r to %r." % (role, current[role]["description"], description))
        else:
            unchanged += 1
            print("  Role '%s' is already in line with the policy package." % role)

    # a role which is not protected and which the policy package does not define goes, including
    # one that was created by hand through the CLI; a protected role is out of the policy
    # package's reach entirely, so it is left untouched even if the policy package does not define it
    for role in sorted(set(current) - set(roles)):
        if current[role]["protected"]:
            skipped_protected += 1
            print("  Role '%s' is not defined by the policy package but is protected, so it would be left untouched." % role)
        else:
            deleted += 1
            print("  Role '%s' is not defined by the policy package, so it would be deleted." % role)

    print()
    print("Summary: would create %d role(s), update %d, delete %d, leave %d unchanged, leave %d protected role(s) untouched."
          % (created, updated, deleted, unchanged, skipped_protected))


def _remove_accounts_from_role(role: str, *, session: "Session") -> int:
    """
    Delete a role together with the rows referencing it.

    `account_role_map.role` and `role_permission_map.role` reference `roles.role`, so the
    database refuses to delete a role which is still assigned to an account or still carries
    permissions. Those rows are therefore removed first, which keeps the deletion working
    whatever referential action the foreign keys are declared with.

    :param role: The role to delete.
    :param session: The database session.
    :returns: The number of permissions and of account assignments removed along with the role.
    """
    unassigned = session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role)).rowcount
    session.execute(delete(models.Roles).where(models.Roles.role == role))
    return unassigned


def sync_roles_from_policy_package(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronize the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an unprotected role (`assignable` True and
    `protected` False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not protected. A protected role
    (`protected` True) is never touched here, whether or not the policy
    package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`. A role which is not protected and which the policy
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

    created, updated, unchanged, skipped_protected, deleted = 0, 0, 0, 0, 0
    revoked, unassigned = 0, 0

    try:
        # Step 3: Create the roles of the policy package and bring the existing, unprotected
        # ones in line with it. A protected role is left untouched.
        for role in sorted(roles):
            description = _normalize_description(roles[role].get("description"))

            if role not in current:
                session.add(models.Roles(role=role, description=description, assignable=True, protected=False))
                created += 1
                print("  Role '%s' created with description %r." % (role, description))
                continue

            if current[role]["protected"]:
                skipped_protected += 1
                print("  Role '%s' is protected, so it is left untouched." % role)
                continue

            if current[role]["description"] != description:
                session.execute(update(models.Roles).where(models.Roles.role == role).values(description=description))
                updated += 1
                print("  Role '%s': description changed from %r to %r." % (role, current[role]["description"], description))
            else:
                unchanged += 1

        # Step 4: Delete the roles the policy package does not define any more, including the
        # ones that were created by hand through the CLI, unless they are protected, which
        # takes them entirely out of the policy package's reach. Neither foreign key to `roles`
        # can be relied on to cascade, so each deleted role takes its permissions and its account
        # assignments along explicitly.
        for role in sorted(set(current) - set(roles)):
            if current[role]["protected"]:
                skipped_protected += 1
                print("  Role '%s' is not defined by the policy package but is protected, so it is left untouched." % role)
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
    print("Summary: created %d role(s), updated %d, deleted %d, left %d unchanged, left %d protected role(s) untouched; removed %d permission(s) and %d account assignment(s) with the deleted roles."
          % (created, updated, deleted, unchanged, skipped_protected, revoked, unassigned))


def _ensure_account_exists(account: "InternalAccount", session: "Session") -> None:
    """
    :raises AccountNotFound: If the account does not exist.
    """
    if session.execute(select(models.Account.account).where(models.Account.account == account)).scalar_one_or_none() is None:
        raise AccountNotFound("Account '%s' does not exist." % account)


def _new_sync_report(
        account: "InternalAccount",
        dry_run: bool,
        now: datetime,
        desired: dict[str, Optional[datetime]],
        current: dict[str, Optional[datetime]],
        known_roles: dict[str, Any]) -> dict[str, Any]:
    """
    Start the report of a synchronisation of an account's roles with an IdP.

    The report is what :func:`sync_account_roles_from_idp` and its dry run return:

    - `account`, `dry_run`, `synced_at`: which account was synchronised, whether anything was
      written, and the time against which expiry dates were compared.
    - `supplied`: the roles supplied by the IdP, with their expiry date, whether Rucio knows them
      and whether they are assignable (None for a role Rucio does not know).
    - `current`: the roles the account held before the synchronisation.
    - `removed_expired`, `removed_unsupplied`, `added`, `updated`, `unchanged`: what was (or, in a
      dry run, would be) done to the assignments of the account.
    - `held_back`: the roles whose assignment was left alone because they are not assignable,
      each with the reason.
    - `ignored_expired`: the roles the IdP supplies with an expiry date which has already passed.
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
        "current": [{"role": role, "expires_at": expires_at, "assignable": _assignable(role)} for role, expires_at in sorted(current.items())],
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
                    "%d role(s) held back because they are not assignable; %d role(s) supplied by the IdP with an already expired date ignored; %d role(s) supplied by the IdP are unknown to Rucio.")
    else:
        template = ("Summary: removed %d assignment(s) (%d expired, %d no longer supplied), added %d, changed the expiry date of %d, left %d unchanged; "
                    "%d role(s) held back because they are not assignable; %d role(s) supplied by the IdP with an already expired date ignored; %d role(s) supplied by the IdP are unknown to Rucio.")
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
    neither assigned nor has its expiry date overwritten with a date in the past.

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
    current = {entry["role"]: entry["expires_at"] for entry in list_account_roles(account, session=session)}
    # expires_at is stored as a naive UTC datetime, so compare it against a naive UTC now
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = _new_sync_report(account, True, now, desired, current, known_roles)
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
        ["ROLE", "EXPIRES AT", "ASSIGNABLE"],
        [[role, _format_expires_at(expires_at), _format_assignable(role, known_roles)] for role, expires_at in sorted(current.items())],
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
    def _supplied_expired(role: str) -> bool:
        """Tell whether the IdP supplies the role with an expiry date which has already passed."""
        expires_at = desired[role]
        return expires_at is not None and expires_at < now

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
    neither assigned nor has its expiry date overwritten with a date in the past.

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
    current = {entry["role"]: entry["expires_at"] for entry in list_account_roles(account, session=session)}

    # expires_at is stored as a naive UTC datetime, so compare it against a naive UTC now
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = _new_sync_report(account, False, now, desired, current, known_roles)
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
            if expires_at is not None and expires_at < now:
                report["ignored_expired"].append({"role": role, "expires_at": expires_at})
                say("  Role '%s' is supplied by the IdP with an expiry date of %s which has already passed, so it was not assigned." % (role, expires_at))
                continue
            session.add(models.AccountRoleAssociation(account=account, role=role, expires_at=expires_at))
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
            if expires_at is not None and expires_at < now:
                report["ignored_expired"].append({"role": role, "expires_at": expires_at})
                say("  Role '%s' is supplied by the IdP with an expiry date of %s which has already passed, so the current expiry date of %s is kept."
                    % (role, expires_at, _format_expires_at(remaining[role])))
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
