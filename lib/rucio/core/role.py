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
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccountNotFound, Duplicate, InputValidationError, RoleAssignmentDisabled, RoleAssignmentNotFound, RoleInUse, RoleNotFound, RolePermissionNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import DATE_FORMAT, str_to_date
from rucio.core import permission
from rucio.core.scope import is_scope_owner
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType

if TYPE_CHECKING:
    from collections.abc import Iterator

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
    List all roles defined in the system, together with their description, assignment_disabled and internal_role_flag state.
    """
    stmt = select(models.Roles.role, models.Roles.description, models.Roles.assignment_disabled, models.Roles.internal_role_flag).order_by(models.Roles.role)
    return [
        {"role": role, "description": description, "assignment_disabled": assignment_disabled, "internal_role_flag": internal_role_flag}
        for role, description, assignment_disabled, internal_role_flag in session.execute(stmt).all()
    ]


def add_role(role: str, description: Optional[str] = None, assignment_disabled: bool = False, internal_role_flag: bool = False, *, session: "Session") -> None:
    """
    Add a new role to the system.

    :param role: The name of the role to add.
    :param description: An optional description of the role. An empty description is stored as NULL.
    :param assignment_disabled: Whether an identity provider is barred from assigning this role to, or taking it away from, an account; only Rucio itself then alters who holds it.
    :param internal_role_flag: Whether the role is flagged as internal.
    :param session: The database session.
    """
    new_role = models.Roles(role=role, description=_normalize_description(description), assignment_disabled=assignment_disabled, internal_role_flag=internal_role_flag)
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
        assignment_disabled: Optional[bool] = None,
        internal_role_flag: Optional[bool] = None,
        session: "Session") -> dict[str, Any]:
    """
    Update the metadata of an existing role, changing only the parameters explicitly given.

    :param role: The role to update.
    :param description: The new description, or None to leave it untouched. An empty string clears it (stored as NULL).
    :param assignment_disabled: The new assignment_disabled state, or None to leave it untouched.
    :param internal_role_flag: The new internal_role_flag state, or None to leave it untouched.
    :param session: The database session.
    :returns: The role as it is stored after the update.
    :raises RoleNotFound: If the role does not exist.
    """
    stmt = select(models.Roles).where(models.Roles.role == role)
    role_obj = session.execute(stmt).scalar_one_or_none()
    if role_obj is None:
        raise RoleNotFound("Role '%s' does not exist." % role)

    if description is not None:
        role_obj.description = _normalize_description(description)
    if assignment_disabled is not None:
        role_obj.assignment_disabled = assignment_disabled
    if internal_role_flag is not None:
        role_obj.internal_role_flag = internal_role_flag

    session.commit()
    return {
        "role": role,
        "description": role_obj.description,
        "assignment_disabled": role_obj.assignment_disabled,
        "internal_role_flag": role_obj.internal_role_flag,
    }


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


def _role_assignment_disabled(role: str, session: "Session") -> bool:
    """Tell whether a role has `assignment_disabled` set. False (also) for a role which does not exist."""
    stmt = select(models.Roles.assignment_disabled).where(models.Roles.role == role)
    return bool(session.execute(stmt).scalar_one_or_none())


def add_account_role(account: "InternalAccount", role: str, expires_at: Optional[Union[str, datetime]] = None, force: bool = False, *, session: "Session") -> None:
    """
    Assign a role to an account.

    :param account: The account to assign the role to.
    :param role: The role to assign.
    :param expires_at: An optional date at which the assignment expires. None means that it does not expire.
    :param force: Assign the role even if it has `assignment_disabled` set.
    :param session: The database session.
    :raises RoleAssignmentDisabled: If the role has `assignment_disabled` set and `force` is not given.
    """
    if not force and _role_assignment_disabled(role, session):
        raise RoleAssignmentDisabled("Role '%s' has assignment_disabled set, so it cannot be assigned to an account without forcing it." % role)

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
    :param force: Remove the role even if it has `assignment_disabled` set.
    :param session: The database session.
    :raises RoleAssignmentNotFound: If the account does not have the role assigned.
    :raises RoleAssignmentDisabled: If the role has `assignment_disabled` set and `force` is not given.
    """
    mapping = session.get(models.AccountRoleAssociation, (account, role))
    if mapping is None:
        raise RoleAssignmentNotFound("Either account '%s' or role '%s' does not exist, or the account does not have that role assigned." % (account, role))

    if not force and _role_assignment_disabled(role, session):
        raise RoleAssignmentDisabled("Role '%s' has assignment_disabled set, so it cannot be removed from an account without forcing it." % role)

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


def add_role_permission(role: str, scope_pattern: str, operation: "DatabaseOperationType", session: "Session") -> None:
    """
    Grant a role a permission on a scope pattern.

    :param role: The role to grant the permission to.
    :param scope_pattern: The scope pattern to grant the permission on; only a trailing '*' wildcard is accepted, see :func:`_validate_scope_pattern`.
    :param operation: The operation to grant.
    :param session: The database session.
    :raises InputValidationError: If the scope pattern is not a trailing wildcard.
    :raises RoleNotFound: If the role does not exist.
    :raises Duplicate: If the role already has that permission on that scope pattern.
    """
    scope_pattern = _validate_scope_pattern(scope_pattern)

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


def delete_role_permission(role: str, scope_pattern: str, operation: "DatabaseOperationType", session: "Session") -> None:
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


def _print_table(headers: list[str], rows: list[list[Any]], indent: str = "  ") -> None:
    """Print a small left-aligned table, or a placeholder if there is nothing to show."""
    if not rows:
        print("%s(none)" % indent)
        return

    cells = [["" if cell is None else str(cell) for cell in row] for row in rows]
    widths = [max([len(header)] + [len(row[index]) for row in cells]) for index, header in enumerate(headers)]
    print(indent + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print(indent + "-+-".join("-" * width for width in widths))
    for row in cells:
        print(indent + " | ".join(row[index].ljust(widths[index]) for index in range(len(headers))))


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


def _assignment_disabled(role: str, known_roles: dict[str, Any]) -> bool:
    """
    Tell whether a role's assignment_disabled flag is set.

    The assignments of such a role may only be altered from within Rucio: an identity
    provider can neither have it assigned to an account nor taken away from one.
    """
    entry = known_roles.get(role)
    return bool(entry and entry.get("assignment_disabled"))


def sync_roles_from_policy_package_dry_run(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronizes the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an external role (`assignment_disabled` and
    `internal_role_flag` both False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not flagged internal. A role flagged
    internal (`internal_role_flag` True) is never touched by the policy package, whether or not
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
        ["ROLE", "DESCRIPTION", "INTERNAL"],
        [[role, entry["description"] or "", "yes" if entry["internal_role_flag"] else "no"] for role, entry in sorted(current.items())],
    )

    print()
    print("Step 3: What the synchronisation would do")
    created, updated, unchanged, skipped_internal, deleted = 0, 0, 0, 0, 0

    for role in sorted(roles):
        description = _normalize_description(roles[role].get("description"))

        if role not in current:
            created += 1
            print("  Role '%s' does not exist yet, so it would be created with description %r." % (role, description))
            continue

        if current[role]["internal_role_flag"]:
            skipped_internal += 1
            print("  Role '%s' is flagged internal, so it would be left untouched." % role)
            continue

        if current[role]["description"] != description:
            updated += 1
            print("  Role '%s': description would change from %r to %r." % (role, current[role]["description"], description))
        else:
            unchanged += 1
            print("  Role '%s' is already in line with the policy package." % role)

    # a role which is not internal and which the policy package does not define goes, including
    # one that was created by hand through the CLI; a role flagged internal is out of the policy
    # package's reach entirely, so it is left untouched even if the policy package does not define it
    for role in sorted(set(current) - set(roles)):
        if current[role]["internal_role_flag"]:
            skipped_internal += 1
            print("  Role '%s' is not defined by the policy package but is flagged internal, so it would be left untouched." % role)
        else:
            deleted += 1
            print("  Role '%s' is not defined by the policy package, so it would be deleted." % role)

    print()
    print("Summary: would create %d role(s), update %d, delete %d, leave %d unchanged, leave %d internal role(s) untouched."
          % (created, updated, deleted, unchanged, skipped_internal))


def _delete_role_with_references(role: str, *, session: "Session") -> tuple[int, int]:
    """
    Delete a role together with the rows referencing it.

    `account_role_map.role` and `role_permission_map.role` reference `roles.role`, so the
    database refuses to delete a role which is still assigned to an account or still carries
    permissions. Those rows are therefore removed first, which keeps the deletion working
    whatever referential action the foreign keys are declared with, see :func:`_role_delete_rules`.

    :param role: The role to delete.
    :param session: The database session.
    :returns: The number of permissions and of account assignments removed along with the role.
    """
    revoked = session.execute(delete(models.RolePermissionAssociation).where(models.RolePermissionAssociation.role == role)).rowcount
    unassigned = session.execute(delete(models.AccountRoleAssociation).where(models.AccountRoleAssociation.role == role)).rowcount
    session.execute(delete(models.Roles).where(models.Roles.role == role))
    return revoked, unassigned


def sync_roles_from_policy_package(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronize the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the description of the roles it defines, not
    for their permissions or their account assignments, which are managed from within Rucio. A
    role the policy package defines is created, as an external role (`assignment_disabled` and
    `internal_role_flag` both False), if it does not exist yet, or has its description brought
    in line with the policy package if it exists and is not flagged internal. A role flagged
    internal (`internal_role_flag` True) is never touched here, whether or not the policy
    package defines it: such a role is managed entirely from within Rucio, see
    :func:`sync_account_roles_from_idp`. A role which is not internal and which the policy
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

    created, updated, unchanged, skipped_internal, deleted = 0, 0, 0, 0, 0
    revoked, unassigned = 0, 0

    try:
        # Step 3: Create the roles of the policy package and bring the existing, non-internal
        # ones in line with it. A role flagged internal is left untouched.
        for role in sorted(roles):
            description = _normalize_description(roles[role].get("description"))

            if role not in current:
                session.add(models.Roles(role=role, description=description, assignment_disabled=False, internal_role_flag=False))
                created += 1
                print("  Role '%s' created with description %r." % (role, description))
                continue

            if current[role]["internal_role_flag"]:
                skipped_internal += 1
                print("  Role '%s' is flagged internal, so it is left untouched." % role)
                continue

            if current[role]["description"] != description:
                session.execute(update(models.Roles).where(models.Roles.role == role).values(description=description))
                updated += 1
                print("  Role '%s': description changed from %r to %r." % (role, current[role]["description"], description))
            else:
                unchanged += 1

        # Step 4: Delete the roles the policy package does not define any more, including the
        # ones that were created by hand through the CLI, unless they are flagged internal, which
        # takes them entirely out of the policy package's reach. Neither foreign key to `roles`
        # can be relied on to cascade, so each deleted role takes its permissions and its account
        # assignments along explicitly.
        for role in sorted(set(current) - set(roles)):
            if current[role]["internal_role_flag"]:
                skipped_internal += 1
                print("  Role '%s' is not defined by the policy package but is flagged internal, so it is left untouched." % role)
                continue

            role_revoked, role_unassigned = _delete_role_with_references(role, session=session)
            deleted += 1
            revoked += role_revoked
            unassigned += role_unassigned
            print("  Role '%s' is not defined by the policy package, so it was deleted with its %d permission(s) and %d account assignment(s)."
                  % (role, role_revoked, role_unassigned))

        session.commit()
    except Exception:
        session.rollback()
        print("  The synchronisation failed, so nothing reported above was applied.")
        raise

    print()
    print("Summary: created %d role(s), updated %d, deleted %d, left %d unchanged, left %d internal role(s) untouched; removed %d permission(s) and %d account assignment(s) with the deleted roles."
          % (created, updated, deleted, unchanged, skipped_internal, revoked, unassigned))


def sync_account_roles_from_idp_dry_run(account: Union[str, "InternalAccount"], roles: Any, vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronize an account's role assignments with roles supplied by an IdP.

    A role with assignment_disabled set is off limits to the identity provider: it is neither
    assigned to nor removed from an account here, and its expiry date is left as it is. Only
    Rucio itself can alter who holds such a role.

    This is a dry run: it reports what the synchronisation would do and leaves the database
    untouched.

    :param account: The account whose role assignments would be synchronised, as an
                    InternalAccount or as a plain account name.
    :param roles: The roles supplied by the IdP, in any of the forms :func:`_parse_idp_roles` accepts.
    :param vo: The VO the account belongs to, used when the account is given by name.
    :param session: The database session.
    """
    # ! Check if the account retrieval should be done here or in a specialized cron job.
    # ! If so, just change this function to sync one account with its roles

    # an account name is accepted as well, so that a tool or a daemon does not have to build
    # an InternalAccount of its own
    if isinstance(account, str):
        account = InternalAccount(account, vo=vo)
    print("Syncing the roles of account '%s'... (dry run, nothing is written to the database)" % account)

    desired = _parse_idp_roles(roles)
    known_roles = {entry["role"]: entry for entry in list_roles(session=session)}

    print()
    print("Roles supplied by the IdP")
    _print_table(
        ["ROLE", "EXPIRES AT", "KNOWN TO RUCIO", "ASSIGNMENT DISABLED"],
        [
            [role, _format_expires_at(expires_at), "yes" if role in known_roles else "no", "yes" if _assignment_disabled(role, known_roles) else "no"]
            for role, expires_at in sorted(desired.items())
        ],
    )

    # Step 1: Retrieve the roles assigned to the account (AccountRoleAssociation)
    current = {entry["role"]: entry["expires_at"] for entry in list_account_roles(account, session=session)}

    print()
    print("Step 1: Retrieve the roles assigned to the account")
    _print_table(
        ["ROLE", "EXPIRES AT", "ASSIGNMENT DISABLED"],
        [[role, _format_expires_at(expires_at), "yes" if _assignment_disabled(role, known_roles) else "no"] for role, expires_at in sorted(current.items())],
    )

    # Step 2: Cleaning:
    # A role with assignment_disabled set is skipped at every step below, since an identity
    # provider must not alter who holds it.
    now = datetime.utcnow()
    print()
    print("Step 2: Cleaning, as of %s" % now)
    # a role is only reported the first time it is held back, so that the same role is not
    # mentioned once per step
    held_back: set[str] = set()

    def _hold_back(role: str, message: str) -> bool:
        """Report that assignment_disabled keeps a change from being applied, once per role."""
        if not _assignment_disabled(role, known_roles):
            return False
        if role not in held_back:
            held_back.add(role)
            print(message)
        return True

    # 2.1 Remove expired roles from the account (AccountRoleAssociation) (expires_at < now)
    expired: dict[str, datetime] = {}
    for role, expires_at in sorted(current.items()):
        if expires_at is None or expires_at >= now:
            continue
        if _hold_back(role, "  2.1 Role '%s' expired at %s but has assignment_disabled set, so the assignment would be left untouched." % (role, expires_at)):
            continue
        expired[role] = expires_at
        print("  2.1 Role '%s' expired at %s, so the assignment would be removed." % (role, expires_at))

    # what is left after 2.1 is what the remaining steps compare against
    remaining = {role: expires_at for role, expires_at in current.items() if role not in expired}

    # 2.2 Remove roles from the account that are not in the list of roles from the IDP (AccountRoleAssociation)
    to_remove = []
    for role in sorted(set(remaining) - set(desired)):
        if _hold_back(role, "  2.2 Role '%s' is not supplied by the IdP but has assignment_disabled set, so the assignment would be kept." % role):
            continue
        to_remove.append(role)
        print("  2.2 Role '%s' is not supplied by the IdP, so the assignment would be removed." % role)

    # 2.3 Add roles to the account that are in the list of roles from the IDP but not in the account's current roles (AccountRoleAssociation)
    to_add, unknown = [], []
    for role in sorted(set(desired) - set(remaining)):
        if role not in known_roles:
            unknown.append(role)
            print("  2.3 Role '%s' is supplied by the IdP but does not exist in Rucio, so it cannot be assigned." % role)
            continue
        if _hold_back(role, "  2.3 Role '%s' has assignment_disabled set, so the IdP cannot have it assigned to the account." % role):
            continue
        to_add.append(role)
        print("  2.3 Role '%s' would be assigned, expiring %s." % (role, _format_expires_at(desired[role])))

    # 2.4 Update the expires_at of the roles that are in both the account's current roles and the list of roles from the IDP (AccountRoleAssociation)
    to_update, unchanged = [], 0
    for role in sorted(set(desired) & set(remaining)):
        if desired[role] == remaining[role]:
            unchanged += 1
            continue
        if _hold_back(role, "  2.4 Role '%s' has assignment_disabled set, so its expiry date of %s would be kept instead of %s."
                            % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role]))):
            continue
        to_update.append(role)
        print("  2.4 Role '%s' would have its expiry date changed from %s to %s."
              % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role])))

    print()
    print("Summary: would remove %d assignment(s) (%d expired, %d no longer supplied), add %d, change the expiry date of %d, leave %d unchanged; %d role(s) held back by assignment_disabled; %d role(s) supplied by the IdP are unknown to Rucio."
          % (len(expired) + len(to_remove), len(expired), len(to_remove), len(to_add), len(to_update), unchanged, len(held_back), len(unknown)))
