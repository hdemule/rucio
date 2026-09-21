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

from sqlalchemy import exists, inspect, select
from sqlalchemy.exc import IntegrityError

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccountNotFound, Duplicate, InputValidationError, RoleAssignmentNotFound, RoleInUse, RoleNotFound, RolePermissionNotFound, ScopeNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import DATE_FORMAT, str_to_date
from rucio.core import permission
from rucio.core.scope import is_scope_owner
from rucio.db.sqla import models
from rucio.db.sqla.constants import DatabaseOperationType

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session


# the only wildcard a policy package may use in a scope, see `_scope_like_pattern`
SCOPE_WILDCARD = "*"

# the tables referencing `roles.role`, which a role deletion has to deal with
ROLE_REFERENCES = {
    "account_role_map": "ACCOUNT_ROLE_MAP_ROLE_FK",
    "role_permission_map": "ROLE_PERMISSION_MAP_ROLE_FK",
}


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

    An identity provider cannot assign a locked role to an account or take it away from one, so only Rucio itself alters who holds it. The definition of the role is not protected: the policy package remains its source of truth.

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


def _format_operations(operations: "Iterable[str]") -> str:
    """Join operation names for display, e.g. 'read+write'."""
    return "+".join(sorted(operations)) or "-"


def _format_expires_at(expires_at: Optional[datetime]) -> str:
    """Render the expiry date of a role assignment, 'never' if it does not expire."""
    return "never" if expires_at is None else str(expires_at)


def _parse_operations(action: Any) -> set["DatabaseOperationType"]:
    """
    Turn the action of a policy package permission into the database operations it grants.

    Accepted forms are an rw-style mask ('rw', 'r-', '-w'), a single operation
    ('read', 'write') or a list of any of those.

    :param action: The action as defined by the policy package.
    :returns: The operations the action grants.
    :raises InputValidationError: If the action is not understood.
    """
    if isinstance(action, (list, tuple, set)):
        operations: set[DatabaseOperationType] = set()
        for item in action:
            operations |= _parse_operations(item)
        return operations

    if not isinstance(action, str):
        raise InputValidationError("permission action must be a string, got '%s'." % type(action).__name__)

    text = action.strip().lower()
    if text in (DatabaseOperationType.READ.value, DatabaseOperationType.WRITE.value):
        return {DatabaseOperationType(text)}

    # an rw-style mask, in which a '-' stands for a permission that is not granted
    if text and set(text) <= {"r", "w", "-"}:
        return {operation for character, operation in (("r", DatabaseOperationType.READ), ("w", DatabaseOperationType.WRITE)) if character in text}

    raise InputValidationError("permission action '%s' is not understood, expected 'read', 'write' or an rw-style mask such as 'rw' or 'r-'." % action)


def _role_delete_rules(session: "Session") -> dict[str, str]:
    """
    Return the delete rule of each foreign key referencing `roles`.

    A role cannot be deleted while it is still assigned to an account or still has permissions:
    either the rows of `account_role_map` and `role_permission_map` go first, or the database
    takes them along, which it only does for a foreign key declared ON DELETE CASCADE.

    :param session: The database session.
    :returns: The delete rule of each foreign key, by constraint name.
    """
    inspector = inspect(session.get_bind())
    schema = models.BASE.metadata.schema
    rules = {}

    for table, constraint in sorted(ROLE_REFERENCES.items()):
        for foreign_key in inspector.get_foreign_keys(table, schema=schema):
            if foreign_key.get("referred_table") != "roles":
                continue
            rule = ((foreign_key.get("options") or {}).get("ondelete") or "NO ACTION").upper()
            rules[foreign_key.get("name") or constraint] = rule

    return rules


def _scope_like_pattern(pattern: str, vo: str) -> str:
    """
    Turn a scope pattern of the policy package into the SQL LIKE pattern it stands for.

    A '*' is the only wildcard, and it is only accepted on its own ('*', every scope of the
    VO) or at the end of a scope ('data*', every scope starting with 'data'). A leading or
    embedded wildcard is refused: it cannot be answered from the index on `scopes.scope`, and
    it over-matches in ways that are hard to review, which is a poor property for something
    that grants access.

    :param pattern: The scope pattern as defined by the policy package.
    :param vo: The VO the pattern applies to, so that it cannot reach into another one.
    :returns: The pattern to hand to a LIKE, escaped with a backslash.
    :raises InputValidationError: If the wildcard is not a trailing one.
    """
    if pattern.count(SCOPE_WILDCARD) > 1 or (SCOPE_WILDCARD in pattern and not pattern.endswith(SCOPE_WILDCARD)):
        raise InputValidationError(
            "scope pattern '%s' is not supported, a '*' may only stand on its own or close a scope, as in 'data*'." % pattern)

    literal = pattern[:-1] if pattern.endswith(SCOPE_WILDCARD) else pattern
    # '%', '_' and the escape character itself are ordinary characters in a scope name, so
    # they must not be taken for LIKE wildcards
    escaped = literal.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    if pattern.endswith(SCOPE_WILDCARD):
        escaped += SCOPE_WILDCARD

    # the internal representation carries the VO ('data@tst' outside the default VO), so the
    # conversion has to happen before the wildcard is translated, which keeps the VO anchored
    # at the end of the pattern
    return InternalScope(escaped, vo=vo).internal.replace(SCOPE_WILDCARD, '%')


def _matching_scopes(pattern: str, vo: str, *, session: "Session") -> list[str]:
    """
    Return the existing scopes a scope pattern of the policy package covers.

    The matching is left to the database, so that a trailing wildcard is answered from the
    index on `scopes.scope`.

    :param pattern: The scope pattern as defined by the policy package.
    :param vo: The VO the pattern applies to.
    :param session: The database session.
    :returns: The external names of the matching scopes.
    """
    stmt = select(models.Scope.scope).where(models.Scope.scope.like(_scope_like_pattern(pattern, vo), escape='\\'))
    if vo == DEFAULT_VO:
        # the internal name of a scope of the default VO carries no VO at all, so a pattern of
        # that VO would otherwise reach the scopes of the other VOs of a multi-VO instance,
        # whose internal name ends in '@<vo>'. A '@' cannot appear in a scope name itself.
        stmt = stmt.where(~models.Scope.scope.like('%@%'))
    return sorted(str(scope) for scope in session.execute(stmt).scalars())


def _format_scope_list(scopes: list[str], limit: int = 4) -> str:
    """Render the scopes a pattern expanded to, shortened once there are too many to read."""
    if not scopes:
        return "(no scope matches)"
    if len(scopes) <= limit:
        return ", ".join(scopes)
    return "%s, ... (%d scopes)" % (", ".join(scopes[:limit]), len(scopes))


def _policy_package_permissions(role: str, definition: dict[str, Any], vo: str, *, session: "Session") -> tuple[set[tuple[str, str]], list[list[str]], list[str]]:
    """
    Turn the permissions of a policy package role definition into (scope, operation) pairs.

    A scope pattern is expanded to the scopes it matches at this point, since
    `role_permission_map.scope` references `scopes.scope` and therefore only holds scopes
    which exist. A scope created later is picked up by the next synchronisation.

    :param role: The name of the role, used in the warnings.
    :param definition: The role definition as provided by the policy package.
    :param vo: The VO the role belongs to.
    :param session: The database session.
    :returns: The pairs the role should grant, the declared permissions for display, and the
              warnings about entries which cannot be applied.
    """
    pairs: set[tuple[str, str]] = set()
    declared: list[list[str]] = []
    warnings: list[str] = []

    for entry in definition.get("permissions") or []:
        if not isinstance(entry, dict):
            warnings.append("Role '%s': permission entry %r is not a mapping, so it is ignored." % (role, entry))
            continue

        scope = entry.get("scope")
        if not isinstance(scope, str) or not scope.strip():
            warnings.append("Role '%s': permission entry %r has no scope, so it is ignored." % (role, entry))
            continue
        scope = scope.strip()

        try:
            operations = _parse_operations(entry.get("action"))
        except InputValidationError as error:
            warnings.append("Role '%s': %s" % (role, error))
            continue
        operations_shown = _format_operations(operation.value for operation in operations)

        if SCOPE_WILDCARD not in scope:
            declared.append([scope, operations_shown, ""])
            for operation in operations:
                pairs.add((scope, operation.value))
            continue

        try:
            matches = _matching_scopes(scope, vo, session=session)
        except InputValidationError as error:
            warnings.append("Role '%s': %s" % (role, error))
            declared.append([scope, operations_shown, "(unsupported pattern)"])
            continue

        if not matches:
            warnings.append("Role '%s': scope pattern '%s' matches no scope, so %s is granted nowhere." % (role, scope, operations_shown))
        declared.append([scope, operations_shown, _format_scope_list(matches)])
        for matched in matches:
            for operation in operations:
                pairs.add((matched, operation.value))

    return pairs, declared, warnings


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


def _scope_note(scope: str, known_scopes: set[str]) -> str:
    """Point out that a permission references a scope which does not exist in Rucio."""
    return "" if scope in known_scopes else " (note: scope '%s' does not exist in Rucio, so the permission cannot be granted)" % scope


def _is_locked(role: str, known_roles: dict[str, Any]) -> bool:
    """
    Tell whether a role is locked.

    The assignments of a locked role may only be altered from within Rucio: an identity
    provider can neither have it assigned to an account nor taken away from one.
    """
    entry = known_roles.get(role)
    return bool(entry and entry.get("locked"))


def sync_roles_from_policy_package(vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronizes the internal roles with the roles defined by the policy package.

    The policy package is the source of truth for the roles themselves: every role it defines
    is brought in line with it, and a role it does not define is deleted, together with the
    permissions and the account assignments that role has. The `locked` flag does not apply
    here, it only keeps an identity provider from altering who holds a role, see
    :func:`sync_account_roles_from_idp`.

    This is a dry run: it reports what the synchronisation would do and leaves the database
    untouched.

    :param vo: The VO whose policy package defines the roles.
    :param session: The database session.
    """
    print("Syncing roles... (dry run, nothing is written to the database)")

    # Read the role definitions from the policy package (the `roles` attribute of its role module)
    # Step 1: Retrieve Roles from the policy package
    roles = permission.get_roles(vo=vo)

    desired_permissions: dict[str, set[tuple[str, str]]] = {}
    warnings: list[str] = []
    rows: list[list[Any]] = []
    for role, definition in sorted(roles.items()):
        desired_permissions[role], declared, role_warnings = _policy_package_permissions(role, definition, vo, session=session)
        warnings.extend(role_warnings)

        description = definition.get("description") or ""
        if not declared:
            rows.append([role, description, "", "", ""])
        for index, (scope, operations, matches) in enumerate(declared):
            rows.append([role if index == 0 else "", description if index == 0 else "", scope, operations, matches])

    print()
    print("Step 1: Retrieve Roles from the policy package")
    # a scope pattern is shown as it is declared, next to the scopes it matches today
    _print_table(["ROLE", "DESCRIPTION", "SCOPE", "OPERATION(S)", "MATCHING SCOPES"], rows)
    for warning in warnings:
        print("  Warning: %s" % warning)

    # Step 2: Retreive all roles and their associated permissions (Roles, RolePermissionAssociation)
    # The policy package is the source of truth, so a role it defines is always brought in line
    # with it and a role it does not define is deleted, whether or not the role is locked: a lock
    # only protects the assignments of a role against an identity provider, never the role itself.
    current = {entry["role"]: entry for entry in list_roles(session=session)}
    current_permissions = {
        role: {(entry["scope"], entry["operation"]) for entry in list_role_permissions(role=role, session=session)}
        for role in current
    }
    # `role_permission_map.scope` references `scopes.scope`, so a permission on a scope
    # which does not exist cannot be stored
    known_scopes = {str(scope.external) for scope in session.execute(select(models.Scope.scope)).scalars()}
    # a role that still has permissions or assignments cannot be deleted, so the accounts
    # holding each role are needed to plan a deletion
    accounts_by_role: dict[str, list[str]] = {}
    for assigned_role, assigned_account in session.execute(select(models.AccountRoleAssociation.role, models.AccountRoleAssociation.account)).all():
        accounts_by_role.setdefault(assigned_role, []).append(str(assigned_account))

    rows = []
    for role in sorted(current):
        operations_by_scope = {}
        for scope, operation in current_permissions[role]:
            operations_by_scope.setdefault(scope, set()).add(operation)

        description = current[role]["description"] or ""
        if not operations_by_scope:
            rows.append([role, description, "", ""])
        for index, (scope, operations) in enumerate(sorted(operations_by_scope.items())):
            rows.append([role if index == 0 else "", description if index == 0 else "", scope, _format_operations(operations)])

    print()
    print("Step 2: Retreive all roles and their associated permissions")
    _print_table(["ROLE", "DESCRIPTION", "SCOPE", "OPERATION(S)"], rows)

    print()
    print("Step 3: What the synchronisation would do")
    created, updated, unchanged, deleted = 0, 0, 0, 0
    granted, revoked, unassigned = 0, 0, 0

    for role in sorted(roles):
        wanted = desired_permissions[role]
        description = roles[role].get("description")

        if role not in current:
            created += 1
            granted += len(wanted)
            print("  Role '%s' does not exist yet, so it would be created with description %r." % (role, description))
            for scope, operation in sorted(wanted):
                print("    would grant %s on scope '%s'%s" % (operation, scope, _scope_note(scope, known_scopes)))
            continue

        changes = []
        if (current[role]["description"] or None) != (description or None):
            changes.append("would change the description from %r to %r" % (current[role]["description"], description))
        for scope, operation in sorted(wanted - current_permissions[role]):
            changes.append("would grant %s on scope '%s'%s" % (operation, scope, _scope_note(scope, known_scopes)))
            granted += 1
        for scope, operation in sorted(current_permissions[role] - wanted):
            changes.append("would revoke %s on scope '%s'" % (operation, scope))
            revoked += 1

        if not changes:
            unchanged += 1
            print("  Role '%s' is already in line with the policy package." % role)
            continue

        updated += 1
        print("  Role '%s':" % role)
        for change in changes:
            print("    %s" % change)

    # the policy package holds the whole set of roles, so anything it does not define goes,
    # including roles that were created by hand through the CLI
    to_delete = sorted(set(current) - set(roles))
    if to_delete:
        # a role is only deletable once nothing references it any more
        holding_back = {name: rule for name, rule in _role_delete_rules(session).items() if rule != "CASCADE"}
        if holding_back:
            print("  Note: %s, so the rows depending on a role have to be removed before the role itself."
                  % ", ".join("%s is ON DELETE %s" % (name, rule) for name, rule in sorted(holding_back.items())))
        else:
            print("  Note: the foreign keys to `roles` cascade on delete, so the database removes the rows depending on a role along with it.")

    for role in to_delete:
        deleted += 1
        print("  Role '%s' is not defined by the policy package, so it would be deleted." % role)
        for scope, operation in sorted(current_permissions[role]):
            revoked += 1
            print("    would also remove its %s permission on scope '%s'" % (operation, scope))
        for held_by in sorted(accounts_by_role.get(role, [])):
            unassigned += 1
            print("    would also remove its assignment to account '%s'" % held_by)

    print()
    print("Summary: would create %d role(s), update %d, delete %d, leave %d unchanged; would grant %d and revoke %d permission(s) and remove %d account assignment(s)."
          % (created, updated, deleted, unchanged, granted, revoked, unassigned))


def sync_account_roles_from_idp(account: Union[str, "InternalAccount"], roles: Any, vo: str = DEFAULT_VO, *, session: "Session") -> None:
    """
    Synchronize an account's role assignments with roles supplied by an IdP.

    A locked role is off limits to the identity provider: it is neither assigned to nor
    removed from an account here, and its expiry date is left as it is. Only Rucio itself
    can alter who holds such a role.

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
        ["ROLE", "EXPIRES AT", "KNOWN TO RUCIO", "LOCKED"],
        [
            [role, _format_expires_at(expires_at), "yes" if role in known_roles else "no", "yes" if _is_locked(role, known_roles) else "no"]
            for role, expires_at in sorted(desired.items())
        ],
    )

    # Step 1: Retrieve the roles assigned to the account (AccountRoleAssociation)
    current = {entry["role"]: entry["expires_at"] for entry in list_account_roles(account, session=session)}

    print()
    print("Step 1: Retrieve the roles assigned to the account")
    _print_table(
        ["ROLE", "EXPIRES AT", "LOCKED"],
        [[role, _format_expires_at(expires_at), "yes" if _is_locked(role, known_roles) else "no"] for role, expires_at in sorted(current.items())],
    )

    # Step 2: Cleaning:
    # A locked role is skipped at every step below, since an identity provider must not alter
    # who holds it.
    now = datetime.utcnow()
    print()
    print("Step 2: Cleaning, as of %s" % now)
    # a role is only reported the first time it is held back, so that the same lock is not
    # mentioned once per step
    held_back: set[str] = set()

    def _hold_back(role: str, message: str) -> bool:
        """Report that a locked role keeps a change from being applied, once per role."""
        if not _is_locked(role, known_roles):
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
        if _hold_back(role, "  2.1 Role '%s' expired at %s but is locked, so the assignment would be left untouched." % (role, expires_at)):
            continue
        expired[role] = expires_at
        print("  2.1 Role '%s' expired at %s, so the assignment would be removed." % (role, expires_at))

    # what is left after 2.1 is what the remaining steps compare against
    remaining = {role: expires_at for role, expires_at in current.items() if role not in expired}

    # 2.2 Remove roles from the account that are not in the list of roles from the IDP (AccountRoleAssociation)
    to_remove = []
    for role in sorted(set(remaining) - set(desired)):
        if _hold_back(role, "  2.2 Role '%s' is not supplied by the IdP but is locked, so the assignment would be kept." % role):
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
        if _hold_back(role, "  2.3 Role '%s' is locked, so the IdP cannot have it assigned to the account." % role):
            continue
        to_add.append(role)
        print("  2.3 Role '%s' would be assigned, expiring %s." % (role, _format_expires_at(desired[role])))

    # 2.4 Update the expires_at of the roles that are in both the account's current roles and the list of roles from the IDP (AccountRoleAssociation)
    to_update, unchanged = [], 0
    for role in sorted(set(desired) & set(remaining)):
        if desired[role] == remaining[role]:
            unchanged += 1
            continue
        if _hold_back(role, "  2.4 Role '%s' is locked, so its expiry date of %s would be kept instead of %s."
                            % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role]))):
            continue
        to_update.append(role)
        print("  2.4 Role '%s' would have its expiry date changed from %s to %s."
              % (role, _format_expires_at(remaining[role]), _format_expires_at(desired[role])))

    print()
    print("Summary: would remove %d assignment(s) (%d expired, %d no longer supplied), add %d, change the expiry date of %d, leave %d unchanged; %d locked role(s) held back; %d role(s) supplied by the IdP are unknown to Rucio."
          % (len(expired) + len(to_remove), len(expired), len(to_remove), len(to_add), len(to_update), unchanged, len(held_back), len(unknown)))
