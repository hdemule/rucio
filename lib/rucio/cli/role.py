from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

import click
from tabulate import tabulate

from rucio.cli.utils import DatabaseOperationType, format_operations, format_permission_tree, wrap_table_column
from rucio.common.exception import Duplicate, RoleInUse, RolePermissionNotFound, RoleProtected
from rucio.common.utils import str_to_date

# Shorthands accepted on the command line, mapped to the operation(s) they expand to.
OPERATION_SHORTHANDS: dict[str, list[DatabaseOperationType]] = {
    'r': [DatabaseOperationType.READ],
    'read': [DatabaseOperationType.READ],
    'w': [DatabaseOperationType.WRITE],
    'write': [DatabaseOperationType.WRITE],
    'rw': [DatabaseOperationType.READ, DatabaseOperationType.WRITE],
}


@contextmanager
def _protection_hint(role_name: str, action: str = "altered") -> Iterator[None]:
    """Turn a RoleProtected error into one telling the CLI user how to bypass the protection."""
    try:
        yield
    except RoleProtected as error:
        forced = "--force to delete it anyway (this also revokes it from every account it is assigned to)" if action == "deleted" else "--force to bypass the protection"
        raise RoleProtected(f"Role '{role_name}' is protected, so it cannot be {action}. Add {forced}, or unprotect it first with `rucio role update {role_name} -p false`.") from error


@click.group()
def role():
    """Manage role-based access control (RBAC). Roles are assignable to accounts (see `rucio account role` for details) and can grant permissions on scopes.
    A role can be protected which prevents it from being altered (e.g. externally by a policy package).
    A role can also be assignable or not, which controls whether it can be assigned freely to accounts; this prevents an external identity provider from assigning a role to anyone."""


@role.command("list")
@click.option("--detail", is_flag=True, help="Show the permissions assigned to each role. Use `role permission list --detail` to also expand their scope patterns.")
@click.pass_context
def list_(ctx: click.Context, detail: bool) -> None:
    """List all roles."""
    roles = ctx.obj.client.list_roles()
    rows = []
    for role_entry in roles:
        rows.append([role_entry['role'], role_entry.get('assignable'), role_entry.get('protected'), role_entry.get('description') or ''])
        if not detail:
            continue

        rows.extend([line, "", "", ""] for line in format_permission_tree(ctx.obj.client.list_role_permissions(role_entry['role'])))

    headers = ["ROLE", "ASSIGNABLE", "PROTECTED", "DESCRIPTION"]
    click.echo(tabulate(wrap_table_column(rows, headers, column=3), headers=headers, tablefmt=ctx.obj.tablefmt))


@role.command("add")
@click.pass_context
@click.argument("role_name")
@click.option("-d", "--description", help="Set the description of the role.")
@click.option("-a", "--assignable", type=bool, is_flag=False, flag_value="true", default=True, show_default=True,
              help="Allow (true) or prevent (false) assigning the role to, or removing it from, an account. Bypassable with '--force' on `account role add`/`remove`.")
@click.option("-p", "--protected", type=bool, is_flag=False, flag_value="true", default=True, show_default=True,
              help="Protect (true) or not (false) the role. A protected role cannot be altered or deleted, by a policy package or through Rucio, unless internally forced.")
def add(ctx: click.Context, role_name: str, description: Optional[str], assignable: bool, protected: bool) -> None:
    """Add a new role, optionally with a description. Give ROLE_NAME before -a/-p, which take an optional true/false."""
    ctx.obj.client.add_role(role_name, description=description, assignable=assignable, protected=protected)
    click.echo(f"Role '{role_name}' added.")


@role.command("update")
@click.pass_context
@click.argument("role_name")
@click.option("-d", "--description", help='Set the description of the role, overwriting the existing one. Pass an empty string ("") to remove it.')
@click.option("-a", "--assignable", type=bool, is_flag=False, flag_value="true", default=None,
              help="Allow (true) or prevent (false) assigning the role to, or removing it from, an account. Bypassable with '--force' on `account role add`/`remove`.")
@click.option("-p", "--protected", type=bool, is_flag=False, flag_value="true", default=None,
              help="Protect (true) or not (false) the role. A protected role cannot be altered or deleted, by a policy package or through Rucio, unless internally forced.")
@click.option("--force", is_flag=True, default=False, help="Change the description or the assignable state even if the role is protected.")
def update(ctx: click.Context, role_name: str, description: Optional[str], assignable: Optional[bool], protected: Optional[bool], force: bool) -> None:
    """Update properties of a role. Only the given options are changed."""
    if description is None and assignable is None and protected is None:
        raise click.UsageError("At least one of --description, --assignable or --protected must be given.")

    if protected is False and not _confirm_unprotect(ctx, role_name):
        click.echo("Aborted, the role was not updated.")
        return

    with _protection_hint(role_name):
        ctx.obj.client.update_role(role_name, description=description, assignable=assignable, protected=protected, force=force)
    click.echo(f"Role '{role_name}' updated.")


@role.command("delete")
@click.pass_context
@click.argument("role_name")
@click.option("--force", is_flag=True, default=False, help="Also revoke the role from every account it is assigned to and remove its permissions, and delete it even if it is protected. Asks for confirmation first.")
def delete(ctx: click.Context, role_name: str, force: bool) -> None:
    """Delete an existing role."""
    if force and not _confirm_forced_delete(ctx, role_name):
        click.echo("Aborted, the role was not deleted.")
        return
    with _protection_hint(role_name, action="deleted"):
        try:
            ctx.obj.client.delete_role(role_name, force=force)
        except RoleInUse as error:
            raise RoleInUse(f"Role '{role_name}' is still assigned to accounts and cannot be deleted. Add --force to revoke it from every account it is assigned to, drop its permissions and delete it.") from error
    click.echo(f"Role '{role_name}' deleted.")


def _confirm_unprotect(ctx: click.Context, role_name: str) -> bool:
    """
    Explain what removing the protection of a role implies, and ask for confirmation.

    Always True for a role which is not protected, since there is nothing to remove.

    :returns: True if the caller should proceed, False if the user declined.
    """
    if not any(entry['role'] == role_name and entry.get('protected') for entry in ctx.obj.client.list_roles()):
        return True

    click.echo(f"You are about to remove the protection from role '{role_name}'. This means that its description, assignable state and associated permissions can be changed, and the role deleted (e.g. by a policy package synchronization).")

    return click.confirm(f"Do you really want to remove the protection from role '{role_name}'?")


def _confirm_forced_delete(ctx: click.Context, role_name: str) -> bool:
    """
    Show the accounts a forced deletion of a role would revoke it from, and ask for confirmation.

    :returns: True if the caller should proceed, False if the user declined.
    """
    accounts = [assignment['account'] for assignment in ctx.obj.client.list_role_accounts(role_name)]

    click.echo(f"Deleting role '{role_name}' would revoke it from the following account(s):")
    for account in accounts:
        click.echo(f"  {account}")
    if not accounts:
        click.echo("  (none)")

    return click.confirm("Do you confirm role deletion?")


@role.group()
def account() -> None:
    """Show the accounts a role is assigned to."""


@account.command("list")
@click.argument("role_name")
@click.option("--active", is_flag=True, help="Hide the accounts whose assignment has already expired.")
@click.pass_context
def account_list(ctx: click.Context, role_name: str, active: bool) -> None:
    """List the accounts ROLE_NAME is assigned to, with the expiry date of each assignment."""
    assignments = ctx.obj.client.list_role_accounts(role_name)
    if active:
        # expiry dates are stored as naive UTC datetimes
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        assignments = [assignment for assignment in assignments if not assignment.get('expires_at') or str_to_date(assignment['expires_at']) > now]

    rows = [[assignment['account'], assignment.get('expires_at') or '-'] for assignment in assignments]
    click.echo(tabulate(rows, headers=["ACCOUNT", "EXPIRES AT"], tablefmt=ctx.obj.tablefmt))


@role.group()
def permission() -> None:
    """Manage permissions assigned to a role."""


def _matching_scopes(scope_pattern: str, known_scopes: list[str]) -> list[str]:
    """Return the known scopes a wildcard scope pattern matches. Only a trailing '*' is accepted, as enforced server-side."""
    prefix = scope_pattern[:-1]
    return sorted(scope for scope in known_scopes if scope.startswith(prefix))


def _confirm_scope_pattern(ctx: click.Context, scope_pattern: str, verb: str) -> bool:
    """
    Show the scopes a wildcard scope pattern currently matches and ask for confirmation.

    Always True for a scope pattern without a wildcard, since it names a single scope and
    there is nothing to expand or confirm.

    :param verb: The action to ask confirmation for, e.g. 'add' or 'remove'.
    :returns: True if the caller should proceed, False if the user declined.
    """
    if '*' not in scope_pattern:
        return True

    matches = _matching_scopes(scope_pattern, ctx.obj.client.list_scopes())
    click.echo(f"The '{scope_pattern}' pattern currently matches the following scope(s):")
    for scope in matches:
        click.echo(f"  {scope}")
    if not matches:
        click.echo("  (none)")

    return click.confirm(f"Do you still want to {verb} this permission?")


@permission.command("list")
@click.argument("role_name")
@click.option("--detail", is_flag=True, help="Expand each wildcard scope pattern into the scopes it currently matches.")
@click.pass_context
def permission_list(ctx: click.Context, role_name: str, detail: bool) -> None:
    """List permissions assigned to ROLE_NAME."""
    permissions = ctx.obj.client.list_role_permissions(role_name)

    ops_by_scope_pattern: dict[str, set[str]] = {}
    for permission in permissions:
        ops_by_scope_pattern.setdefault(permission['scope_pattern'], set()).add(permission['operation'])

    if not detail:
        rows = [[scope_pattern, format_operations(ops)] for scope_pattern, ops in sorted(ops_by_scope_pattern.items())]
        click.echo(tabulate(rows, headers=["SCOPE PATTERN", "OPERATION(S)"], tablefmt=ctx.obj.tablefmt))
        return

    # only fetch the (potentially large) list of every scope if a pattern actually needs expanding
    known_scopes = ctx.obj.client.list_scopes() if any('*' in scope_pattern for scope_pattern in ops_by_scope_pattern) else []

    rows = []
    for scope_pattern, ops in sorted(ops_by_scope_pattern.items()):
        rows.append([scope_pattern, format_operations(ops)])
        if '*' not in scope_pattern:
            continue

        matches = _matching_scopes(scope_pattern, known_scopes)
        if not matches:
            rows.append(["    (no scope currently matches)", ""])
            continue
        for index, scope in enumerate(matches):
            branch = "`-- " if index == len(matches) - 1 else "|-- "
            rows.append([f"    {branch}{scope}", ""])

    click.echo(tabulate(rows, headers=["SCOPE PATTERN", "OPERATION(S)"], tablefmt=ctx.obj.tablefmt))


@permission.command("add")
@click.argument("role_name")
@click.argument("operation", type=click.Choice(list(OPERATION_SHORTHANDS), case_sensitive=False))
@click.argument("scope_pattern")
@click.option("--force", is_flag=True, default=False, help="Add the permission even if the role is protected.")
@click.pass_context
def permission_add(ctx: click.Context, role_name: str, operation: str, scope_pattern: str, force: bool) -> None:
    """Add OPERATION on SCOPE_PATTERN to ROLE_NAME. OPERATION is 'r'/'read', 'w'/'write' or both ('rw'). SCOPE_PATTERN only accepts a trailing '*' wildcard, e.g. 'data*' or '*' for every scope; quote it so the shell does not expand it as a glob."""
    if not _confirm_scope_pattern(ctx, scope_pattern, "add"):
        click.echo("Aborted, no permission was added.")
        return
    added, already_assigned = [], []
    for op in OPERATION_SHORTHANDS[operation.lower()]:
        try:
            with _protection_hint(role_name):
                ctx.obj.client.add_role_permission(role_name, op.value, scope_pattern, force=force)
            added.append(op.value)
        except Duplicate:
            already_assigned.append(op.value)

    if already_assigned:
        click.echo(f"Warning: {'/'.join(already_assigned)} permission(s) on {scope_pattern} already assigned to role '{role_name}'.")
    if added:
        click.echo(f"Added {'/'.join(added)} permission(s) on {scope_pattern} to role '{role_name}'.")


@permission.command("remove")
@click.argument("role_name")
@click.argument("operation", type=click.Choice(list(OPERATION_SHORTHANDS), case_sensitive=False))
@click.argument("scope_pattern")
@click.option("--force", is_flag=True, default=False, help="Remove the permission even if the role is protected.")
@click.pass_context
def permission_remove(ctx: click.Context, role_name: str, operation: str, scope_pattern: str, force: bool) -> None:
    """Remove OPERATION on SCOPE_PATTERN from ROLE_NAME. OPERATION is 'r'/'read', 'w'/'write' or both ('rw')."""
    requested = OPERATION_SHORTHANDS[operation.lower()]
    assigned = {
        permission['operation']
        for permission in ctx.obj.client.list_role_permissions(role_name)
        if permission['scope_pattern'] == scope_pattern
    }
    if not any(op.value in assigned for op in requested):
        raise RolePermissionNotFound(
            f"None of the requested permissions ({'/'.join(op.value for op in requested)}) are assigned to role '{role_name}' on scope pattern '{scope_pattern}'.")

    if not _confirm_scope_pattern(ctx, scope_pattern, "remove"):
        click.echo("Aborted, no permission was removed.")
        return

    removed, not_assigned = [], []
    for op in requested:
        try:
            with _protection_hint(role_name):
                ctx.obj.client.delete_role_permission(role_name, op.value, scope_pattern, force=force)
            removed.append(op.value)
        except RolePermissionNotFound:
            not_assigned.append(op.value)
    if not_assigned:
        click.echo(f"Warning: {'/'.join(not_assigned)} permission(s) on {scope_pattern} were already not assigned to role '{role_name}'.")
    click.echo(f"Removed {'/'.join(removed)} permission(s) on {scope_pattern} from role '{role_name}'.")
