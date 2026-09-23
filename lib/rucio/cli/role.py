from datetime import datetime, timezone
from typing import Optional

import click
from tabulate import tabulate

from rucio.cli.utils import DatabaseOperationType, format_operations, wrap_table_column
from rucio.common.exception import Duplicate, RolePermissionNotFound
from rucio.common.utils import str_to_date

# Shorthands accepted on the command line, mapped to the operation(s) they expand to.
OPERATION_SHORTHANDS: dict[str, list[DatabaseOperationType]] = {
    'r': [DatabaseOperationType.READ],
    'read': [DatabaseOperationType.READ],
    'w': [DatabaseOperationType.WRITE],
    'write': [DatabaseOperationType.WRITE],
    'rw': [DatabaseOperationType.READ, DatabaseOperationType.WRITE],
}


@click.group()
def role():
    """Manage role-based access control (RBAC)."""


@role.command("list")
@click.pass_context
def list_(ctx: click.Context) -> None:
    """List all roles with their assignment_disabled/internal_role_flag state and description."""
    roles = ctx.obj.client.list_roles()
    rows = [
        [role_entry['role'], role_entry.get('assignment_disabled'), role_entry.get('internal_role_flag'), role_entry.get('description') or '']
        for role_entry in roles
    ]
    headers = ["ROLE", "ASSIGNMENT DISABLED", "INTERNAL ROLE FLAG", "DESCRIPTION"]
    click.echo(tabulate(wrap_table_column(rows, headers, column=3), headers=headers, tablefmt=ctx.obj.tablefmt))


@role.command("add")
@click.pass_context
@click.argument("role_name")
@click.option("--description", help="Description of the role")
@click.option("--assignment-disabled", type=bool, is_flag=False, default=False, help="Prevents this role from being assigned to, or taken away from, an account. Only bypassable with '--force' on `account role add`/`remove`.")
@click.option("--internal-role-flag", type=bool, is_flag=False, default=False, help="Prevents a policy package from altering the role such as deleting it.")
def add(ctx: click.Context, role_name: str, description: Optional[str], assignment_disabled: bool, internal_role_flag: bool) -> None:
    """Add a new role, optionally with a description."""
    ctx.obj.client.add_role(role_name, description=description, assignment_disabled=assignment_disabled, internal_role_flag=internal_role_flag)
    click.echo(f"Role '{role_name}' added.")


@role.command("update")
@click.pass_context
@click.argument("role_name")
@click.option("--description", help='New description of the role, overwriting the existing one. Pass an empty string ("") to remove the description.')
@click.option("--assignment-disabled", type=bool, is_flag=False, default=None, help="Prevents (true) or allow (false) this role from being assigned to, or taken away from, an account. Only bypassable with '--force' on `account role add`/`remove`.")
@click.option("--internal-role-flag", type=bool, is_flag=False, default=None, help="Flags (true) or unflags (false) the role as internal.")
def update(ctx: click.Context, role_name: str, description: Optional[str], assignment_disabled: Optional[bool], internal_role_flag: Optional[bool]) -> None:
    """Update metadata of a role. Only the given options are changed; an empty description removes it."""
    if description is None and assignment_disabled is None and internal_role_flag is None:
        raise click.UsageError("At least one of --description, --assignment-disabled or --internal-role-flag must be given.")

    ctx.obj.client.update_role(role_name, description=description, assignment_disabled=assignment_disabled, internal_role_flag=internal_role_flag)
    click.echo(f"Role '{role_name}' updated.")


@role.command("delete")
@click.pass_context
@click.argument("role_name")
def delete(ctx: click.Context, role_name: str) -> None:
    """Delete an existing role."""
    ctx.obj.client.delete_role(role_name)
    click.echo(f"Role '{role_name}' deleted.")



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
@click.pass_context
def permission_add(ctx: click.Context, role_name: str, operation: str, scope_pattern: str) -> None:
    """Add OPERATION on SCOPE_PATTERN to ROLE_NAME. OPERATION is 'r'/'read', 'w'/'write' or both ('rw'). SCOPE_PATTERN only accepts a trailing '*' wildcard, e.g. 'data*' or '*' for every scope; quote it so the shell does not expand it as a glob."""
    if not _confirm_scope_pattern(ctx, scope_pattern, "add"):
        click.echo("Aborted, no permission was added.")
        return
    added, already_assigned = [], []
    for op in OPERATION_SHORTHANDS[operation.lower()]:
        try:
            ctx.obj.client.add_role_permission(role_name, op.value, scope_pattern)
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
@click.pass_context
def permission_remove(ctx: click.Context, role_name: str, operation: str, scope_pattern: str) -> None:
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
            ctx.obj.client.delete_role_permission(role_name, op.value, scope_pattern)
            removed.append(op.value)
        except RolePermissionNotFound:
            not_assigned.append(op.value)
    if not_assigned:
        click.echo(f"Warning: {'/'.join(not_assigned)} permission(s) on {scope_pattern} were already not assigned to role '{role_name}'.")
    click.echo(f"Removed {'/'.join(removed)} permission(s) on {scope_pattern} from role '{role_name}'.")
