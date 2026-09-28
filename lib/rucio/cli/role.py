from contextlib import contextmanager
from datetime import datetime
from typing import TYPE_CHECKING, Optional

import click
from tabulate import tabulate

from rucio.cli.utils import OptionalDateTime, RoleOperationType, format_operations, format_permission_tree, wrap_table_column
from rucio.common.exception import Duplicate, RoleAssignmentDisabled, RoleInUse, RoleLocked, RolePermissionNotFound

if TYPE_CHECKING:
    from collections.abc import Generator


# Shorthands accepted on the command line, mapped to the operation(s) they expand to.
OPERATION_SHORTHANDS: dict[str, list[RoleOperationType]] = {
    'r': [RoleOperationType.READ],
    'read': [RoleOperationType.READ],
    'w': [RoleOperationType.WRITE],
    'write': [RoleOperationType.WRITE],
    'd': [RoleOperationType.DELETE],
    'delete': [RoleOperationType.DELETE],
    'rw': [RoleOperationType.READ, RoleOperationType.WRITE],
    'rwd': [RoleOperationType.READ, RoleOperationType.WRITE, RoleOperationType.DELETE],
}

OPTIONAL_DATE = OptionalDateTime()
DATE_EXAMPLE = "2012-02-29 or 2012-02-29T16:33:30"


@contextmanager
def _assignable_hint(role_name: str, account_name: str, action: str) -> 'Generator[None, None, None]':
    """Turn a RoleAssignmentDisabled error into one telling the CLI user how to bypass it."""
    try:
        yield
    except RoleAssignmentDisabled as error:
        raise RoleAssignmentDisabled(f"Role '{role_name}' is not assignable, so it cannot be {action} account '{account_name}'. Add --force to bypass this.") from error


@contextmanager
def _lock_hint(role_name: str, action: str = "altered") -> 'Generator[None, None, None]':
    """Turn a RoleLocked error into one telling the CLI user how to bypass the lock."""
    try:
        yield
    except RoleLocked as error:
        forced = "--force to delete it anyway (this also revokes it from every account it is assigned to)" if action == "deleted" else "--force to bypass the lock"
        raise RoleLocked(f"Role '{role_name}' is locked, so it cannot be {action}. Add {forced}, or unlock it first with `rucio role update {role_name} -l false`.") from error


@click.group()
def role():
    """Manage role-based access control."""


@role.command("list")
@click.option("--detail", is_flag=True, help="Show the permissions associated with each role. Use `role permission list --detail` to also expand their scope patterns.")
@click.pass_context
def list_(ctx: click.Context, detail: bool) -> None:
    """List all roles."""
    roles = ctx.obj.client.list_roles()
    rows = []
    for role_entry in roles:
        rows.append([role_entry['role'], role_entry.get('assignable'), role_entry.get('locked'), role_entry.get('description') or ''])
        if not detail:
            continue

        rows.extend([line, "", "", ""] for line in format_permission_tree(ctx.obj.client.list_role_permissions(role_entry['role'])))

    headers = ["ROLE", "ASSIGNABLE", "LOCKED", "DESCRIPTION"]
    click.echo(tabulate(wrap_table_column(rows, headers, column=3), headers=headers, tablefmt=ctx.obj.tablefmt))


@role.command("add")
@click.pass_context
@click.argument("role_name")
@click.option("-d", "--description", help="Set the description of the role.")
@click.option("-a", "--assignable", type=bool, is_flag=False, flag_value="true", default=True, show_default=True,
              help="Allow (true) or prevent (false) assigning the role to, or removing it from, an account. Bypassable with '--force' on `role account add`/`remove`.")
@click.option("-l", "--locked", type=bool, is_flag=False, flag_value="true", default=True, show_default=True,
              help="Lock (true) or not (false) the role. A locked role cannot be altered or deleted, by a policy package or through Rucio, unless internally forced.")
def add(ctx: click.Context, role_name: str, description: Optional[str], assignable: bool, locked: bool) -> None:
    """Create a new role."""
    ctx.obj.client.add_role(role_name, description=description, assignable=assignable, locked=locked)
    click.echo(f"Role '{role_name}' added.")


@role.command("update")
@click.pass_context
@click.argument("role_name")
@click.option("-d", "--description", help='Set the description of the role, overwriting the existing one. Pass an empty string ("") to remove it.')
@click.option("-a", "--assignable", type=bool, is_flag=False, flag_value="true", default=None,
              help="Allow (true) or prevent (false) assigning the role to, or removing it from, an account. Bypassable with '--force' on `role account add`/`remove`.")
@click.option("-l", "--locked", type=bool, is_flag=False, flag_value="true", default=None,
              help="Lock (true) or not (false) the role. A locked role cannot be altered or deleted, by a policy package or through Rucio, unless internally forced.")
@click.option("--force", is_flag=True, default=False, help="Change the description or the assignable state even if the role is locked.")
def update(ctx: click.Context, role_name: str, description: Optional[str], assignable: Optional[bool], locked: Optional[bool], force: bool) -> None:
    """Update properties of a role. Only the given options are changed."""
    if description is None and assignable is None and locked is None:
        raise click.UsageError("At least one of --description, --assignable or --locked must be given.")

    if locked is False and not _confirm_unlock(ctx, role_name):
        click.echo("Aborted, the role was not updated.")
        return

    with _lock_hint(role_name):
        ctx.obj.client.update_role(role_name, description=description, assignable=assignable, locked=locked, force=force)
    click.echo(f"Role '{role_name}' updated.")


@role.command("remove")
@click.pass_context
@click.argument("role_name")
@click.option("--force", is_flag=True, default=False, help="Delete the role even if it is locked. This automatically revokes the role from every account it is assigned to and removes its permissions.")
def delete(ctx: click.Context, role_name: str, force: bool) -> None:
    """Remove a role."""
    if force and not _confirm_forced_delete(ctx, role_name):
        click.echo("Aborted, the role was not deleted.")
        return
    with _lock_hint(role_name, action="deleted"):
        try:
            ctx.obj.client.delete_role(role_name, force=force)
        except RoleInUse as error:
            raise RoleInUse(f"Role '{role_name}' is still assigned to accounts and cannot be deleted. Add --force to revoke it from every account it is assigned to, drop its permissions and delete it.") from error
    click.echo(f"Role '{role_name}' deleted.")


def _confirm_unlock(ctx: click.Context, role_name: str) -> bool:
    """
    Explain what unlocking a role implies, and ask for confirmation.

    Always True for a role which is not locked, since there is nothing to unlock.

    :returns: True if the caller should proceed, False if the user declined.
    """
    if not any(entry['role'] == role_name and entry.get('locked') for entry in ctx.obj.client.list_roles()):
        return True

    click.echo(f"You are about to unlock role '{role_name}'. This means that its description, assignable state and associated permissions can be changed, and the role deleted (e.g. by a policy package synchronization).")

    return click.confirm(f"Do you really want to unlock role '{role_name}'?")


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
    """Manage account role assignments."""


@account.command("list")
@click.option("-a", "--account", "account_name", metavar="ACCOUNT", help="List the roles assigned to ACCOUNT.")
@click.option("-r", "--role", "role_name", metavar="ROLE", help="List the accounts ROLE is assigned to.")
@click.option("--me", is_flag=True, help="List the roles assigned to your own account.")
@click.option("--detail", is_flag=True, help="Also list the permissions granted by each role. To be used with -a/--account or --me.")
@click.pass_context
def account_list(ctx: click.Context, account_name: Optional[str], role_name: Optional[str], me: bool, detail: bool) -> None:
    """
    List role assignments.

    Exactly one of -a/--account, -r/--role or --me must be given.
    """
    if sum([account_name is not None, role_name is not None, me]) != 1:
        raise click.UsageError("Exactly one of -a/--account, -r/--role or --me must be given.")
    if detail and role_name is not None:
        raise click.UsageError("--detail can only be used with -a/--account or --me.")

    if role_name is not None:
        assignments = ctx.obj.client.list_role_accounts(role_name)
        click.echo(f"Accounts assigned to role {role_name}:")
        rows = [[assignment['account'], assignment.get('expires_at') or '-'] for assignment in assignments]
        click.echo(tabulate(rows, headers=["ACCOUNT", "EXPIRES AT"], tablefmt=ctx.obj.tablefmt))
    else:
        rbac = ctx.obj.client.list_account_roles(account_name, use_issuer_account=me, detail=detail)
        click.echo(f"Roles for account {rbac['account']}:")
        if not detail:
            rows = [[entry['role'], entry.get('expires_at') or '-'] for entry in rbac['roles']]
            headers = ["ROLE", "EXPIRES AT"]
            click.echo(tabulate(wrap_table_column(rows, headers, column=1), headers=headers, tablefmt=ctx.obj.tablefmt))
        else:
            permissions_by_role: dict[str, list[dict[str, str]]] = {}
            for permission in rbac['permissions']:
                permissions_by_role.setdefault(permission['role'], []).append(permission)

            rows = []
            for entry in rbac['roles']:
                rows.append([entry['role'], entry.get('expires_at') or '-', entry.get('description') or '-'])
                rows.extend([line, "", ""] for line in format_permission_tree(permissions_by_role.get(entry['role'], [])))
            headers = ["ROLE", "EXPIRES AT", "DESCRIPTION"]
            click.echo(tabulate(wrap_table_column(rows, headers, column=2), headers=headers, tablefmt=ctx.obj.tablefmt))


@account.command("add")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--expires-at", type=OPTIONAL_DATE, help=f"Date at which the assignment expires, e.g. {DATE_EXAMPLE}. If not given, the assignment does not expire.")
@click.option("--force", is_flag=True, default=False, help="Assign the role even if it is not assignable.")
@click.pass_context
def account_add(ctx: click.Context, role_name: str, account_name: str, expires_at: Optional[datetime], force: bool) -> None:
    """Assign ROLE_NAME to ACCOUNT_NAME, optionally until an expiry date."""
    with _assignable_hint(role_name, account_name, action="assigned to"):
        ctx.obj.client.add_account_role(account_name, role_name, expires_at=expires_at, force=force)
    if expires_at:
        click.echo(f"Added role '{role_name}' to account '{account_name}', expiring at {expires_at}.")
    else:
        click.echo(f"Added role '{role_name}' to account '{account_name}'.")


@account.command("update")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--expires-at", type=OPTIONAL_DATE, required=True, help=f'New date at which the assignment expires, e.g. {DATE_EXAMPLE}, overwriting the existing one. Pass an empty string ("") so that the assignment does not expire.')
@click.pass_context
def account_update(ctx: click.Context, role_name: str, account_name: str, expires_at: Optional[datetime]) -> None:
    """Update the expiry date of ROLE_NAME for ACCOUNT_NAME. The given date overwrites the existing one; an empty date removes it."""
    ctx.obj.client.set_account_role_expires_at(account_name, role_name, expires_at)
    if expires_at:
        click.echo(f"Role '{role_name}' for account '{account_name}' now expires at {expires_at}.")
    else:
        click.echo(f"Role '{role_name}' for account '{account_name}' does not expire any more.")


@account.command("remove")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--force", is_flag=True, default=False, help="Remove the role even if it is not assignable.")
@click.pass_context
def account_remove(ctx: click.Context, role_name: str, account_name: str, force: bool) -> None:
    """Remove ROLE_NAME from ACCOUNT_NAME."""
    with _assignable_hint(role_name, account_name, action="removed from"):
        ctx.obj.client.delete_account_role(account_name, role_name, force=force)
    click.echo(f"Removed role '{role_name}' from account '{account_name}'.")


@role.group()
def permission() -> None:
    """Manage permissions of a role."""


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
@click.option("--force", is_flag=True, default=False, help="Add the permission even if the role is locked.")
@click.pass_context
def permission_add(ctx: click.Context, role_name: str, operation: str, scope_pattern: str, force: bool) -> None:
    """Add OPERATION on SCOPE_PATTERN to ROLE_NAME. OPERATION is 'r'/'read', 'w'/'write', 'd'/'delete', or a combination ('rw', 'rwd').
    SCOPE_PATTERN only accepts a trailing '*' wildcard, e.g. 'data*' or '*' for every scope; quote it so the shell does not expand it as a glob."""
    if not _confirm_scope_pattern(ctx, scope_pattern, "add"):
        click.echo("Aborted, no permission was added.")
        return
    added, already_assigned = [], []
    for op in OPERATION_SHORTHANDS[operation.lower()]:
        try:
            with _lock_hint(role_name):
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
@click.option("--force", is_flag=True, default=False, help="Remove the permission even if the role is locked.")
@click.pass_context
def permission_remove(ctx: click.Context, role_name: str, operation: str, scope_pattern: str, force: bool) -> None:
    """Remove OPERATION on SCOPE_PATTERN from ROLE_NAME. OPERATION is 'r'/'read', 'w'/'write', 'd'/'delete', or a combination ('rw', 'rwd')."""
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
            with _lock_hint(role_name):
                ctx.obj.client.delete_role_permission(role_name, op.value, scope_pattern, force=force)
            removed.append(op.value)
        except RolePermissionNotFound:
            not_assigned.append(op.value)
    if not_assigned:
        click.echo(f"Warning: {'/'.join(not_assigned)} permission(s) on {scope_pattern} were already not assigned to role '{role_name}'.")
    click.echo(f"Removed {'/'.join(removed)} permission(s) on {scope_pattern} from role '{role_name}'.")
