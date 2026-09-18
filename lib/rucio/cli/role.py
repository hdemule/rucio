from typing import Optional

import click
from tabulate import tabulate

from rucio.cli.utils import DatabaseOperationType, format_operations, wrap_table_column
from rucio.common.exception import Duplicate, RolePermissionNotFound

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
    """List all roles with their description."""
    roles = ctx.obj.client.list_roles()
    rows = [[role_entry['role'], role_entry.get('description') or ''] for role_entry in roles]
    headers = ["ROLE", "DESCRIPTION"]
    click.echo(tabulate(wrap_table_column(rows, headers, column=1), headers=headers, tablefmt=ctx.obj.tablefmt))


@role.command("add")
@click.pass_context
@click.argument("role_name")
@click.option("--description", help="Description of the role")
def add(ctx: click.Context, role_name: str, description: Optional[str]) -> None:
    """Add a new role, optionally with a description."""
    ctx.obj.client.add_role(role_name, description=description)
    click.echo(f"Role '{role_name}' added.")


@role.command("update")
@click.pass_context
@click.argument("role_name")
@click.option("--description", required=True, help='New description of the role, overwriting the existing one. Pass an empty string ("") to remove the description.')
def update(ctx: click.Context, role_name: str, description: str) -> None:
    """Update metadata of a role. The given description overwrites the existing one; an empty description removes it."""
    ctx.obj.client.set_role_description(role_name, description)
    if description.strip():
        click.echo(f"Description of role '{role_name}' updated.")
    else:
        click.echo(f"Description of role '{role_name}' removed.")


@role.command("delete")
@click.pass_context
@click.argument("role_name")
def delete(ctx: click.Context, role_name: str) -> None:
    """Delete an existing role."""
    ctx.obj.client.delete_role(role_name)
    click.echo(f"Role '{role_name}' deleted.")


@role.group()
def permission() -> None:
    """Manage permissions assigned to a role."""


@permission.command("list")
@click.argument("role_name")
@click.pass_context
def permission_list(ctx: click.Context, role_name: str) -> None:
    """List permissions assigned to ROLE_NAME."""
    permissions = ctx.obj.client.list_role_permissions(role_name)

    ops_by_scope: dict[str, set[str]] = {}
    for permission in permissions:
        ops_by_scope.setdefault(permission['scope'], set()).add(permission['operation'])

    rows = [[scope, format_operations(ops)] for scope, ops in sorted(ops_by_scope.items())]
    click.echo(tabulate(rows, headers=["SCOPE", "OPERATION(S)"], tablefmt=ctx.obj.tablefmt))


@permission.command("add")
@click.argument("role_name")
@click.argument("operation", type=click.Choice(list(OPERATION_SHORTHANDS), case_sensitive=False))
@click.argument("scope")
@click.pass_context
def permission_add(ctx: click.Context, role_name: str, operation: str, scope: str) -> None:
    """Add OPERATION on SCOPE to ROLE_NAME. OPERATION is read ('r'/'read'), write ('w'/'write') or both ('rw')."""
    added, already_assigned = [], []
    for op in OPERATION_SHORTHANDS[operation.lower()]:
        try:
            ctx.obj.client.add_role_permission(role_name, op.value, scope)
            added.append(op.value)
        except Duplicate:
            already_assigned.append(op.value)

    if already_assigned:
        click.echo(f"Warning: {'/'.join(already_assigned)} permission(s) on {scope} already assigned to role '{role_name}'.")
    if added:
        click.echo(f"Added {'/'.join(added)} permission(s) on {scope} to role '{role_name}'.")


@permission.command("remove")
@click.argument("role_name")
@click.argument("operation", type=click.Choice(list(OPERATION_SHORTHANDS), case_sensitive=False))
@click.argument("scope")
@click.pass_context
def permission_remove(ctx: click.Context, role_name: str, operation: str, scope: str) -> None:
    """Remove OPERATION on SCOPE from ROLE_NAME. OPERATION is read ('r'/'read'), write ('w'/'write') or both ('rw')."""
    removed, not_assigned = [], []
    for op in OPERATION_SHORTHANDS[operation.lower()]:
        try:
            ctx.obj.client.delete_role_permission(role_name, op.value, scope)
            removed.append(op.value)
        except RolePermissionNotFound:
            not_assigned.append(op.value)

    if not removed:
        raise RolePermissionNotFound(f"None of the requested permissions ({'/'.join(not_assigned)}) were assigned to role '{role_name}' on scope '{scope}'.")
    if not_assigned:
        click.echo(f"Warning: {'/'.join(not_assigned)} permission(s) on {scope} were already not assigned to role '{role_name}'.")
    click.echo(f"Removed {'/'.join(removed)} permission(s) on {scope} from role '{role_name}'.")
