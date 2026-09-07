import click
from tabulate import tabulate

from rucio.db.sqla.constants import DatabaseOperationType


@click.group()
def role():
    """Manage role-based access control (RBAC)."""


@role.command("list")
@click.pass_context
def list_(ctx: click.Context) -> None:
    """List all roles."""
    roles = ctx.obj.client.list_roles()
    click.echo(tabulate([[role_name] for role_name in roles], headers=["ROLE"], tablefmt=ctx.obj.tablefmt))


@role.command("add")
@click.pass_context
@click.argument("role_name")
def add(ctx: click.Context, role_name: str) -> None:
    """Add a new role."""
    ctx.obj.client.add_role(role_name)
    click.echo(f"Role '{role_name}' added.")


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
    click.echo(tabulate([[permission['scope'], permission['operation']] for permission in permissions], headers=["SCOPE", "OPERATION"], tablefmt=ctx.obj.tablefmt))


@permission.command("add")
@click.argument("role_name")
@click.argument("operation", type=click.Choice([operation.value for operation in DatabaseOperationType]))
@click.argument("scope")
@click.pass_context
def permission_add(ctx: click.Context, role_name: str, operation: str, scope: str) -> None:
    """Add OPERATION on SCOPE to ROLE_NAME."""
    ctx.obj.client.add_role_permission(role_name, operation, scope)
    click.echo(f"Added {operation} permission on {scope} to role '{role_name}'.")


@permission.command("remove")
@click.argument("role_name")
@click.argument("operation", type=click.Choice([operation.value for operation in DatabaseOperationType]))
@click.argument("scope")
@click.pass_context
def permission_remove(ctx: click.Context, role_name: str, operation: str, scope: str) -> None:
    """Remove OPERATION on SCOPE from ROLE_NAME."""
    ctx.obj.client.delete_role_permission(role_name, operation, scope)
    click.echo(f"Removed {operation} permission on {scope} from role '{role_name}'.")
