import textwrap
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

import click
from tabulate import tabulate

from rucio.cli.utils import (
    OptionalDateTime,
    QuotaSize,
    RoleOperations,
    ScopeOperationType,
    SizeFormat,
    format_permission_trees,
    format_quota,
    format_sections,
    format_tree,
    permission_lines,
    wrap_table_column,
)
from rucio.common.exception import AccessDenied, AccountNotFound, Duplicate, InvalidRSEExpression, RoleAssignmentDisabled, RoleInUse, RoleLocked, RolePermissionNotFound, RSENotFound
from rucio.common.utils import str_to_date

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Generator, Iterable, Mapping, Sequence


OPERATIONS = RoleOperations()
QUOTA_SIZE = QuotaSize()

OPTIONAL_DATE = OptionalDateTime()
DATE = click.DateTime(formats=OptionalDateTime.FORMATS)
DATE_EXAMPLE = "2012-02-29 or 2012-02-29T16:33:30"

# appended to the name of a reserved role when listing roles, and explained below it with `--detail`
RESERVED_ROLE_TAG = "(built-in)"
RESERVED_ROLE_DETAIL = textwrap.fill(
    "`-- (managed by Rucio)",
    width=40, initial_indent="", subsequent_indent="  ",
)


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


def _holds(assignment: "Mapping[str, Any]") -> bool:
    """
    Tell whether a role assignment, as listed by the server, grants its role right now: activated already and not expired yet.

    Only then is the account bound by the limits of the role, see `rucio role permission limit --help`.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    activates_at, expires_at = str_to_date(assignment.get('activates_at') or ''), str_to_date(assignment.get('expires_at') or '')
    return (activates_at is None or activates_at <= now) and (expires_at is None or now < expires_at)


def _role_label(role_name: str, reserved: bool) -> str:
    """The name of a role, tagged with `RESERVED_ROLE_TAG` if it is reserved."""
    return f"{role_name} {RESERVED_ROLE_TAG}" if reserved else role_name


def _role_details(
        ctx: click.Context,
        roles: "Sequence[tuple[str, bool, Iterable[Mapping[str, Any]]]]",
        account_name: Optional[str] = None,
        held: "Collection[str]" = (),
) -> list[str]:
    """
    The label of each role followed by its permission tree, the trees being aligned with each other, see :func:`format_permission_trees`.

    A reserved role has no permissions, so its tag is explained instead of an empty permission tree.

    :param roles: The roles, as their name, whether they are reserved, and their permissions as listed by the server.
    :param account_name: The account to measure the limits against, see :func:`_usage_resolver`. None to only list the limits.
    :param held: The roles `account_name` holds, see :func:`_holds`: only their limits are measured, the others being
                 limits the account is not bound by.
    :returns: The details, in the order of `roles`, each to be used as a single table cell.
    """
    rse_names = _rse_names_resolver(ctx)
    used = _usage_resolver(ctx, account_name, rse_names) if account_name is not None and held else None
    trees = iter(format_permission_trees(
        [(_role_label(role_name, reserved), permissions, used if role_name in held else None) for role_name, reserved, permissions in roles if not reserved],
        rse_names, SizeFormat.of(ctx.obj.human),
    ))
    return [f"{_role_label(role_name, reserved)}\n{RESERVED_ROLE_DETAIL}" if reserved else next(trees) for role_name, reserved, _ in roles]


class _RBACStatusHelp:
    """Ask the server whether RBAC is enabled before showing the help of a role command, so that the client warns if it is not."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        try:
            ctx.obj.client.get_rbac_status()
        except Exception:  # noqa: S110 -- the help must be shown even if the server cannot tell
            pass
        super().format_help(ctx, formatter)  # type: ignore[misc]


class RoleCommand(_RBACStatusHelp, click.Command):
    pass


class RoleGroup(_RBACStatusHelp, click.Group):
    command_class = RoleCommand
    # the subgroups are role groups as well
    group_class = type


@click.group(cls=RoleGroup)
def role():
    """Manage role-based access control."""


@role.command("list")
@click.option("--detail", is_flag=True, help="Show the permissions associated with each role. Use `role permission list --detail` to also expand their scope patterns and RSE expressions.")
@click.pass_context
def list_(ctx: click.Context, detail: bool) -> None:
    """List all roles. A role managed by Rucio itself is tagged with (built-in)."""
    roles = ctx.obj.client.list_roles()
    headers = ["ROLE", "ASSIGNABLE", "LOCKED", "DESCRIPTION"]
    if not detail:
        rows = [[_role_label(entry['role'], bool(entry.get('reserved'))), entry.get('assignable'), entry.get('locked'), entry.get('description') or ''] for entry in roles]
        click.echo(tabulate(wrap_table_column(rows, headers, column=3), headers=headers, tablefmt=ctx.obj.tablefmt))
        return

    role_cells = _role_details(ctx, [
        (entry['role'], bool(entry.get('reserved')), [] if entry.get('reserved') else ctx.obj.client.list_role_permissions(entry['role']))
        for entry in roles
    ])
    rows = [[role_cell, str(entry.get('assignable')), str(entry.get('locked')), entry.get('description') or '-'] for role_cell, entry in zip(role_cells, roles)]
    # each role spans several lines, so that the rows are separated, see `format_sections`
    click.echo(format_sections([(headers, wrap_table_column(rows, headers, column=3))]))


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
@click.option("-d", "--description", help='Set the description of the role, overwriting the existing one. Pass an empty string ("") to remove it (--description="").')
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
@click.option("--detail", is_flag=True, help="Also list the permissions granted by each role, each limit of a role the account holds with its usage measured against it. To be used with -a/--account or --me.")
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
        reserved = any(entry['role'] == role_name and entry.get('reserved') for entry in ctx.obj.client.list_roles())
        click.echo(f"Accounts assigned to role {_role_label(role_name, reserved)}:")
        rows = [[assignment['account'], assignment.get('activates_at') or '-', assignment.get('expires_at') or '-'] for assignment in assignments]
        click.echo(tabulate(rows, headers=["ACCOUNT", "ACTIVATES AT", "EXPIRES AT"], tablefmt=ctx.obj.tablefmt))
    else:
        rbac = ctx.obj.client.list_account_roles(account_name, use_issuer_account=me, detail=detail)
        click.echo(f"Roles for account '{rbac['account']}':")
        if not detail:
            rows = [
                [_role_label(entry['role'], bool(entry.get('reserved'))), entry.get('activates_at') or '-', entry.get('expires_at') or '-']
                for entry in rbac['roles']
            ]
            headers = ["ROLE", "ACTIVATES AT", "EXPIRES AT"]
            click.echo(tabulate(wrap_table_column(rows, headers, column=2), headers=headers, tablefmt=ctx.obj.tablefmt))
        else:
            permissions_by_role: dict[str, list[dict[str, Any]]] = {}
            for permission in rbac['permissions']:
                permissions_by_role.setdefault(permission['role'], []).append(permission)

            role_cells = _role_details(
                ctx, [(entry['role'], bool(entry.get('reserved')), permissions_by_role.get(entry['role'], [])) for entry in rbac['roles']],
                account_name=rbac['account'], held={entry['role'] for entry in rbac['roles'] if _holds(entry)},
            )
            rows = [
                [role_cell, str(entry.get('activates_at') or '-'), str(entry.get('expires_at') or '-'), entry.get('description') or '-']
                for role_cell, entry in zip(role_cells, rbac['roles'])
            ]
            headers = ["ROLE", "ACTIVATES AT", "EXPIRES AT", "DESCRIPTION"]
            if rows:
                # each role spans several lines, so that the rows are separated, see `format_sections`
                click.echo(format_sections([(headers, wrap_table_column(rows, headers, column=3))]))
            else:
                click.echo(tabulate(rows, headers=headers, tablefmt=ctx.obj.tablefmt))


@account.command("add")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--activates-at", type=DATE, help=f"Date from which the assignment grants the role, e.g. {DATE_EXAMPLE}. If not given, the assignment is active right away.")
@click.option("--expires-at", type=OPTIONAL_DATE, help=f"Date at which the assignment expires, e.g. {DATE_EXAMPLE}. If not given, or {OptionalDateTime.NEVER}, the assignment does not expire.")
@click.option("--force", is_flag=True, default=False, help="Assign the role even if it is not assignable.")
@click.pass_context
def account_add(ctx: click.Context, role_name: str, account_name: str, activates_at: Optional["datetime"], expires_at: Optional["datetime"], force: bool) -> None:
    """Assign ROLE_NAME to ACCOUNT_NAME, optionally from an activation date and/or until an expiry date."""
    with _assignable_hint(role_name, account_name, action="assigned to"):
        ctx.obj.client.add_account_role(account_name, role_name, expires_at=expires_at, force=force, activates_at=activates_at)
    period = (f", active from {activates_at}" if activates_at else "") + (f", expiring at {expires_at}" if expires_at else "")
    click.echo(f"Added role '{role_name}' to account '{account_name}'{period}.")


@account.command("update")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--activates-at", type=DATE, help=f"New date from which the assignment grants the role, e.g. {DATE_EXAMPLE}, overwriting the existing one.")
@click.option("--expires-at", type=OPTIONAL_DATE, help=f"New date at which the assignment expires, e.g. {DATE_EXAMPLE}, overwriting the existing one. Pass {OptionalDateTime.NEVER} so that the assignment does not expire.")
@click.pass_context
def account_update(ctx: click.Context, role_name: str, account_name: str, activates_at: Optional["datetime"], expires_at: Optional["datetime"]) -> None:
    """
    Update the activation and/or expiry date of ROLE_NAME for ACCOUNT_NAME.

    The given dates overwrite the existing ones; an --expires-at of NEVER removes the expiry date.
    Both dates given together are applied at once, so that the whole period of the assignment can be moved.
    """
    # not `required=True` for --expires-at: click would then reject NEVER, which converts to None like a missing option
    expires_given = ctx.get_parameter_source("expires_at") is not click.core.ParameterSource.DEFAULT
    if activates_at is None and not expires_given:
        raise click.UsageError("At least one of '--activates-at' or '--expires-at' must be given.")

    if activates_at is not None and expires_given:
        ctx.obj.client.set_account_role_dates(account_name, role_name, activates_at=activates_at, expires_at=expires_at)
    elif activates_at is not None:
        ctx.obj.client.set_account_role_activates_at(account_name, role_name, activates_at)
    else:
        ctx.obj.client.set_account_role_expires_at(account_name, role_name, expires_at)

    if activates_at is not None:
        click.echo(f"Role '{role_name}' for account '{account_name}' is now active from {activates_at}.")
    if expires_given:
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
    """Manage permissions of a role, of every type.

    \b
    Every permission type is managed the same way:
      rucio role permission TYPE add|remove ROLE_NAME IDENTIFIER... [PARAMETERS]"""


@permission.command("list")
@click.argument("role_name")
@click.option("--detail", is_flag=True, help="Expand each wildcard scope pattern into the scopes it currently matches, and give the limits and their usage to the byte.")
@click.pass_context
def permission_list(ctx: click.Context, role_name: str, detail: bool) -> None:
    """List permissions assigned to ROLE_NAME, one section per permission type.

    A local limit is listed under the name of its RSE, a global limit under the RSEs its expression currently matches, one per line.
    If you hold ROLE_NAME, each limit is listed with the usage of your account measured against it: like the account limits, each
    account holding the role gets the whole limit for itself. Use `role account list -a ACCOUNT --detail` for that of another account."""
    rbac = ctx.obj.client.list_account_roles(use_issuer_account=True)
    account_name = rbac['account']
    rse_names = _rse_names_resolver(ctx)
    # the limits of a role the account does not hold do not bind it, its usage means nothing against them
    holds_role = any(entry['role'] == role_name and _holds(entry) for entry in rbac['roles'])
    used = _usage_resolver(ctx, account_name, rse_names) if holds_role else None
    lines = permission_lines(ctx.obj.client.list_role_permissions(role_name), SizeFormat.of(ctx.obj.human, exact=detail), used)

    # only fetch the (potentially large) list of every scope if a pattern actually needs expanding
    needs_scopes = detail and any(permission_type == 'scope' and '*' in target for permission_type, target, _, _ in lines)
    known_scopes = ctx.obj.client.list_scopes() if needs_scopes else []

    scope_rows, limit_rows = [], []
    for permission_type, target, operations, limits in lines:
        if permission_type == 'scope':
            cell = target
            if detail and '*' in target:
                cell = format_tree(target, _matching_scopes(target, known_scopes), placeholder="(no scope currently matches)")
            scope_rows.append([permission_type, cell, operations])
        else:
            # a local limit is listed under the name of its single RSE, a global one by the RSEs its expression
            # currently matches, one per line, or by its expression if it matches none
            limit_rows.append([permission_type, '\n'.join(rse_names(target) or [target]), limits])

    sections = [(headers, rows) for headers, rows in ((["TYPE", "IDENTIFIER", "OPERATION(S)"], scope_rows), (["TYPE", "IDENTIFIER", "LIMIT"], limit_rows)) if rows]
    if not sections:
        click.echo(f"No permission associated with role '{role_name}'.")
        return
    click.echo(f"Permissions associated with role '{role_name}':")
    click.echo(format_sections(sections))
    if limit_rows and used is not None:
        click.echo(f"Limits measured against the usage of your account '{account_name}'.")


# --- Scopes -----------------------------------------------------------------------------------

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


@permission.group("scope")
def permission_scope() -> None:
    """Manage the operations a role grants on scopes."""


@permission_scope.command("add")
@click.argument("role_name")
@click.argument("scope_patterns", metavar="SCOPE_PATTERN...", nargs=-1, required=True)
@click.argument("operations", type=OPERATIONS)
@click.option("--force", is_flag=True, default=False, help="Add the permissions even if the role is locked.")
@click.pass_context
def scope_add(ctx: click.Context, role_name: str, scope_patterns: tuple[str, ...], operations: list[ScopeOperationType], force: bool) -> None:
    """Add OPERATIONS on each SCOPE_PATTERN to ROLE_NAME.

    SCOPE_PATTERN only accepts a trailing '*' wildcard, e.g. 'data*' or '*' for every scope; quote it so the shell does not expand it as a glob.

    OPERATIONS is any combination of r(ead), w(rite) and d(elete), in any order, e.g. 'r', 'rw', 'wd', 'rwd' or 'read,delete'."""
    for scope_pattern in scope_patterns:
        if not _confirm_scope_pattern(ctx, scope_pattern, "add"):
            click.echo(f"Skipped scope pattern '{scope_pattern}', no permission was added on it.")
            continue

        added, already_assigned = [], []
        for op in operations:
            try:
                with _lock_hint(role_name):
                    ctx.obj.client.add_role_permission(role_name, 'scope', {'scope_pattern': scope_pattern, 'operation': op.value}, force=force)
                added.append(op.value)
            except Duplicate:
                already_assigned.append(op.value)

        if already_assigned:
            click.echo(f"Warning: {'/'.join(already_assigned)} permission(s) on {scope_pattern} already assigned to role '{role_name}'.")
        if added:
            click.echo(f"Added {'/'.join(added)} permission(s) on {scope_pattern} to role '{role_name}'.")


@permission_scope.command("remove")
@click.argument("role_name")
@click.argument("scope_patterns", metavar="SCOPE_PATTERN...", nargs=-1, required=True)
@click.argument("operations", type=OPERATIONS)
@click.option("--force", is_flag=True, default=False, help="Remove the permissions even if the role is locked.")
@click.pass_context
def scope_remove(ctx: click.Context, role_name: str, scope_patterns: tuple[str, ...], operations: list[ScopeOperationType], force: bool) -> None:
    """Remove OPERATIONS on each SCOPE_PATTERN from ROLE_NAME.

    SCOPE_PATTERN must be given exactly as it was granted, see `rucio role permission list`.

    OPERATIONS is any combination of r(ead), w(rite) and d(elete), in any order, e.g. 'r', 'rw', 'wd', 'rwd' or 'read,delete'."""
    permissions = ctx.obj.client.list_role_permissions(role_name)
    for scope_pattern in scope_patterns:
        assigned = {permission['operation'] for permission in permissions if permission.get('type') == 'scope' and permission['scope_pattern'] == scope_pattern}
        if not any(op.value in assigned for op in operations):
            raise RolePermissionNotFound(
                f"None of the requested permissions ({'/'.join(op.value for op in operations)}) are assigned to role '{role_name}' on scope pattern '{scope_pattern}'.")

    for scope_pattern in scope_patterns:
        if not _confirm_scope_pattern(ctx, scope_pattern, "remove"):
            click.echo(f"Skipped scope pattern '{scope_pattern}', no permission was removed from it.")
            continue

        removed, not_assigned = [], []
        for op in operations:
            try:
                with _lock_hint(role_name):
                    ctx.obj.client.delete_role_permission(role_name, 'scope', {'scope_pattern': scope_pattern, 'operation': op.value}, force=force)
                removed.append(op.value)
            except RolePermissionNotFound:
                not_assigned.append(op.value)
        if not_assigned:
            click.echo(f"Warning: {'/'.join(not_assigned)} permission(s) on {scope_pattern} were already not assigned to role '{role_name}'.")
        click.echo(f"Removed {'/'.join(removed)} permission(s) on {scope_pattern} from role '{role_name}'.")


# --- Limits -----------------------------------------------------------------------------------

def _matching_rses(ctx: click.Context, rse_expression: str) -> list[str]:
    """Return the names of the RSEs an RSE expression currently matches, none if it is not valid or matches nothing."""
    try:
        return sorted(rse['rse'] for rse in ctx.obj.client.list_rses(rse_expression))
    except (InvalidRSEExpression, RSENotFound):
        return []


def _rse_names_resolver(ctx: click.Context) -> "Callable[[str], list[str]]":
    """Give the names of the RSEs an RSE expression currently matches, see :func:`_matching_rses`, asking the server once per expression."""
    names: dict[str, list[str]] = {}

    def _resolve(rse_expression: str) -> list[str]:
        if rse_expression not in names:
            names[rse_expression] = _matching_rses(ctx, rse_expression)
        return names[rse_expression]

    return _resolve


def _usage_resolver(ctx: click.Context, account_name: str, rse_names: "Callable[[str], Sequence[str]]") -> "Optional[Callable[[str], int]]":
    """
    Give the bytes an account uses on the RSEs an RSE expression currently matches, summed over them, as a role limit on the expression measures it.

    The usage of the account on every RSE is asked for once, the RSEs of each expression through `rse_names`.

    :param account_name: The account whose usage to measure.
    :param rse_names: Gives the names of the RSEs an RSE expression currently matches, see :func:`_rse_names_resolver`.
    :returns: The resolver, or None if the usage of the account cannot be read, e.g. that of another account without the right to.
    """
    try:
        usage = {entry['rse']: entry['bytes'] or 0 for entry in ctx.obj.client.get_local_account_usage(account_name)}
    except (AccessDenied, AccountNotFound):
        return None

    def _resolve(rse_expression: str) -> int:
        return sum(usage.get(rse, 0) for rse in rse_names(rse_expression))

    return _resolve


def _confirm_limit_add(ctx: click.Context, role_name: str, rse_expression: str, locality: str, bytes_: int, limits: "Mapping[str, Mapping[str, Any]]") -> bool:
    """
    Ask for confirmation if setting a limit overwrites one of the role with another value.

    :param locality: The locality of the limit to set, 'local' or 'global'.
    :param bytes_: The limit to set.
    :param limits: The limits the role currently has, as listed by the server, by target.
    :returns: True if the caller should proceed, False if the user declined.
    """
    # a local limit is listed under the name of its RSE, which the expression may only match; on an
    # expression which does not match exactly one RSE, the server refuses it, so there is nothing to confirm
    targets = _matching_rses(ctx, rse_expression) if locality == 'local' else [rse_expression]
    overwritten = [(target, limits[target][locality]) for target in targets[:1] if len(targets) == 1 and limits.get(target, {}).get(locality, bytes_) != bytes_]
    if not overwritten:
        return True

    click.echo(f"This overwrites the following limit of role '{role_name}':")
    for target, current in overwritten:
        click.echo(f"  {locality} limit on {target}: {format_quota(current, SizeFormat.of(ctx.obj.human))} -> {format_quota(bytes_, SizeFormat.of(ctx.obj.human))}")
    return click.confirm("Do you still want to set this limit?")


@permission.group("limit")
def permission_limit() -> None:
    """Manage the limits a role grants on RSEs, like `rucio account limit` does for an account.

    A local limit caps the usage of an account on a single RSE, a global limit its usage summed over the several RSEs
    an RSE expression matches. Within a role, an RSE may be written to if a local limit covers it, and every global
    limit covering it must still have room: a global limit only restricts. On an RSE a local limit of one of its
    roles covers, an account is bound by its roles instead of its account limits, the role leaving the most space
    being taken. Each account holding the role gets the whole limit for itself."""


@permission_limit.command("add")
@click.argument("role_name")
@click.argument("rse_expressions", metavar="RSE_EXPRESSION...", nargs=-1, required=True)
@click.option("--local", "local_bytes", type=QUOTA_SIZE, help="Set a local limit of this size on the single RSE the expression matches, e.g. its name.")
@click.option("--global", "global_bytes", type=QUOTA_SIZE,
              help="Set a global limit of this size on the expression, which must match several RSEs, capping the usage summed over the RSEs it matches whenever it is applied.")
@click.option("--force", is_flag=True, default=False, help="Set the limits even if the role is locked.")
@click.pass_context
def limit_add(ctx: click.Context, role_name: str, rse_expressions: tuple[str, ...], local_bytes: Optional[int], global_bytes: Optional[int], force: bool) -> None:
    """Set a limit of ROLE_NAME on each RSE_EXPRESSION, overwriting the existing one after confirmation.

    Exactly one of --local or --global must be given: a local limit is set on an RSE_EXPRESSION matching a single RSE,
    e.g. 'CERN-EOS-DISK', a global limit on one matching several, e.g. 'CERN-EOS-DISK|ICSC-STORM' or 'tier=1'. Quote
    the expressions so the shell does not interpret their operators.

    The size is given in bytes ("10000"), with a storage unit ("10GB"), or as NOCAP (or "infinity") for no cap."""
    if (local_bytes is None) == (global_bytes is None):
        raise click.UsageError("Exactly one of --local or --global must be given: a local limit is set on one RSE, a global one on an expression matching several.")
    locality, bytes_ = ('local', local_bytes) if local_bytes is not None else ('global', global_bytes)

    limits = {permission['rse_expression']: permission for permission in ctx.obj.client.list_role_permissions(role_name) if permission.get('type') == 'limit'}
    for rse_expression in rse_expressions:
        if not _confirm_limit_add(ctx, role_name, rse_expression, locality, bytes_, limits):
            click.echo(f"Skipped RSE expression '{rse_expression}', no limit was set on it.")
            continue

        with _lock_hint(role_name):
            ctx.obj.client.add_role_permission(role_name, 'limit', {'rse_expression': rse_expression, locality: bytes_}, force=force)
        click.echo(f"Set {locality} limit of {format_quota(bytes_, SizeFormat.of(ctx.obj.human))} on {rse_expression} for role '{role_name}'.")
        if bytes_ == 0:
            click.echo(f"Warning: a limit of 0 lets nothing be written on {rse_expression}"
                       + (", while it still takes precedence over the account limits there." if locality == 'local' else "."))


@permission_limit.command("remove")
@click.argument("role_name")
@click.argument("rse_expressions", metavar="RSE_EXPRESSION...", nargs=-1, required=True)
@click.option("--local", "local", is_flag=True, default=False, help="Only remove the local limit on the single RSE the expression matches.")
@click.option("--global", "global_", is_flag=True, default=False, help="Only remove the global limit on the expression.")
@click.option("--force", is_flag=True, default=False, help="Remove the limits even if the role is locked.")
@click.pass_context
def limit_remove(ctx: click.Context, role_name: str, rse_expressions: tuple[str, ...], local: bool, global_: bool, force: bool) -> None:
    """Remove limits of ROLE_NAME on each RSE_EXPRESSION.

    The local limit on the RSE the expression matches is removed, and the global limit on the expression itself, which
    must be given exactly as it was set, see `rucio role permission list`. --local or --global only removes that one;
    both are looked for if neither is given."""
    parameters = {locality: True for locality, given in (('local', local), ('global', global_)) if given}
    # e.g. 'local limit(s)', or just 'limit(s)' if both are looked for
    described = ''.join(f"{locality} " for locality in parameters) + 'limit'

    missing = None
    removed_any = False
    for rse_expression in rse_expressions:
        try:
            with _lock_hint(role_name):
                removed = ctx.obj.client.delete_role_permission(role_name, 'limit', {'rse_expression': rse_expression, **parameters}, force=force)
        except RolePermissionNotFound as error:
            missing = error
            click.echo(f"Warning: role '{role_name}' has no {described} on {rse_expression}.")
            continue
        removed_any = True
        click.echo(f"Removed {removed} {described}(s) on {rse_expression} from role '{role_name}'.")

    if missing is not None and not removed_any:
        raise missing
