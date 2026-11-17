import textwrap
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

import click

from rucio.cli.utils import (
    DATE_COLUMN,
    IDENTIFIER_COLUMN,
    PARAMETER_COLUMN,
    PERMISSIONS_COLUMN,
    ROLE_COLUMN,
    TEXT_COLUMN,
    DidOperationType,
    MetadataOperations,
    OptionalDateTime,
    QuotaSize,
    RoleOperations,
    SizeFormat,
    describe_metadata_keys,
    echo_fitted,
    format_metadata_operations,
    format_operations,
    format_permission_lists,
    format_quota,
    format_table,
    format_tree,
    permission_lines,
    terminal_width,
)
from rucio.common.exception import AccessDenied, AccountNotFound, InvalidRSEExpression, RoleAssignmentDisabled, RoleInUse, RoleLocked, RolePermissionNotFound, RSENotFound
from rucio.common.utils import str_to_date

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Generator, Iterable, Mapping, Sequence


OPERATIONS = RoleOperations()
METADATA_OPERATIONS = MetadataOperations()
QUOTA_SIZE = QuotaSize()

OPTIONAL_DATE = OptionalDateTime()
DATE = click.DateTime(formats=OptionalDateTime.FORMATS)
DATE_EXAMPLE = "2012-02-29 or 2012-02-29T16:33:30"

# appended to the name of a reserved role when listing roles, and explained in place of its permissions with `--detail`
RESERVED_ROLE_TAG = "(built-in)"
RESERVED_ROLE_PERMISSIONS = "(managed by Rucio)"


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


ASSIGNMENT_DATE_FORMAT = "%d-%b-%Y %H:%M:%S UTC"


def _format_date(date: Optional[str]) -> str:
    """Render a date of a role assignment, as listed by the server, e.g. '21-Oct-2026 07:58:54 UTC', '-' if there is none."""
    if not date:
        return '-'
    try:
        return str_to_date(date).strftime(ASSIGNMENT_DATE_FORMAT)  # type: ignore[union-attr]
    except ValueError:
        # a date in another format than the one the server sends, shown as is rather than hidden
        return date


def _fill(text: str) -> str:
    """Wrap a line printed along a table, e.g. its title, to the width of the terminal, so that it does not make the output too wide, see :func:`echo_fitted`."""
    return textwrap.fill(text, terminal_width())


def _role_label(role_name: str, reserved: bool, emphasized: bool = False) -> str:
    """The name of a role, in bold if `emphasized`, tagged with `RESERVED_ROLE_TAG` if it is reserved."""
    name = click.style(role_name, bold=True) if emphasized else role_name
    return f"{name} {RESERVED_ROLE_TAG}" if reserved else name


def _role_card(role_name: str, reserved: bool, properties: "Sequence[tuple[str, str]]", description: Optional[str]) -> str:
    """
    A role as the first cell of a row of a `--detail` table, its name emphasized, its properties and its description below it:

        moderator
        assignable: True
        locked:     False

        Reads the DIDs of scope physics.

    :param properties: The properties, as their label and value, e.g. ('assignable', 'True').
    """
    label_width = max(len(label) for label, _ in properties) + 1
    lines = [_role_label(role_name, reserved, emphasized=True)]
    lines.extend(f"{(label + ':').ljust(label_width)} {value}" for label, value in properties)
    if description:
        lines.extend(['', description])
    return '\n'.join(lines)


def _role_permissions(
        ctx: click.Context,
        roles: "Sequence[tuple[str, bool, Iterable[Mapping[str, Any]]]]",
        account_name: Optional[str] = None,
        held: "Collection[str]" = (),
) -> "Callable[[Optional[int]], list[str]]":
    """
    The permissions of each role, as the PERMISSIONS column of a `--detail` table, aligned with each other, see
    :func:`format_permission_lists`.

    A reserved role has no permissions, so its tag is explained instead.

    :param roles: The roles, as their name, whether they are reserved, and their permissions as listed by the server.
    :param account_name: The account to measure the limits against, see :func:`_usage_resolver`. None to only list the limits.
    :param held: The roles `account_name` holds, see :func:`_holds`: only their limits are measured, the others being
                 limits the account is not bound by.
    :returns: Gives the permissions, in the order of `roles`, given the width they should fit in, see `format_table`.
    """
    rse_names = _rse_names_resolver(ctx)
    used = _usage_resolver(ctx, account_name, rse_names) if account_name is not None and held else None

    def _permissions(width: Optional[int]) -> list[str]:
        cells = iter(format_permission_lists(
            [(permissions, used if role_name in held else None) for role_name, reserved, permissions in roles if not reserved],
            rse_names, SizeFormat.of(ctx.obj.human), width=width,
        ))
        return [RESERVED_ROLE_PERMISSIONS if reserved else next(cells) for _, reserved, _ in roles]

    return _permissions


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
    """Manage roles, their permissions and the accounts holding them (RBAC).

    An account gets what all its roles grant: the roles always add up, none restricts another."""


@role.command("list")
@click.option("--detail", is_flag=True, help="Also show the permissions of each role.")
@click.pass_context
def list_(ctx: click.Context, detail: bool) -> None:
    """List the roles. Roles managed by Rucio are tagged (built-in)."""
    roles = ctx.obj.client.list_roles()
    if not detail:
        rows = [
            [_role_label(entry['role'], bool(entry.get('reserved'))), str(entry.get('assignable')), str(entry.get('locked')), entry.get('description') or '-']
            for entry in roles
        ]
        echo_fitted(ctx, format_table([(["ROLE", "ASSIGNABLE", "LOCKED", "DESCRIPTION"], rows)], {0: IDENTIFIER_COLUMN, 3: TEXT_COLUMN}))
        return

    rows = [
        [_role_card(entry['role'], bool(entry.get('reserved')), [('assignable', str(entry.get('assignable'))), ('locked', str(entry.get('locked')))], entry.get('description')), '']
        for entry in roles
    ]
    permissions = _role_permissions(ctx, [
        (entry['role'], bool(entry.get('reserved')), [] if entry.get('reserved') else ctx.obj.client.list_role_permissions(entry['role']))
        for entry in roles
    ])
    echo_fitted(ctx, format_table([(["ROLE", "PERMISSIONS"], rows)], {0: ROLE_COLUMN, 1: PERMISSIONS_COLUMN}, fitted={1: permissions}))


@role.command("add")
@click.pass_context
@click.argument("role_name")
@click.option("-d", "--description", help="Description of the role.")
@click.option("-a", "--assignable", type=bool, is_flag=False, flag_value="true", default=True, show_default=True,
              help="true/false: whether the role can be assigned to and removed from accounts.")
@click.option("-l", "--locked", type=bool, is_flag=False, flag_value="true", default=True, show_default=True,
              help="true/false: whether the role is locked, i.e. can't be changed nor deleted.")
def add(ctx: click.Context, role_name: str, description: Optional[str], assignable: bool, locked: bool) -> None:
    """Create the role ROLE_NAME."""
    ctx.obj.client.add_role(role_name, description=description, assignable=assignable, locked=locked)
    click.echo(f"Role '{role_name}' added.")


@role.command("update")
@click.pass_context
@click.argument("role_name")
@click.option("-d", "--description", help='New description, "" to remove it.')
@click.option("-a", "--assignable", type=bool, is_flag=False, flag_value="true", default=None,
              help="true/false: whether the role can be assigned to and removed from accounts.")
@click.option("-l", "--locked", type=bool, is_flag=False, flag_value="true", default=None,
              help="true/false: whether the role is locked, i.e. can't be changed nor deleted.")
@click.option("--force", is_flag=True, default=False, help="Change the description or --assignable even if the role is locked.")
def update(ctx: click.Context, role_name: str, description: Optional[str], assignable: Optional[bool], locked: Optional[bool], force: bool) -> None:
    """Change the given properties of ROLE_NAME."""
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
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked or held: revokes it from its accounts and drops its permissions.")
def delete(ctx: click.Context, role_name: str, force: bool) -> None:
    """Delete the role ROLE_NAME."""
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
    """Manage which accounts hold which roles."""


@account.command("list")
@click.option("-a", "--account", "account_name", metavar="ACCOUNT", help="The roles of ACCOUNT.")
@click.option("-r", "--role", "role_name", metavar="ROLE", help="The accounts holding ROLE.")
@click.option("--me", is_flag=True, help="Your own roles.")
@click.option("--detail", is_flag=True, help="With -a or --me: also show the permissions of each role, and the usage of each limit.")
@click.pass_context
def account_list(ctx: click.Context, account_name: Optional[str], role_name: Optional[str], me: bool, detail: bool) -> None:
    """List role assignments: give exactly one of -a, -r or --me."""
    if sum([account_name is not None, role_name is not None, me]) != 1:
        raise click.UsageError("Exactly one of -a/--account, -r/--role or --me must be given.")
    if detail and role_name is not None:
        raise click.UsageError("--detail can only be used with -a/--account or --me.")

    if role_name is not None:
        assignments = ctx.obj.client.list_role_accounts(role_name)
        reserved = any(entry['role'] == role_name and entry.get('reserved') for entry in ctx.obj.client.list_roles())
        rows = [[assignment['account'], _format_date(assignment.get('activates_at')), _format_date(assignment.get('expires_at'))] for assignment in assignments]
        table = format_table([(["ACCOUNT", "ACTIVATES AT", "EXPIRES AT"], rows)], {0: IDENTIFIER_COLUMN, 1: DATE_COLUMN, 2: DATE_COLUMN})
        echo_fitted(ctx, f"{_fill(f'Accounts assigned to role {_role_label(role_name, reserved)}:')}\n{table}")
        return

    rbac = ctx.obj.client.list_account_roles(account_name, use_issuer_account=me, detail=detail)
    title = _fill(f"Roles for account '{rbac['account']}':")
    if not detail:
        rows = [
            [_role_label(entry['role'], bool(entry.get('reserved'))), _format_date(entry.get('activates_at')), _format_date(entry.get('expires_at'))]
            for entry in rbac['roles']
        ]
        table = format_table([(["ROLE", "ACTIVATES AT", "EXPIRES AT"], rows)], {0: IDENTIFIER_COLUMN, 1: DATE_COLUMN, 2: DATE_COLUMN})
        echo_fitted(ctx, f"{title}\n{table}")
        return

    permissions_by_role: dict[str, list[dict[str, Any]]] = {}
    for permission in rbac['permissions']:
        permissions_by_role.setdefault(permission['role'], []).append(permission)
    rows = [
        [_role_card(entry['role'], bool(entry.get('reserved')), [('from', _format_date(entry.get('activates_at'))), ('until', _format_date(entry.get('expires_at')))], entry.get('description')), '']
        for entry in rbac['roles']
    ]
    permissions = _role_permissions(
        ctx, [(entry['role'], bool(entry.get('reserved')), permissions_by_role.get(entry['role'], [])) for entry in rbac['roles']],
        account_name=rbac['account'], held={entry['role'] for entry in rbac['roles'] if _holds(entry)},
    )
    table = format_table([(["ROLE", "PERMISSIONS"], rows)], {0: ROLE_COLUMN, 1: PERMISSIONS_COLUMN}, fitted={1: permissions})
    echo_fitted(ctx, f"{title}\n{table}")


@account.command("add")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--activates-at", type=DATE, metavar="DATE", help=f"Start date, e.g. {DATE_EXAMPLE}. Default: now.")
@click.option("--expires-at", type=OPTIONAL_DATE, help=f"End date, e.g. {DATE_EXAMPLE}, or {OptionalDateTime.NEVER}. Default: {OptionalDateTime.NEVER}.")
@click.option("--force", is_flag=True, default=False, help="Even if the role is not assignable.")
@click.pass_context
def account_add(ctx: click.Context, role_name: str, account_name: str, activates_at: Optional["datetime"], expires_at: Optional["datetime"], force: bool) -> None:
    """Assign ROLE_NAME to ACCOUNT_NAME."""
    with _assignable_hint(role_name, account_name, action="assigned to"):
        ctx.obj.client.add_account_role(account_name, role_name, expires_at=expires_at, force=force, activates_at=activates_at)
    period = (f", active from {activates_at}" if activates_at else "") + (f", expiring at {expires_at}" if expires_at else "")
    click.echo(f"Added role '{role_name}' to account '{account_name}'{period}.")


@account.command("update")
@click.argument("role_name")
@click.argument("account_name")
@click.option("--activates-at", type=DATE, metavar="DATE", help=f"New start date, e.g. {DATE_EXAMPLE}.")
@click.option("--expires-at", type=OPTIONAL_DATE, help=f"New end date, e.g. {DATE_EXAMPLE}, or {OptionalDateTime.NEVER}.")
@click.pass_context
def account_update(ctx: click.Context, role_name: str, account_name: str, activates_at: Optional["datetime"], expires_at: Optional["datetime"]) -> None:
    """Change the dates of the assignment of ROLE_NAME to ACCOUNT_NAME: give at least one of them."""
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
@click.option("--force", is_flag=True, default=False, help="Even if the role is not assignable.")
@click.pass_context
def account_remove(ctx: click.Context, role_name: str, account_name: str, force: bool) -> None:
    """Revoke ROLE_NAME from ACCOUNT_NAME."""
    with _assignable_hint(role_name, account_name, action="removed from"):
        ctx.obj.client.delete_account_role(account_name, role_name, force=force)
    click.echo(f"Removed role '{role_name}' from account '{account_name}'.")


@role.group()
def permission() -> None:
    """Manage the permissions of a role."""


@permission.command("list")
@click.argument("role_name")
@click.option("--detail", is_flag=True, help="Expand wildcard scope patterns into their scopes, and show sizes to the byte.")
@click.pass_context
def permission_list(ctx: click.Context, role_name: str, detail: bool) -> None:
    """List the permissions of ROLE_NAME. If you hold it, its limits show your usage."""
    rbac = ctx.obj.client.list_account_roles(use_issuer_account=True)
    account_name = rbac['account']
    rse_names = _rse_names_resolver(ctx)
    # the limits of a role the account does not hold do not bind it, its usage means nothing against them
    holds_role = any(entry['role'] == role_name and _holds(entry) for entry in rbac['roles'])
    used = _usage_resolver(ctx, account_name, rse_names) if holds_role else None
    lines = permission_lines(ctx.obj.client.list_role_permissions(role_name), SizeFormat.of(ctx.obj.human, exact=detail), used)

    # only fetch the (potentially large) list of every scope if a pattern actually needs expanding
    needs_scopes = detail and any(permission_type in ('did', 'metadata') and _is_scope_wildcard(target) for permission_type, target, _, _ in lines)
    known_scopes = ctx.obj.client.list_scopes() if needs_scopes else []

    did_rows, metadata_rows, limit_rows = [], [], []
    for permission_type, target, operations, limits in lines:
        if permission_type in ('did', 'metadata'):
            cell = target
            if detail and _is_scope_wildcard(target):
                cell = format_tree(target, _matching_scopes(target, known_scopes), placeholder="(no scope currently matches)")
            (did_rows if permission_type == 'did' else metadata_rows).append([permission_type, cell, operations])
        else:
            # a local limit is listed under the name of its single RSE, a global one by the RSEs its expression
            # currently matches, one per line, or by its expression if it matches none
            limit_rows.append([permission_type, '\n'.join(rse_names(target) or [target]), limits])

    sections = [(headers, rows) for headers, rows in (
        (["TYPE", "IDENTIFIER", "OPERATION(S)"], did_rows),
        (["TYPE", "IDENTIFIER", "OPERATION(S) ON KEY(S)"], metadata_rows),
        (["TYPE", "IDENTIFIER", "LIMIT"], limit_rows),
    ) if rows]
    if not sections:
        click.echo(f"No permission associated with role '{role_name}'.")
        return
    output = [_fill(f"Permissions associated with role '{role_name}':"), format_table(sections, {1: IDENTIFIER_COLUMN, 2: PARAMETER_COLUMN})]
    if limit_rows and used is not None:
        output.append(_fill(f"Limits measured against the usage of your account '{account_name}'."))
    echo_fitted(ctx, '\n'.join(output))


# --- DIDs -------------------------------------------------------------------------------------

def _is_scope_wildcard(did_pattern: str) -> bool:
    """Tell whether a DID pattern has a wildcard scope part, e.g. 'data*:*', which may match several scopes."""
    return '*' in did_pattern.partition(':')[0]


def _normalize_did_pattern(did_pattern: str) -> str:
    """Bring a DID pattern to the form it is stored and listed in, as done server-side: a pattern without name part stands for the whole scope(s), e.g. 'data' for 'data:*'."""
    did_pattern = did_pattern.strip()
    return did_pattern if ':' in did_pattern else did_pattern + ':*'


def _matching_scopes(did_pattern: str, known_scopes: list[str]) -> list[str]:
    """Return the known scopes the wildcard scope part of a DID pattern matches, as 'scope:*'. Only a trailing '*' is accepted, as enforced server-side."""
    prefix = did_pattern.partition(':')[0][:-1]
    return [f'{scope}:*' for scope in sorted(known_scopes) if scope.startswith(prefix)]


def _confirm_did_pattern(ctx: click.Context, did_pattern: str, verb: str) -> bool:
    """
    Show the scopes a wildcard scope pattern currently matches and ask for confirmation.

    Always True for any other DID pattern, since it stays within a single scope ('data:*', 'data:raw*',
    'data:raw1'), so there is nothing to expand or confirm.

    :param verb: The action to ask confirmation for, e.g. 'add' or 'remove'.
    :returns: True if the caller should proceed, False if the user declined.
    """
    if not _is_scope_wildcard(did_pattern):
        return True

    matches = _matching_scopes(did_pattern, ctx.obj.client.list_scopes())
    click.echo(f"The '{did_pattern}' pattern currently matches the following scope(s):")
    for scope in matches:
        click.echo(f"  {scope}")
    if not matches:
        click.echo("  (none)")

    return click.confirm(f"Do you still want to {verb} this permission?")


def _did_pattern_specificity(did_pattern: str) -> tuple[int, int]:
    """Rank a DID pattern as the server does, the higher the more specific: a single DID, a name pattern, a whole scope, a scope pattern, a longer prefix being more specific."""
    scope_part, _, name_part = did_pattern.partition(':')
    if name_part != '*':
        return (2, len(name_part) - 1) if name_part.endswith('*') else (3, len(name_part))
    return (0, len(scope_part) - 1) if scope_part.endswith('*') else (1, len(scope_part))


def _did_pattern_covers(wider: str, narrower: str) -> bool:
    """Tell whether a DID pattern matches every DID another, more specific, one matches, e.g. 'data:*' covers 'data:raw*'."""
    if wider == narrower or _did_pattern_specificity(wider) >= _did_pattern_specificity(narrower):
        return False
    wider_scope, _, wider_name = wider.partition(':')
    narrower_scope, _, narrower_name = narrower.partition(':')
    if wider_name == '*':
        # a whole scope, or the scopes starting with a prefix
        if wider_scope.endswith('*'):
            return narrower_scope.rstrip('*').startswith(wider_scope[:-1])
        return narrower_scope == wider_scope
    # a single DID covers no other pattern; a name pattern covers the longer name patterns and the single DIDs of its scope
    return wider_name.endswith('*') and narrower_scope == wider_scope and narrower_name.rstrip('*').startswith(wider_name[:-1])


def _deciding_did_pattern(did_pattern: str, operations_by_pattern: "Mapping[str, str]") -> Optional[str]:
    """Among the DID patterns of a role, the most specific one covering `did_pattern`: it decides the DIDs `did_pattern` matches without it."""
    covering = [pattern for pattern in operations_by_pattern if _did_pattern_covers(pattern, did_pattern)]
    return max(covering, key=_did_pattern_specificity) if covering else None


def _assigned_did_operations(ctx: click.Context, role_name: str) -> dict[str, str]:
    """The operations of the DID permissions of a role, e.g. 'r--', by DID pattern."""
    return {
        permission['did_pattern']: format_operations(permission['operations'])
        for permission in ctx.obj.client.list_role_permissions(role_name)
        if permission.get('type') == 'did'
    }


@permission.group("did")
def permission_did() -> None:
    """Manage the operations a role grants on DIDs.

    \b
    r  see and read the DIDs, their data and metadata
    w  create DIDs, add content
    d  alter and delete existing DIDs
    Within a role, the most specific pattern matching a DID decides it: e.g. 'rwd' on
    'data:*' and 'r' on 'data:raw*' keep the raw DIDs read-only."""


@permission_did.command("add")
@click.argument("role_name")
@click.argument("did_pattern")
@click.argument("operations", type=OPERATIONS)
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked.")
@click.pass_context
def did_add(ctx: click.Context, role_name: str, did_pattern: str, operations: list[DidOperationType], force: bool) -> None:
    """Set OPERATIONS on DID_PATTERN for ROLE_NAME, replacing them.

    \b
    DID_PATTERN  SCOPE:NAME, a '*' only at the end of a part (quote it):
                   '*' or '*:*'           every DID
                   'data*' or 'data*:*'   the DIDs of the scopes starting with data
                   'data' or 'data:*'     the DIDs of the scope data
                   'data:raw*'            the DIDs of data whose name starts with raw
                   'data:raw1'            the DID data:raw1
    OPERATIONS   r, w, d in any order, e.g. 'rw', or 'none' (listed '---') to grant
                 nothing on these DIDs, i.e. hide them from a wider pattern."""
    did_pattern = _normalize_did_pattern(did_pattern)
    new = format_operations(op.value for op in operations)
    assigned = _assigned_did_operations(ctx, role_name)
    if not _confirm_did_pattern(ctx, did_pattern, "add"):
        click.echo(f"Skipped DID pattern '{did_pattern}', no permission was set on it.")
        return

    with _lock_hint(role_name):
        ctx.obj.client.add_role_permission(role_name, 'did', {'did_pattern': did_pattern, 'operations': [op.value for op in operations]}, force=force)

    if did_pattern in assigned and assigned[did_pattern] != new:
        click.echo(f"Replaced {assigned[did_pattern]} by {new} on {did_pattern}.")
    click.echo(f"Set {new} on {did_pattern} for role '{role_name}'.")
    wider = _deciding_did_pattern(did_pattern, assigned)
    withdrawn = [letter for letter in assigned.get(wider, '') if letter != '-' and letter not in new]
    if wider is not None and withdrawn:
        click.echo(f"Warning: {did_pattern} ({new}) is more specific than {wider} ({assigned[wider]}), so it decides the DIDs it matches"
                   f" instead: {'/'.join(withdrawn)} withdrawn from them within role '{role_name}'.")


@permission_did.command("remove")
@click.argument("role_name")
@click.argument("did_pattern")
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked.")
@click.pass_context
def did_remove(ctx: click.Context, role_name: str, did_pattern: str, force: bool) -> None:
    """Remove the DID permission of ROLE_NAME on DID_PATTERN.

    \b
    DID_PATTERN  as listed by `rucio role permission list`. Its DIDs fall back to
                 the next wider pattern of the role, if any."""
    did_pattern = _normalize_did_pattern(did_pattern)
    assigned = _assigned_did_operations(ctx, role_name)
    if did_pattern not in assigned:
        raise RolePermissionNotFound(
            f"Role '{role_name}' has no DID permission on {did_pattern}."
            + (f" Its DID permissions are on: {', '.join(sorted(assigned))}." if assigned else ""))
    if not _confirm_did_pattern(ctx, did_pattern, "remove"):
        click.echo(f"Skipped DID pattern '{did_pattern}', no permission was removed from it.")
        return

    with _lock_hint(role_name):
        ctx.obj.client.delete_role_permission(role_name, 'did', {'did_pattern': did_pattern}, force=force)
    removed = assigned.pop(did_pattern)
    wider = _deciding_did_pattern(did_pattern, assigned)
    decided = f"decided by {wider} ({assigned[wider]}) again" if wider is not None else "no longer granted anything by this role through a DID permission"
    click.echo(f"Removed {removed} on {did_pattern} from role '{role_name}': the DIDs it matched are {decided}.")


# --- Metadata ---------------------------------------------------------------------------------

def _metadata_keys(keys: "Iterable[str]") -> list[str]:
    """
    The metadata keys given on the command line, each argument possibly holding several comma-separated keys.

    An empty list stands for no key.
    """
    return sorted({key.strip() for argument in keys for key in argument.split(',') if key.strip()})


def _assigned_metadata_operations(ctx: click.Context, role_name: str, did_pattern: str) -> dict[Optional[str], str]:
    """The operations of the metadata permissions of a role on a DID pattern, e.g. 'r-', by key (None for no key)."""
    return {
        permission['meta_key']: format_metadata_operations(permission['operations'])
        for permission in ctx.obj.client.list_role_permissions(role_name)
        if permission.get('type') == 'metadata' and permission['did_pattern'] == did_pattern
    }


@permission.group("metadata")
def permission_metadata() -> None:
    """Manage the operations a role grants on metadata keys of DIDs.

    \b
    r  see the key and its value, and list the DIDs (without their data)
    w  add, modify or delete the key
    On the keys it names, it overrides the DID permissions of the role: e.g. DID 'r' on
    'data:*' and metadata 'none' on 'provenance' of 'data:*' hide that key."""


@permission_metadata.command("add")
@click.argument("role_name")
@click.argument("did_pattern")
@click.argument("operations", type=METADATA_OPERATIONS)
@click.argument("keys", metavar="[KEY...]", nargs=-1)
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked.")
@click.pass_context
def metadata_add(ctx: click.Context, role_name: str, did_pattern: str, operations: list[DidOperationType], keys: tuple[str, ...], force: bool) -> None:
    """Set OPERATIONS on each KEY of DID_PATTERN for ROLE_NAME, replacing them.

    \b
    DID_PATTERN  SCOPE:NAME, a '*' only at the end of a part (quote it):
                   '*' or '*:*'           every DID
                   'data*' or 'data*:*'   the DIDs of the scopes starting with data
                   'data' or 'data:*'     the DIDs of the scope data
                   'data:raw*'            the DIDs of data whose name starts with raw
                   'data:raw1'            the DID data:raw1
    OPERATIONS   r, w in any order, e.g. 'rw', or 'none' (listed '--') to hide the keys.
    KEY          keys, spaced or comma-separated, e.g. 'quality,datatype'; '*' for every
                 key (quote it); no KEY to only list the DIDs (OPERATIONS 'r').
    The keys held by Rucio (bytes, checksums, lifetime, ...) can only get 'r'."""
    did_pattern = _normalize_did_pattern(did_pattern)
    meta_keys = _metadata_keys(keys)
    if not _confirm_did_pattern(ctx, did_pattern, "add"):
        click.echo(f"Skipped DID pattern '{did_pattern}', no permission was set on it.")
        return

    assigned = _assigned_metadata_operations(ctx, role_name, did_pattern)
    parameters: dict[str, Any] = {'did_pattern': did_pattern, 'operations': [op.value for op in operations]}
    if meta_keys:
        parameters['keys'] = meta_keys
    with _lock_hint(role_name):
        ctx.obj.client.add_role_permission(role_name, 'metadata', parameters, force=force)

    new = format_metadata_operations(op.value for op in operations)
    changed: dict[str, list[Optional[str]]] = {}
    for key in meta_keys or [None]:
        if key in assigned and assigned[key] != new:
            changed.setdefault(assigned[key], []).append(key)
    for old, changed_keys in sorted(changed.items()):
        click.echo(f"Replaced {old} by {new} on {describe_metadata_keys(changed_keys)} of {did_pattern}.")
    if meta_keys:
        click.echo(f"Set {new} on {describe_metadata_keys(meta_keys)} of {did_pattern} for role '{role_name}'.")
    else:
        click.echo(f"Set {new} on no key of {did_pattern} for role '{role_name}': the DIDs it matches are visible.")
    if new == '-w':
        click.echo(f"Note: without r, the DIDs matching {did_pattern} are not made visible: the keys can be written but not read.")


@permission_metadata.command("remove")
@click.argument("role_name")
@click.argument("did_pattern")
@click.argument("keys", metavar="[KEY...]", nargs=-1)
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked.")
@click.pass_context
def metadata_remove(ctx: click.Context, role_name: str, did_pattern: str, keys: tuple[str, ...], force: bool) -> None:
    """Remove the metadata permissions of ROLE_NAME on each KEY of DID_PATTERN.

    \b
    DID_PATTERN, KEY  as listed by `rucio role permission list`: '*' for every key,
                      no KEY for the one on no key. The keys fall back to the DID permissions."""
    did_pattern = _normalize_did_pattern(did_pattern)
    meta_keys = _metadata_keys(keys)
    assigned = _assigned_metadata_operations(ctx, role_name, did_pattern)
    missing = [key for key in meta_keys or [None] if key not in assigned]
    if missing:
        raise RolePermissionNotFound(
            f"Role '{role_name}' has no metadata permission on {describe_metadata_keys(missing)} of {did_pattern}, nothing was removed."
            + (f" Its metadata permissions on {did_pattern} are on: {describe_metadata_keys(assigned)}." if assigned else ""))
    if not _confirm_did_pattern(ctx, did_pattern, "remove"):
        click.echo(f"Skipped DID pattern '{did_pattern}', no permission was removed from it.")
        return

    parameters: dict[str, Any] = {'did_pattern': did_pattern}
    if meta_keys:
        parameters['keys'] = meta_keys
    with _lock_hint(role_name):
        ctx.obj.client.delete_role_permission(role_name, 'metadata', parameters, force=force)
    click.echo(f"Removed the metadata permission(s) on {describe_metadata_keys(meta_keys or [None])} of {did_pattern} from role '{role_name}'.")


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
    """Manage the storage limits a role grants on RSEs, per account holding it.

    \b
    local   cap on one RSE: the role lets its accounts write there
    global  cap on the total over several RSEs: it only restricts the local limits
    Where a role has a local limit, the roles replace the account limits, the most
    generous role applying."""


@permission_limit.command("add")
@click.argument("role_name")
@click.argument("rse_expressions", metavar="RSE_EXPRESSION...", nargs=-1, required=True)
@click.option("--local", "local_bytes", type=QUOTA_SIZE, metavar="SIZE", help="Local limit, on an expression matching one RSE.")
@click.option("--global", "global_bytes", type=QUOTA_SIZE, metavar="SIZE", help="Global limit, on an expression matching several RSEs.")
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked.")
@click.pass_context
def limit_add(ctx: click.Context, role_name: str, rse_expressions: tuple[str, ...], local_bytes: Optional[int], global_bytes: Optional[int], force: bool) -> None:
    """Set a limit of ROLE_NAME on each RSE_EXPRESSION, replacing it.

    \b
    Give exactly one of --local or --global.
    RSE_EXPRESSION  one RSE for --local, e.g. 'CERN-EOS-DISK'; several for --global,
                    e.g. 'tier=1' (quote it).
    SIZE            bytes ('10000'), with a unit ('10GB'), or NOCAP for no cap."""
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
@click.option("--local", "local", is_flag=True, default=False, help="Only the local limit.")
@click.option("--global", "global_", is_flag=True, default=False, help="Only the global limit.")
@click.option("--force", is_flag=True, default=False, help="Even if the role is locked.")
@click.pass_context
def limit_remove(ctx: click.Context, role_name: str, rse_expressions: tuple[str, ...], local: bool, global_: bool, force: bool) -> None:
    """Remove the limits of ROLE_NAME on each RSE_EXPRESSION.

    \b
    Both the local and the global one, unless --local or --global is given.
    RSE_EXPRESSION  as it was set, see `rucio role permission list`."""
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
