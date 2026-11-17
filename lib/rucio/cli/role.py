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

import pydoc
import re
import shutil
import textwrap
from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple, Optional

import click

from rucio.common.exception import RoleAssignmentDisabled, RoleInUse, RoleLocked, RolePermissionNotFound
from rucio.common.utils import str_to_date

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable, Mapping, Sequence


# Client-side representation of the operations a DID permission can grant.
class DidOperationType(Enum):
    READ = 'read'
    WRITE = 'write'
    DELETE = 'delete'


# The letter shown for each operation, in the order the operations are rendered.
OPERATION_LETTERS: dict[DidOperationType, str] = {
    DidOperationType.READ: 'r',
    DidOperationType.WRITE: 'w',
    DidOperationType.DELETE: 'd',
}


def format_operations(operations: "Iterable[str]") -> str:
    """
    Render the operations granted on a DID pattern compactly, e.g. 'rw-' for read and write, 'r--' for read only.

    :param operations: The operation values that are granted, e.g. 'read', 'write' and/or 'delete'.
    :returns: One character per known operation, with '-' where the operation is not granted.
    """
    granted = set(operations)
    return ''.join(
        letter if operation.value in granted else '-'
        for operation, letter in OPERATION_LETTERS.items()
    )


TREE_BRANCH = "|-- "
TREE_LAST_BRANCH = "`-- "
TREE_PLACEHOLDER_INDENT = "`-- "
# prefixes the lines of a multi-line branch other than the one it is attached by, see `format_tree`
TREE_TRUNK = "|   "
TREE_NO_TRUNK = "    "
# the permissions of a role which has none, see `format_permission_lists`
NO_PERMISSION = "(no permission assigned)"


def format_tree(root: str, branches: "Sequence[str]", placeholder: str) -> str:
    """
    Render a node and its branches as a tree, to be used as a single (multi-line) table cell.

    Keeping the whole tree in one cell makes it start right below `root`, even if another column
    of the same row wraps over several lines, and keeps the indentation of the branches, which
    tabulate would strip from single-line cells.

    A branch may span several lines: it is attached to the
    tree by its middle line, the trunk running along the lines above it, and along those below it
    unless it is the last branch.

    :param root: The first line of the tree, e.g. a role name or a DID pattern.
    :param branches: One entry per branch, listed under `root` in the given order.
    :param placeholder: The line listed under `root` if there is no branch.
    :returns: The lines of the tree, joined by newlines.
    """
    if not branches:
        return '\n'.join([root, f"{TREE_PLACEHOLDER_INDENT}{placeholder}"])

    lines = [root]
    for index, branch in enumerate(branches):
        last = index == len(branches) - 1
        branch_lines = branch.split('\n')
        anchor = (len(branch_lines) - 1) // 2
        for line_index, line in enumerate(branch_lines):
            if line_index < anchor:
                prefix = TREE_TRUNK
            elif line_index == anchor:
                prefix = TREE_LAST_BRANCH if last else TREE_BRANCH
            else:
                prefix = TREE_NO_TRUNK if last else TREE_TRUNK
            lines.append(f"{prefix}{line}")
    return '\n'.join(lines)


def permission_lines(permissions: "Iterable[Mapping[str, Any]]") -> list[tuple[str, str, str]]:
    """
    Gather the permissions of a role into one line per type and target, sorted by type then target.

    :param permissions: The permissions of the role, as listed by the server.
    :returns: The lines, as (type, target, operations): the operations granted on a DID pattern, e.g. 'rw-'
              (see :func:`format_operations`). A permission of a type this client does not know is left out.
    """
    ops_by_did_pattern: dict[str, list[str]] = {}
    for permission in permissions:
        if permission.get('type') == 'did':
            ops_by_did_pattern[permission['did_pattern']] = permission['operations']

    return [('did', did_pattern, format_operations(ops)) for did_pattern, ops in sorted(ops_by_did_pattern.items())]


def format_permission_lists(roles: "Sequence[Iterable[Mapping[str, Any]]]", width: Optional[int] = None) -> list[str]:
    """
    Render the permissions of several roles, each to be used as a single table cell.

    Each line of :func:`permission_lines` is one entry, made of the same columns whatever its type,
    aligned across the entries of all the roles: its TYPE, its identifier and its parameters, i.e. the
    operations on a DID pattern:

        DID   physics:*  r--
        DID   data:raw*  rw-

    :param roles: The roles, as their permissions as listed by the server.
    :param width: The width the lines should fit in, None for no limit. The identifier column narrows to it, down to
                  `MIN_IDENTIFIER_WIDTH`, each identifier too long for it being broken over several lines, see
                  :func:`break_identifier`.
    :returns: The permissions of each role, in the order of `roles`, their lines joined by newlines.
    """
    # each entry of each role as (type, identifier, parameters)
    entries_by_role = [
        [(permission_type.upper(), target, operations) for permission_type, target, operations in permission_lines(permissions)]
        for permissions in roles
    ]

    all_entries = [entry for entries in entries_by_role for entry in entries]
    if not all_entries:
        return [NO_PERMISSION for _ in roles]

    type_width = max(len(permission_type) for permission_type, _, _ in all_entries) + 3
    id_width = max(len(identifier) + 2 for _, identifier, _ in all_entries)
    if width is not None:
        parameters_width = max(len(line) for _, _, parameters in all_entries for line in parameters.split('\n'))
        id_width = max(min(id_width, width - type_width - parameters_width), MIN_IDENTIFIER_WIDTH + 2)

    cells = []
    for entries in entries_by_role:
        lines = []
        for permission_type, identifier, parameters in entries:
            identifier_lines = break_identifier(identifier, id_width - 2)
            parameter_lines = parameters.split('\n')
            lines.extend(
                f"{(permission_type if index == 0 else '').ljust(type_width)}"
                f"{(identifier_lines[index] if index < len(identifier_lines) else '').ljust(id_width)}"
                f"{parameter_lines[index] if index < len(parameter_lines) else ''}".rstrip()
                for index in range(max(len(identifier_lines), len(parameter_lines)))
            )
        cells.append('\n'.join(lines) if lines else NO_PERMISSION)
    return cells


# --- Tables -----------------------------------------------------------------------------------

# ends each line of an identifier but the last when it is broken over several lines, see `break_identifier`
IDENTIFIER_CONTINUATION = '\\'
# the characters an identifier is preferably broken after, e.g. 'physics:calib.' / '00456789._0001'
IDENTIFIER_SEPARATORS = ':._-/'
# the narrowest an identifier column gets, its identifiers being broken over several lines
MIN_IDENTIFIER_WIDTH = 12
# the styles a table cell may have, e.g. a role name in bold, which take no room on the terminal
ANSI_STYLE = re.compile(r'\x1b\[[0-9;]*m')


def terminal_width() -> int:
    """The width of the terminal, 120 if the output is not one, e.g. piped into a file."""
    return shutil.get_terminal_size(fallback=(120, 24)).columns


def visible_length(text: str) -> int:
    """The room a line takes on the terminal, without its styles, see `ANSI_STYLE`."""
    return len(ANSI_STYLE.sub('', text))


def break_identifier(identifier: str, width: int) -> list[str]:
    """
    Break an identifier, which has no spaces to wrap at (a DID pattern, an RSE name, ...), into lines of at most `width` characters.

    Each line but the last ends with `IDENTIFIER_CONTINUATION`, so that a broken identifier does not read as several.
    It is broken after the last of `IDENTIFIER_SEPARATORS` fitting on the line, if one is in its second half,
    anywhere otherwise, e.g. 'physics:calib.\\' and '00456789._0001.data'.

    :returns: The lines, a single one if it fits in `width`.
    """
    room = max(width - len(IDENTIFIER_CONTINUATION), 1)
    lines = []
    while len(identifier) > width:
        cut = max(identifier.rfind(separator, 0, room) for separator in IDENTIFIER_SEPARATORS) + 1
        if cut <= room // 2:
            cut = room
        lines.append(identifier[:cut] + IDENTIFIER_CONTINUATION)
        identifier = identifier[cut:]
    lines.append(identifier)
    return lines


class Wrap(Enum):
    """How the lines of a table cell too long for its column are wrapped, see :func:`format_table`."""
    # at the spaces, as a text
    TEXT = 'text'
    # anywhere, preferably after a separator, see `break_identifier`
    IDENTIFIER = 'identifier'
    # not at all: the cells are rendered for the width of their column, see the `fitted` columns of `format_table`
    FITTED = 'fitted'


class Narrowing(NamedTuple):
    """How a column of a table narrows when the table is wider than the terminal, see :func:`format_table`."""
    wrap: Wrap
    # the narrowest it gets, though never so narrow that a word of its header would be broken
    min_width: int
    # the columns narrow by increasing order, the widest first among those of the same order
    order: int = 0
    # whether the column narrows to `min_width` at once rather than gradually, e.g. a date moving its time to a second line
    snap: bool = False
    # the widest its cells get, even if the table has room for more, e.g. so that a text keeps lines easy to read
    max_width: Optional[int] = None


# e.g. a description, wrapped first since it reads well over several lines, which it keeps short to be readable
TEXT_COLUMN = Narrowing(Wrap.TEXT, min_width=20, order=0, max_width=50)
# a role with its properties and description, one below the other, next to its permissions, see `PERMISSIONS_COLUMN`
ROLE_COLUMN = Narrowing(Wrap.TEXT, min_width=20, order=0, max_width=32)
# e.g. a DID pattern or an RSE name, broken only if wrapping the texts is not enough
IDENTIFIER_COLUMN = Narrowing(Wrap.IDENTIFIER, min_width=MIN_IDENTIFIER_WIDTH, order=1)
# the permissions of a role, see `format_permission_lists`, rendered for the width they are left
PERMISSIONS_COLUMN = Narrowing(Wrap.FITTED, min_width=1, order=1)
# the parameters of a permission, e.g. 'rw-'
PARAMETER_COLUMN = Narrowing(Wrap.TEXT, min_width=16, order=2)
# a date as rendered for a role assignment, '21-Oct-2026 07:58:54 UTC', its time going below it last
DATE_COLUMN = Narrowing(Wrap.TEXT, min_width=len('07:58:54 UTC'), order=3, snap=True)


def _wrap_cell(cell: str, width: int, wrap: Optional[Wrap]) -> list[str]:
    """The lines of a table cell, those longer than `width` wrapped as `wrap` tells, kept as they are if it is None."""
    lines = []
    for line in cell.split('\n'):
        if wrap in (None, Wrap.FITTED) or visible_length(line) <= width:
            lines.append(line)
            continue
        # a line too long loses its styles, which wrapping it could cut through
        line = ANSI_STYLE.sub('', line)
        if wrap == Wrap.TEXT:
            # a property, e.g. 'from:  21-Oct-2026 07:58:54 UTC', wraps under its value
            label = re.match(r'\S+:\s+', line)
            lines.extend(textwrap.wrap(line, width, subsequent_indent=' ' * len(label.group()) if label else ''))
        else:
            # at its spaces first, if any, e.g. those of 'admin (built-in)'
            lines.extend(part for word in textwrap.wrap(line, width, break_long_words=False) for part in break_identifier(word, width))
    return lines


def _narrow(widths: list[int], minimums: "Sequence[int]", narrowings: "Mapping[int, Narrowing]", excess: int) -> None:
    """Narrow the `widths` of the columns, in place, by `excess` in total if they can, see :class:`Narrowing`."""
    for order in sorted({narrowing.order for narrowing in narrowings.values()}):
        columns = [column for column, narrowing in narrowings.items() if narrowing.order == order and widths[column] > minimums[column]]
        while excess > 0 and columns:
            column = max(columns, key=lambda column: widths[column])
            step = widths[column] - minimums[column] if narrowings[column].snap else 1
            widths[column] -= step
            excess -= step
            if widths[column] == minimums[column]:
                columns.remove(column)


def format_table(
        sections: "Sequence[tuple[Sequence[str], Sequence[Sequence[str]]]]",
        narrowings: "Optional[Mapping[int, Narrowing]]" = None,
        fitted: "Optional[Mapping[int, Callable[[Optional[int]], Sequence[str]]]]" = None,
        width: Optional[int] = None,
) -> str:
    """
    Render tables having the same number of columns one below the other, as one table split into sections, fitting the terminal.

    Every section has its own header, the columns keeping the same width across all of them. A cell
    may span several lines. As long as the first cell of each row holds on one line, it shows where
    each row starts:

        +------+------------+---------------+
        | TYPE | IDENTIFIER | OPERATION(S)  |
        |------+------------+---------------|
        | did  | data:*     | rw-           |
        | did  | data:raw*  | r--           |
        +------+------------+---------------+

    Otherwise, the rows spanning several lines are separated by a dashed line, so that it is clear
    which lines belong together:

        +------------------+---------------+
        | ROLE             | PERMISSIONS   |
        |------------------+---------------|
        | moderator        | DID  *:*  r-- |
        | assignable: True |               |
        |- - - - - - - - - |- - - - - - - -|
        | user             | DID  *:*  rw- |
        | assignable: True |               |
        +------------------+---------------+

    If the table is wider than `width`, the columns given a :class:`Narrowing` narrow, their cells being wrapped.
    A cell may be styled, e.g. in bold, see `ANSI_STYLE`.

    :param sections: The sections, each as its headers and its rows.
    :param narrowings: How each column narrows, by index. A column without one keeps its width.
    :param fitted: The columns whose cells are rendered for the width they get rather than wrapped, by index, e.g. the
                   permissions of roles aligned across them, see :func:`format_permission_lists`. Each gives the
                   cells of its column, in the order of the rows of all the sections, given the width they should fit
                   in, None for their natural width; the cells given in `sections` for it are ignored.
    :param width: The width to fit in, that of the terminal by default. The table is wider if its columns cannot
                  narrow enough, e.g. to be shown in a pager scrolling horizontally, see :func:`echo_fitted`.
    :returns: The table, as lines joined by newlines.
    """
    narrowings = narrowings or {}
    fitted = fitted or {}
    width = width or terminal_width()
    columns = len(sections[0][0])
    sections = [(headers, [list(row) for row in rows]) for headers, rows in sections]
    all_rows = [row for _, rows in sections for row in rows]

    def _fill(widths: "Optional[Sequence[int]]") -> None:
        for column, render in fitted.items():
            for row, cell in zip(all_rows, render(widths[column] if widths is not None else None)):
                row[column] = cell

    _fill(None)
    widths, minimums = [], []
    for column in range(columns):
        cells = [str(cell) for headers, rows in sections for cell in [headers[column], *(row[column] for row in rows)]]
        widths.append(max(visible_length(line) for cell in cells for line in cell.split('\n')))
        narrowing = narrowings.get(column)
        header_words = [len(word) for headers, _ in sections for word in headers[column].split()]
        if narrowing is not None and narrowing.max_width is not None:
            widths[column] = min(widths[column], max([narrowing.max_width, *header_words]))
        minimums.append(widths[column] if narrowing is None else min(widths[column], max([narrowing.min_width, *header_words])))
    # each column is padded and separated by borders, e.g. '| a | b |'
    _narrow(widths, minimums, narrowings, sum(widths) + 3 * columns + 1 - width)

    if fitted:
        _fill(widths)
        # a fitted column takes the width its cells were rendered to, more than it was given if they could not narrow enough
        for column in fitted:
            header_width = max(len(headers[column]) for headers, _ in sections)
            widths[column] = max([header_width, *(visible_length(line) for row in all_rows for line in str(row[column]).split('\n'))])

    def _border(char: str = '-', joint: str = '+', edge: str = '+') -> str:
        return edge + joint.join(char * (column_width + 2) for column_width in widths) + edge

    def _dashes(column_width: int) -> str:
        return ('- ' * (column_width + 2))[:column_width + 2]

    def _pad(text: str, column_width: int) -> str:
        return text + ' ' * (column_width - visible_length(text))

    def _row(cells: "Sequence[Any]", header: bool = False) -> list[str]:
        cell_lines = [
            _wrap_cell(str(cell), column_width, Wrap.TEXT if header else narrowings[column].wrap if column in narrowings else None)
            for column, (cell, column_width) in enumerate(zip(cells, widths))
        ]
        return [
            '| ' + ' | '.join(_pad(lines[line_index] if line_index < len(lines) else '', column_width) for lines, column_width in zip(cell_lines, widths)) + ' |'
            for line_index in range(max(len(lines) for lines in cell_lines))
        ]

    # a first column filled on the first line of each row only already shows where each row starts
    first_wrap = narrowings[0].wrap if 0 in narrowings else None
    marked = all(len(lines) == 1 and lines[0] for lines in (_wrap_cell(str(row[0]), widths[0], first_wrap) for row in all_rows))

    lines = [_border()]
    for section_index, (headers, rows) in enumerate(sections):
        if section_index:
            lines.append(_border())
        lines.extend(_row(headers, header=True))
        lines.append(_border(joint='+', edge='|'))
        previous: list[str] = []
        for row in rows:
            row_lines = _row(row)
            if previous and not marked and (len(previous) > 1 or len(row_lines) > 1):
                lines.append('|' + '|'.join(_dashes(column_width) for column_width in widths) + '|')
            lines.extend(row_lines)
            previous = row_lines
    lines.append(_border())
    return '\n'.join(lines)


def echo_fitted(ctx: click.Context, output: str) -> None:
    """
    Print the output of a command, made to fit the terminal, see :func:`format_table`.

    If a line is still wider than the terminal, e.g. an identifier no column could narrow enough for, the output
    is shown in a pager scrolling horizontally, as the rich tables are, rather than letting the terminal wrap it.
    The styles of the output, see `ANSI_STYLE`, are dropped if it is not printed on a terminal.
    """
    too_wide = max(visible_length(line) for line in output.split('\n')) > terminal_width()
    if too_wide and ctx.obj.console.is_terminal and not ctx.obj.no_pager and shutil.which('less') is not None:
        # unlike the default pager, without -F, so that it does not quit with the lines chopped if they fit vertically
        pydoc.pipepager(output, 'less -RSXK')
    else:
        click.echo(output)


class OptionalDateTime(click.ParamType):
    """A date, or None when the given value is `NEVER` (case insensitive)."""

    name = "date"
    FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
    NEVER = "NEVER"

    def convert(self, value, param, ctx) -> Optional[datetime]:
        """Turn a command line value into a datetime, or None if it is `NEVER`."""
        if value is None or isinstance(value, datetime):
            return value
        if value.strip().upper() == self.NEVER:
            return None
        for date_format in self.FORMATS:
            try:
                return datetime.strptime(value.strip(), date_format)
            except ValueError:
                continue
        self.fail(f"{value!r} is not a valid date, expected one of {', '.join(self.FORMATS)} or {self.NEVER}", param, ctx)


class _LetterOperations(click.ParamType):
    """
    Operations given as letters, in any order and combination, e.g. 'rw' or 'wr' for read and write, or 'none' (case
    insensitive) for no operation, shown as dashes only by `role permission list`.

    The dashes of `role permission list` (e.g. 'rw-') only show the operations which are not granted, they are not
    accepted, nor are the names of the operations.
    """

    name = "operations"
    LETTERS: "Mapping[DidOperationType, str]" = OPERATION_LETTERS
    NONE = 'none'
    HELP = ""

    def convert(self, value, param, ctx) -> list[DidOperationType]:
        """Turn a command line value into the requested operations, deduplicated and in canonical order, possibly none."""
        if isinstance(value, list):
            return value
        if isinstance(value, str) and value.lower() == self.NONE:
            return []
        by_letter = {letter: operation for operation, letter in self.LETTERS.items()}
        if not value:
            self.fail(f"no operation given, expected {self.HELP}", param, ctx)
        if '-' in value:
            self.fail(f"{value!r}: give the operations as letters only, the dashes are only shown by `rucio role permission list`. Expected {self.HELP}", param, ctx)
        unknown = [char for char in value if char not in by_letter]
        if unknown:
            self.fail(self._unknown_message(value, unknown), param, ctx)
        requested = {by_letter[char] for char in value}
        return [operation for operation in self.LETTERS if operation in requested]

    def _unknown_message(self, value: str, unknown: "Sequence[str]") -> str:
        return f"{value!r} is not a valid operation, {', '.join(map(repr, dict.fromkeys(unknown)))} not being one. Expected {self.HELP}"


class RoleOperations(_LetterOperations):
    """
    The operations of a DID permission: letters among r, w and d, in any order and combination, e.g. 'r', 'rw', 'dw',
    'rwd', or 'none' for no operation, shown as '---' by `role permission list`.
    """

    HELP = "any combination of r(ead), w(rite) and d(elete), e.g. 'r', 'rw', 'wd' or 'rwd', or 'none' for no operation"


OPERATIONS = RoleOperations()

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


def _role_permissions(roles: "Sequence[tuple[str, bool, Iterable[Mapping[str, Any]]]]") -> "Callable[[Optional[int]], list[str]]":
    """
    The permissions of each role, as the PERMISSIONS column of a `--detail` table, aligned with each other, see
    :func:`format_permission_lists`.

    A reserved role has no permissions, so its tag is explained instead.

    :param roles: The roles, as their name, whether they are reserved, and their permissions as listed by the server.
    :returns: Gives the permissions, in the order of `roles`, given the width they should fit in, see `format_table`.
    """
    def _permissions(width: Optional[int]) -> list[str]:
        cells = iter(format_permission_lists([permissions for _, reserved, permissions in roles if not reserved], width=width))
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
    permissions = _role_permissions([
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
@click.option("--detail", is_flag=True, help="With -a or --me: also show the permissions of each role.")
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
    permissions = _role_permissions([(entry['role'], bool(entry.get('reserved')), permissions_by_role.get(entry['role'], [])) for entry in rbac['roles']])
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
@click.option("--detail", is_flag=True, help="Expand wildcard scope patterns into their scopes.")
@click.pass_context
def permission_list(ctx: click.Context, role_name: str, detail: bool) -> None:
    """List the permissions of ROLE_NAME."""
    lines = permission_lines(ctx.obj.client.list_role_permissions(role_name))

    # only fetch the (potentially large) list of every scope if a pattern actually needs expanding
    needs_scopes = detail and any(_is_scope_wildcard(target) for _, target, _ in lines)
    known_scopes = ctx.obj.client.list_scopes() if needs_scopes else []

    did_rows = []
    for permission_type, target, operations in lines:
        cell = target
        if detail and _is_scope_wildcard(target):
            cell = format_tree(target, _matching_scopes(target, known_scopes), placeholder="(no scope currently matches)")
        did_rows.append([permission_type, cell, operations])

    sections = [(["TYPE", "IDENTIFIER", "OPERATION(S)"], did_rows)] if did_rows else []
    if not sections:
        click.echo(f"No permission associated with role '{role_name}'.")
        return
    output = [_fill(f"Permissions associated with role '{role_name}':"), format_table(sections, {1: IDENTIFIER_COLUMN, 2: PARAMETER_COLUMN})]
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


def _echo_completed_operations(given: str, stored: str, target: str) -> None:
    """Tell the operations stored when the server completed those given with the ones they include, e.g. 'w' with 'r'."""
    if stored != given:
        added = [letter for letter in stored if letter != '-' and letter not in given]
        highest = [letter for letter in given if letter != '-'][-1]
        click.echo(f"{highest} implies {' and '.join(added)}: stored {stored} on {target}.")


@permission.group("did")
def permission_did() -> None:
    """Manage the operations a role grants on DIDs.

    \b
    r  see and read the DIDs, their data and metadata
    w  r, and create DIDs, add content, manage your own DIDs
    d  rw, and alter and delete existing DIDs
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
                 nothing on these DIDs, i.e. hide them from a wider pattern. w also
                 grants r, and d also grants w and r: 'w' is stored as 'rw-'."""
    did_pattern = _normalize_did_pattern(did_pattern)
    new = format_operations(op.value for op in operations)
    assigned = _assigned_did_operations(ctx, role_name)
    if not _confirm_did_pattern(ctx, did_pattern, "add"):
        click.echo(f"Skipped DID pattern '{did_pattern}', no permission was set on it.")
        return

    with _lock_hint(role_name):
        ctx.obj.client.add_role_permission(role_name, 'did', {'did_pattern': did_pattern, 'operations': [op.value for op in operations]}, force=force)

    # the server completes the operations with those they include, e.g. 'w' with 'r'
    given, new = new, _assigned_did_operations(ctx, role_name).get(did_pattern, new)
    _echo_completed_operations(given, new, did_pattern)
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
