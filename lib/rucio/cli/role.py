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
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple, Optional, Union

import click

from rucio.common.constants import ROLE_QUOTA_NOCAP
from rucio.common.exception import AccessDenied, AccountNotFound, InvalidRSEExpression, RoleAssignmentDisabled, RoleInUse, RoleLocked, RolePermissionNotFound, RSENotFound
from rucio.common.utils import get_bytes_value_from_string, str_to_date

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Generator, Iterable, Mapping, Sequence


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


# The letter shown for each operation a metadata permission can grant, in the order they are rendered: reading a key,
# and writing it, i.e. adding, modifying or deleting it. Deleting a DID is not an operation on its metadata.
METADATA_OPERATION_LETTERS: dict[DidOperationType, str] = {
    DidOperationType.READ: 'r',
    DidOperationType.WRITE: 'w',
}

# The keys of a metadata permission as listed by the server: '*' for every key, None for no key, which only makes the
# matching DIDs visible.
METADATA_ALL_KEYS = '*'


def format_metadata_operations(operations: "Iterable[str]") -> str:
    """
    Render the operations a metadata permission grants compactly, e.g. 'rw' for read and write, 'r-' for read only,
    '--' for none.

    :param operations: The operation values that are granted, 'read' and/or 'write'.
    """
    granted = set(operations)
    return ''.join(letter if operation.value in granted else '-' for operation, letter in METADATA_OPERATION_LETTERS.items())


def describe_metadata_keys(keys: "Iterable[Optional[str]]") -> str:
    """
    Name the keys of metadata permissions, e.g. 'datatype, quality', 'every key' for '*' and 'no key' for None.

    :param keys: The keys, as listed by the server.
    """
    keys = set(keys)
    names = (['no key'] if None in keys else []) + (['every key'] if METADATA_ALL_KEYS in keys else [])
    return ', '.join(names + sorted(key for key in keys if key not in (None, METADATA_ALL_KEYS)))


def metadata_key_label(key: "Optional[str]") -> str:
    """Name one key of a metadata permission as listed by the server, e.g. 'quality', '(every key)' for '*' and '(no key)' for None."""
    if key is None:
        return '(no key)'
    return '(every key)' if key == METADATA_ALL_KEYS else key


def format_metadata_permissions(permissions: "Iterable[Mapping[str, Any]]") -> str:
    """
    Render the metadata permissions of a role on a DID pattern, one line per key: its operations and the key, e.g.

        rw  (every key)
        r-  project

    The permission on no key comes first, then the one on every key, then the keys in alphabetical order.

    :param permissions: The metadata permissions on the DID pattern, as listed by the server.
    """
    def order(permission: "Mapping[str, Any]") -> tuple[int, str]:
        key = permission['meta_key']
        return (0, '') if key is None else (1, '') if key == METADATA_ALL_KEYS else (2, key)

    return '\n'.join(f"{format_metadata_operations(permission['operations'])}  {metadata_key_label(permission['meta_key'])}"
                     for permission in sorted(permissions, key=order))


TREE_BRANCH = "|-- "
TREE_LAST_BRANCH = "`-- "
TREE_PLACEHOLDER_INDENT = "`-- "
# prefixes the lines of a multi-line branch other than the one it is attached by, see `format_tree`
TREE_TRUNK = "|   "
TREE_NO_TRUNK = "    "
# bracket the RSEs of a global limit in the permissions of a role, see `format_permission_lists`
TREE_BRACKET_OPEN = "| "
TREE_BRACKET_CLOSE = " |"
# the permissions of a role which has none, see `format_permission_lists`
NO_PERMISSION = "(no permission assigned)"


def format_tree(root: str, branches: "Sequence[str]", placeholder: str) -> str:
    """
    Render a node and its branches as a tree, to be used as a single (multi-line) table cell.

    Keeping the whole tree in one cell makes it start right below `root`, even if another column
    of the same row wraps over several lines, and keeps the indentation of the branches, which
    tabulate would strip from single-line cells.

    A branch may span several lines, e.g. one per RSE a global limit covers: it is attached to the
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


class SizeFormat(Enum):
    """How the sizes of the limits of a role, and the usage measured against them, are rendered."""
    # with a storage unit, e.g. '1.5 TB'
    COMPACT = 'compact'
    # to the byte, with grouped digits, e.g. '1,500,000,000,000 B'
    EXACT = 'exact'
    # to the byte, as a bare number for scripts, e.g. '1500000000000'
    RAW = 'raw'

    @classmethod
    def of(cls, human: bool, exact: bool = False) -> "SizeFormat":
        """The format matching `--robot` (`human` being False with it) and a request for sizes to the byte, e.g. `--detail`."""
        if not human:
            return cls.RAW
        return cls.EXACT if exact else cls.COMPACT


# The decimal storage units, as `sizefmt` names them.
SIZE_UNITS = ('B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB')


def _compact_size(bytes_: float, decimals: int) -> tuple[str, str]:
    """
    Render a size with the largest decimal unit it reaches, without trailing zeros, e.g. ('1.5', 'TB').

    :param bytes_: The size, in bytes.
    :param decimals: The decimals kept at most, the size being rounded to them.
    :returns: The number and its unit, apart so that two sizes in the same unit can share it.
    """
    value = float(bytes_)
    # the unit is chosen once rounded, so that 999.96 kB reads as 1 MB rather than 1000 kB
    for unit in SIZE_UNITS:
        if abs(round(value, decimals)) < 1000 or unit == SIZE_UNITS[-1]:
            break
        value /= 1000
    number = f"{value:.{decimals}f}"
    return (number.rstrip('0').rstrip('.') if '.' in number else number), unit


def format_size(bytes_: int, sizes: SizeFormat = SizeFormat.COMPACT) -> str:
    """Render a size in bytes, see :class:`SizeFormat`, e.g. '1.234 TB', '1,234,000,000,000 B' or '1234000000000'."""
    if sizes == SizeFormat.RAW:
        return str(bytes_)
    if sizes == SizeFormat.EXACT:
        return f"{bytes_:,} B"
    return ' '.join(_compact_size(bytes_, decimals=3))


def format_quota(bytes_: int, sizes: SizeFormat = SizeFormat.COMPACT) -> str:
    """Render a limit of a role, e.g. '100 GB' or '1.5 TB', 'no cap' if it is `ROLE_QUOTA_NOCAP`."""
    if bytes_ == ROLE_QUOTA_NOCAP:
        return "no cap"
    return format_size(bytes_, sizes)


def _format_percentage(used: int, limit: int, decimals: int) -> str:
    """
    Render the share of a (non-zero) limit which is used, rounded to `decimals`.

    The rounding never hides that a limit is used, nor makes it look reached when it is not: a usage
    rounding to 0 reads as e.g. '<1%', one rounding to 100 while still below the limit as e.g. '>99%'.
    A usage beyond the limit reads as '>100%': it is not an error, the limit of a role being only one of
    those an account may write by, the role leaving the most space being taken.
    """
    if used > limit:
        return ">100%"
    step = 10 ** -decimals
    percentage = round(100 * used / limit, decimals)
    if used and percentage == 0:
        return f"<{step:.{decimals}f}%"
    if used < limit and percentage >= 100:
        return f">{100 - step:.{decimals}f}%"
    return f"{percentage:.{decimals}f}%"


def format_quota_usage(used: int, limit: int, sizes: SizeFormat = SizeFormat.COMPACT) -> str:
    """
    Render a limit of a role together with the usage of an account measured against it.

    The usage and the limit share their unit when they have the same. The share of the limit used is
    rounded to the percent in the compact format, to a tenth of a percent otherwise:

        1.4/10 GB (14% used)
        950 MB/10 GB (10% used)
        1,395,864,371/10,000,000,000 B (14.0% used)
        12/10 GB (>100% used)
        3.2 TB/no cap
        0/0 B (full)

    :param used: The bytes used, on the RSE of a local limit or summed over the RSEs of a global one.
    :param limit: The limit, `ROLE_QUOTA_NOCAP` for no cap.
    :param sizes: How the sizes are rendered.
    """
    if sizes == SizeFormat.COMPACT:
        # the usage is only indicative, a tenth of its unit is enough
        used_number, used_unit = _compact_size(used, decimals=1)
        # nothing used reads the same in any unit
        shares_unit = not used or (limit != ROLE_QUOTA_NOCAP and _compact_size(limit, decimals=3)[1] == used_unit)
        used_text = used_number if shares_unit else f"{used_number} {used_unit}"
    else:
        # the exact sizes always share their unit, if any
        used_text = format_size(used, sizes).removesuffix(' B')

    usage = f"{used_text}/{format_quota(limit, sizes)}"
    if limit == ROLE_QUOTA_NOCAP:
        return usage
    if limit == 0:
        return f"{usage} (full)"
    return f"{usage} ({_format_percentage(used, limit, decimals=0 if sizes == SizeFormat.COMPACT else 1)} used)"


# The localities of the limits of a role, in the order they are rendered.
LIMIT_LOCALITIES = ('local', 'global')


def format_limits(
        permission: "Mapping[str, Any]",
        sizes: SizeFormat = SizeFormat.COMPACT,
        used: "Optional[Callable[[str], int]]" = None,
) -> str:
    """
    Render the limits of a role on a target, as listed by the server, e.g. 'local: 10 TB' or 'global: no cap'.

    :param permission: The limit permission, as listed by the server.
    :param sizes: How the sizes are rendered.
    :param used: Gives the bytes an account uses, summed over the RSEs an RSE expression currently matches. With it,
                 each limit is rendered with the usage measured against it, e.g. 'local: 1.4/10 GB (14% used)', see
                 :func:`format_quota_usage`.
    """
    return ', '.join(
        f"{locality}: "
        + (format_quota(permission[locality], sizes) if used is None else format_quota_usage(used(permission['rse_expression']), permission[locality], sizes))
        for locality in LIMIT_LOCALITIES if locality in permission
    )


def permission_lines(
        permissions: "Iterable[Mapping[str, Any]]",
        sizes: SizeFormat = SizeFormat.COMPACT,
        used: "Optional[Callable[[str], int]]" = None,
) -> list[tuple[str, str, str, str]]:
    """
    Gather the permissions of a role into one line per type and target, sorted by type then target.

    :param permissions: The permissions of the role, as listed by the server.
    :param sizes: How the sizes of the limits are rendered.
    :param used: Gives the bytes an account uses on the RSEs of an RSE expression, to render each limit with the usage
                 measured against it, see :func:`format_limits`.
    :returns: The lines, as (type, target, operations, limits): the operations granted on a DID pattern, e.g. 'rw-'
              (see :func:`format_operations`), those granted on the metadata keys of a DID pattern, one key per line
              (see :func:`format_metadata_permissions`), and the limits on an RSE expression (see
              :func:`format_limits`), '' where they do not apply. A permission of a type this client does not know is
              left out.
    """
    ops_by_did_pattern: dict[str, list[str]] = {}
    metadata_by_did_pattern: dict[str, list["Mapping[str, Any]"]] = {}
    limits: list["Mapping[str, Any]"] = []
    for permission in permissions:
        if permission.get('type') == 'did':
            ops_by_did_pattern[permission['did_pattern']] = permission['operations']
        elif permission.get('type') == 'metadata':
            metadata_by_did_pattern.setdefault(permission['did_pattern'], []).append(permission)
        elif permission.get('type') == 'limit':
            limits.append(permission)

    lines = [('did', did_pattern, format_operations(ops), '') for did_pattern, ops in sorted(ops_by_did_pattern.items())]
    lines.extend(('metadata', did_pattern, format_metadata_permissions(metadata), '') for did_pattern, metadata in sorted(metadata_by_did_pattern.items()))
    lines.extend(('limit', limit['rse_expression'], '', format_limits(limit, sizes, used)) for limit in sorted(limits, key=lambda limit: limit['rse_expression']))
    return lines


def format_permission_lists(
        roles: "Sequence[tuple[Iterable[Mapping[str, Any]], Optional[Callable[[str], int]]]]",
        rse_names: "Optional[Callable[[str], Sequence[str]]]" = None,
        sizes: SizeFormat = SizeFormat.COMPACT,
        width: Optional[int] = None,
) -> list[str]:
    """
    Render the permissions of several roles, each to be used as a single table cell.

    Each line of :func:`permission_lines` is one entry, made of the same columns whatever its type,
    aligned across the entries of all the roles: its TYPE, its identifier and its parameters, i.e. the
    operations on a DID pattern, those on the metadata keys of a DID pattern, one key per line, or the
    limit on an RSE expression. A global limit on an expression matching several RSEs lists them one per
    line, bracketed in the identifier column, its limit on the middle one:

        DID        physics:*  r--
        METADATA   physics:*  rw  (every key)
                              r-  project
        LIMIT      MOCK       local: 1 MB
                 | MOCK2   |
        LIMIT    | MOCK3   |- global: 100 kB
                 | MOCK4   |

    :param roles: The roles, as their permissions as listed by the server, and what gives the bytes an account uses on
                  the RSEs of an RSE expression, to render each limit with the usage measured against it (see
                  :func:`format_limits`), None to only render the limits, e.g. if the account does not hold the role.
    :param rse_names: Gives the names of the RSEs an RSE expression currently matches. Without it, every
                      limit holds on one line, with its RSE expression.
    :param sizes: How the sizes of the limits are rendered.
    :param width: The width the lines should fit in, None for no limit. The identifier column narrows to it, down to
                  `MIN_IDENTIFIER_WIDTH`, each identifier too long for it being broken over several lines, see
                  :func:`break_identifier`.
    :returns: The permissions of each role, in the order of `roles`, their lines joined by newlines.
    """
    # each entry of each role as (type, identifier, parameters), the identifier being the RSEs of a global limit if it covers several
    entries_by_role: list[list[tuple[str, Union[str, list[str]], str]]] = []
    for permissions, used in roles:
        entries: list[tuple[str, Union[str, list[str]], str]] = []
        for permission_type, target, operations, limits in permission_lines(permissions, sizes, used):
            if permission_type != 'limit':
                entries.append((permission_type.upper(), target, operations))
                continue
            rses = list(rse_names(target)) if rse_names is not None else [target]
            if not rses:
                entries.append((permission_type.upper(), target, f"{limits} (no RSE currently matches)"))
            elif rses == [target]:
                entries.append((permission_type.upper(), target, limits))
            else:
                entries.append((permission_type.upper(), rses, limits))
        entries_by_role.append(entries)

    all_entries = [entry for entries in entries_by_role for entry in entries]
    if not all_entries:
        return [NO_PERMISSION for _ in roles]

    # the bracket of a list of RSEs opens in the gap before the identifier column, so that the RSEs line up
    # with the other identifiers, and closes with '|-' in the gap before the parameter column
    type_width = max(len(permission_type) for permission_type, _, _ in all_entries) + len(TREE_BRACKET_OPEN) + 1
    id_width = max(
        len(identifier) + 2 if isinstance(identifier, str) else max(len(rse) for rse in identifier) + len(TREE_BRACKET_CLOSE) + 2
        for _, identifier, _ in all_entries
    )
    if width is not None:
        parameters_width = max(len(line) for _, _, parameters in all_entries for line in parameters.split('\n'))
        id_width = max(min(id_width, width - type_width - parameters_width), MIN_IDENTIFIER_WIDTH + len(TREE_BRACKET_CLOSE) + 2)
    rse_width = id_width - len(TREE_BRACKET_CLOSE) - 2

    cells = []
    for entries in entries_by_role:
        lines = []
        for permission_type, identifier, parameters in entries:
            if isinstance(identifier, str):
                identifier_lines = break_identifier(identifier, id_width - 2)
                parameter_lines = parameters.split('\n')
                lines.extend(
                    f"{(permission_type if index == 0 else '').ljust(type_width)}"
                    f"{(identifier_lines[index] if index < len(identifier_lines) else '').ljust(id_width)}"
                    f"{parameter_lines[index] if index < len(parameter_lines) else ''}".rstrip()
                    for index in range(max(len(identifier_lines), len(parameter_lines)))
                )
                continue
            rse_lines = [line for rse in identifier for line in break_identifier(rse, rse_width)]
            anchor = (len(rse_lines) - 1) // 2
            lines.extend(
                ((permission_type if index == anchor else '').ljust(type_width - len(TREE_BRACKET_OPEN))
                 + f"{TREE_BRACKET_OPEN}{rse.ljust(rse_width)}{TREE_BRACKET_CLOSE}"
                 + (f"- {parameters}" if index == anchor else '')).rstrip()
                for index, rse in enumerate(rse_lines)
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
# the parameters of a permission, e.g. 'local: 0/10 MB (0% used)'
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

        +--------+------------+---------------+
        | TYPE   | IDENTIFIER | LIMIT         |
        |--------+------------+---------------|
        | limit  | MOCK1      | global: 10 MB |
        |        | MOCK2      |               |
        | limit  | MOCK3      | local: 100 kB |
        +--------+------------+---------------+

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


class QuotaSize(click.ParamType):
    """
    A limit, in bytes, or `ROLE_QUOTA_NOCAP` when the given value is `NOCAP` (case insensitive).

    Accepted forms: a number of bytes ('10000'), or a number with a decimal storage unit among
    B, KB, MB, GB, TB and PB ('100GB', '10TB'), case insensitive. 'infinity' and 'inf' are
    accepted for `NOCAP` too, as `rucio account limit add` does.
    """

    name = "size"
    NOCAP = "NOCAP"
    NOCAP_ALIASES = ("NOCAP", "INFINITY", "INF")

    def convert(self, value, param, ctx) -> int:
        """Turn a command line value into a number of bytes, or `ROLE_QUOTA_NOCAP` if it is `NOCAP`."""
        if isinstance(value, int):
            return value
        value = value.strip()
        if value.upper() in self.NOCAP_ALIASES:
            return ROLE_QUOTA_NOCAP
        if value.isdigit():
            return int(value)
        bytes_ = get_bytes_value_from_string(value)
        # False for a value which cannot be parsed, but 0 is a valid limit
        if bytes_ is False:
            self.fail(f"{value!r} is not a valid size, expected a number of bytes (e.g. '10000'), one with a unit (e.g. '100GB', '10TB') or {self.NOCAP} (also 'infinity')", param, ctx)
        return int(bytes_)


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


class MetadataOperations(_LetterOperations):
    """
    The operations of a metadata permission: letters among r and w, in any order and combination, e.g. 'r', 'w', 'rw'
    or 'wr', or 'none' (case insensitive) for no operation, shown as '--' by `role permission list`.
    """

    LETTERS = METADATA_OPERATION_LETTERS
    HELP = "any combination of r(ead) and w(rite), e.g. 'r', 'w' or 'rw', or 'none' for no operation"

    def _unknown_message(self, value: str, unknown: "Sequence[str]") -> str:
        if set(unknown) == {OPERATION_LETTERS[DidOperationType.DELETE]}:
            return f"{value!r}: a metadata permission has no d(elete) operation, w(rite) also deletes a key. Expected {self.HELP}"
        return super()._unknown_message(value, unknown)


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
    w  r, and add, modify or delete the key
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
                 w also grants r: 'w' is stored as 'rw'.
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

    # the server completes the operations with those they include, 'w' with 'r'
    given = format_metadata_operations(op.value for op in operations)
    new = _assigned_metadata_operations(ctx, role_name, did_pattern).get(meta_keys[0] if meta_keys else None, given)
    _echo_completed_operations(given, new, f"{describe_metadata_keys(meta_keys or [None])} of {did_pattern}")
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
