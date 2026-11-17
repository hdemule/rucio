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

import errno
import json
import logging
import os
import pydoc
import re
import shutil
import signal
import subprocess  # noqa: S404 -- subprocess used for external commands
import sys
import textwrap
import traceback
from configparser import NoOptionError, NoSectionError
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Any, NamedTuple, Optional, Union

import click

from rucio.client.client import Client
from rucio.common.config import config_get
from rucio.common.constants import ROLE_QUOTA_NOCAP
from rucio.common.exception import (
    AccessDenied,
    CannotAuthenticate,
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    Duplicate,
    DuplicateContent,
    InputValidationError,
    InvalidRSEExpression,
    MissingDependency,
    RSENotFound,
    RucioException,
    RuleNotFound,
    ScopeNotFound,
    UnsupportedOperation,
)
from rucio.common.utils import extract_scope, get_bytes_value_from_string, setup_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence


SUCCESS = 0
FAILURE = 1


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


def exception_handler(function):
    verbosity = ("-v" in sys.argv) or ("--verbose" in sys.argv)
    logger = setup_logger(module_name=__name__, logger_name="user", verbose=verbosity)

    @wraps(function)
    def new_funct(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except click.exceptions.Exit as error:
            # Exit is evoked every time click ends a program without running anything
            # This error is raised when the help menu is called
            logger.debug("Exited click context")
            if ("-h" not in sys.argv) or ("--help" not in sys.argv):
                return error.exit_code
            return SUCCESS
        except click.MissingParameter as error:
            error.show()
            msg = f"{error}. Please check the command help (-h/--help)."
            logger.error(msg)
            return 2  # Always return an error 2 for an incorrect specification
        except (InputValidationError, click.exceptions.UsageError) as error:
            logger.error(error)
            logger.debug("This means that one you provided an invalid combination of parameters, or incorrect types. Please check the command help (-h/--help).")
            return FAILURE
        except NotImplementedError as error:
            logger.error(f"Cannot run that operation/command combination {error}")
            return FAILURE
        except DataIdentifierNotFound as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you provided is not known by Rucio.")
            return error.error_code
        except AccessDenied as error:
            logger.error(error)
            logger.debug("This error is a permission issue. You cannot run this command with your account.")
            return error.error_code
        except DataIdentifierAlreadyExists as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you try to add is already registered in Rucio.")
            return error.error_code
        except RSENotFound as error:
            logger.error(error)
            logger.debug("This means that the Rucio Storage Element you provided is not known by Rucio.")
            return error.error_code
        except InvalidRSEExpression as error:
            logger.error(error)
            logger.debug("This means the RSE expression you provided is not syntactically correct.")
            return error.error_code
        except DuplicateContent as error:
            logger.error(error)
            logger.debug("This means that the DID you want to attach is already in the target DID.")
            return error.error_code
        except Duplicate as error:
            logger.error(error)
            logger.debug("This means that you are trying to add something that already exists.")
            return error.error_code
        except TypeError as error:
            logger.error(error)
            logger.debug("This means the parameter you passed has a wrong type.")
            return FAILURE
        except RuleNotFound as error:
            logger.error(error)
            logger.debug("This means the rule you specified does not exist.")
            return error.error_code
        except UnsupportedOperation as error:
            logger.error(error)
            logger.debug("This means you cannot change the status of the DID.")
            return error.error_code
        except MissingDependency as error:
            logger.error(error)
            logger.debug("This means one dependency is missing.")
            return error.error_code
        except KeyError as error:
            if "x-rucio-auth-token" in str(error):
                used_account = None
                try:  # get the configured account from the configuration file
                    used_account = "%s (from rucio.cfg)" % config_get("client", "account")
                except Exception:
                    pass
                try:  # are we overriden by the environment?
                    used_account = "%s (from RUCIO_ACCOUNT)" % os.environ["RUCIO_ACCOUNT"]
                except Exception:
                    pass
                logger.error("Specified account %s does not have an associated identity." % used_account)

            else:
                logger.debug(traceback.format_exc())
                contact = config_get("policy", "support", raise_exception=False)
                support = ("Please follow up with all relevant information at: " + contact) if contact else ""
                logger.error("\nThe object is missing this property: %s\n" 'This should never happen. Please rerun the last command with the "-v" option to gather more information.\n' "%s" % (str(error), support))
            return FAILURE
        except RucioException as error:
            logger.error(error)
            return error.error_code
        except Exception as error:
            if isinstance(error, IOError) and getattr(error, "errno", None) == errno.EPIPE:
                # Ignore Broken Pipe
                # While in python3 we can directly catch 'BrokenPipeError', in python2 it doesn't exist.

                # Python flushes standard streams on exit; redirect remaining output
                # to devnull to avoid another BrokenPipeError at shutdown
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return SUCCESS
            logger.debug(traceback.format_exc())
            logger.error(error)
            contact = config_get("policy", "support", raise_exception=False)
            support = ("If it's a problem concerning your experiment or if you're unsure what to do, please follow up at: %s\n" % contact) if contact else ""
            contact = config_get("policy", "support_rucio", default="https://github.com/rucio/rucio/issues")
            support += "If you're sure there is a problem with Rucio itself, please follow up at: " + contact
            logger.error("\nRucio exited with an unexpected/unknown error.\n" 'Please rerun the last command with the "-v" option to gather more information.\n' "%s" % support)
            return FAILURE

    return new_funct


def get_client(args, logger):
    """
    Returns a new client object.
    """
    if hasattr(args, "config") and (args.config is not None):
        os.environ["RUCIO_CONFIG"] = args.config

    if logger is None:
        logger = setup_logger(module_name=__name__, logger_name="user", verbose=args.verbose)

    if not args.auth_strategy:
        if "RUCIO_AUTH_TYPE" in os.environ:
            auth_type = os.environ["RUCIO_AUTH_TYPE"].lower()
        else:
            try:
                auth_type = config_get("client", "auth_type").lower()
            except (NoOptionError, NoSectionError):
                logger.error("Cannot get AUTH_TYPE")
                sys.exit(1)
    else:
        auth_type = args.auth_strategy.lower()

    if auth_type == "userpass" and args.username is not None and args.password is not None:
        creds = {"username": args.username, "password": args.password}
    elif auth_type == "oidc":
        if args.oidc_issuer:
            args.oidc_issuer = args.oidc_issuer.lower()
        creds = {
            "oidc_scope": args.oidc_scope,
            "oidc_audience": args.oidc_audience,
            "oidc_polling": args.oidc_polling,
            "oidc_refresh_lifetime": args.oidc_refresh_lifetime,
            "oidc_issuer": args.oidc_issuer
        }
    elif auth_type == "x509":
        creds = {"client_cert": args.certificate, "client_key": args.client_key}
    else:
        creds = None

    try:
        client = Client(rucio_host=args.host, auth_host=args.auth_host, account=args.issuer, auth_type=auth_type, creds=creds, ca_cert=args.ca_certificate, timeout=args.timeout, user_agent=args.user_agent, vo=args.vo, logger=logger)
    except CannotAuthenticate as error:
        logger.error(error)
        if "alert certificate expired" in str(error):
            logger.error("The server certificate expired.")
        elif auth_type.lower() == "x509_proxy":
            logger.error("Please verify that your proxy is still valid and renew it if needed.")
        sys.exit(1)
    return client


def signal_handler(sig, frame, logger):
    logger.warning("You pressed Ctrl+C! Exiting gracefully")
    child_processes = subprocess.Popen("ps -o pid --ppid %s --noheaders" % os.getpid(), shell=True, stdout=subprocess.PIPE)
    child_processes = child_processes.stdout.read()  # type: ignore
    for pid in child_processes.split("\n")[:-1]:  # type: ignore
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:
            print("Cannot kill child process")
    sys.exit(1)


def setup_gfal2_logger():
    gfal2_logger = logging.getLogger("gfal2")
    gfal2_logger.setLevel(logging.CRITICAL)
    gfal2_logger.addHandler(logging.StreamHandler())


class Arguments(dict):
    """dot.notation access to dictionary attributes"""

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class JSONType(click.ParamType):
    name = "json"

    def convert(
            self,
            value: Union[str, None],
            param: "Optional[click.Parameter]",
            ctx: "Optional[click.Context]",
    ) -> Optional[dict]:
        if value is None:
            return None

        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON: {e}", param, ctx)


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


def get_scope(did: str, client: Client) -> tuple[str, str]:
    try:
        scope, name = extract_scope(did)
        return scope, name
    except TypeError:
        known_scopes = client.list_scopes()
        if not len(list(known_scopes)):
            raise ScopeNotFound
        if isinstance(known_scopes, dict):
            scopes = known_scopes.get('scope')  # type: ignore - does not accept 'scope' as a Literal['scope']
            scope, name = extract_scope(did, scopes)
        elif isinstance(known_scopes, list):
            scope, name = extract_scope(did, known_scopes)  # type: ignore - Handled by the isinstance
        else:
            raise ScopeNotFound

        return scope, name
