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
from typing import TYPE_CHECKING, Any, Optional, Union

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
from rucio.common.utils import extract_scope, get_bytes_value_from_string, setup_logger, sizefmt

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence


SUCCESS = 0
FAILURE = 1


# Client-side representation of the operations a scope permission can grant.
class ScopeOperationType(Enum):
    READ = 'read'
    WRITE = 'write'
    DELETE = 'delete'


# The letter shown for each operation, in the order the operations are rendered.
OPERATION_LETTERS: dict[ScopeOperationType, str] = {
    ScopeOperationType.READ: 'r',
    ScopeOperationType.WRITE: 'w',
    ScopeOperationType.DELETE: 'd',
}


def format_operations(operations: "Iterable[str]") -> str:
    """
    Render the operations granted on a scope compactly, e.g. 'rw-' for read and write, 'r--' for read only.

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
# bracket the RSEs of a global limit in a permission tree, see `format_permission_tree`
TREE_BRACKET_OPEN = "| "
TREE_BRACKET_CLOSE = " |"


def format_tree(root: str, branches: "Sequence[str]", placeholder: str) -> str:
    """
    Render a node and its branches as a tree, to be used as a single (multi-line) table cell.

    Keeping the whole tree in one cell makes it start right below `root`, even if another column
    of the same row wraps over several lines, and keeps the indentation of the branches, which
    tabulate would strip from single-line cells.

    A branch may span several lines, e.g. one per RSE a global limit covers: it is attached to the
    tree by its middle line, the trunk running along the lines above it, and along those below it
    unless it is the last branch.

    :param root: The first line of the tree, e.g. a role name or a scope pattern.
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


def format_quota(bytes_: int, human: bool = True) -> str:
    """Render a limit of a role compactly, e.g. '100 GB' or '1.5 TB', 'no cap' if it is `ROLE_QUOTA_NOCAP`."""
    if bytes_ == ROLE_QUOTA_NOCAP:
        return "no cap"
    if not human:
        return sizefmt(bytes_, human)
    # sizefmt always shows three decimals, e.g. '100.000 GB', which a limit set as '100GB' does not need
    number, _, unit = sizefmt(bytes_, human).partition(' ')
    return f"{number.rstrip('0').rstrip('.')} {unit}" if '.' in number else f"{number} {unit}"


# The localities of the limits of a role, in the order they are rendered.
LIMIT_LOCALITIES = ('local', 'global')


def format_limits(permission: "Mapping[str, Any]", human: bool = True) -> str:
    """Render the limits of a role on a target, as listed by the server, e.g. 'local: 10 TB, global: no cap'."""
    return ', '.join(f"{locality}: {format_quota(permission[locality], human)}" for locality in LIMIT_LOCALITIES if locality in permission)


def permission_lines(permissions: "Iterable[Mapping[str, Any]]", human: bool = True) -> list[tuple[str, str, str, str]]:
    """
    Gather the permissions of a role into one line per type and target, sorted by type then target.

    :param permissions: The permissions of the role, as listed by the server.
    :param human: Render the limits with a storage unit rather than in bytes.
    :returns: The lines, as (type, target, operations, limits): the operations granted on a scope pattern, e.g. 'rw-'
              (see :func:`format_operations`), and the limits on an RSE expression (see :func:`format_limits`), '' where
              they do not apply. A permission of a type this client does not know is left out.
    """
    ops_by_scope_pattern: dict[str, set[str]] = {}
    limits: list["Mapping[str, Any]"] = []
    for permission in permissions:
        if permission.get('type') == 'scope':
            ops_by_scope_pattern.setdefault(permission['scope_pattern'], set()).add(permission['operation'])
        elif permission.get('type') == 'limit':
            limits.append(permission)

    lines = [('scope', scope_pattern, format_operations(ops), '') for scope_pattern, ops in sorted(ops_by_scope_pattern.items())]
    lines.extend(('limit', limit['rse_expression'], '', format_limits(limit, human)) for limit in sorted(limits, key=lambda limit: limit['rse_expression']))
    return lines


def format_permission_tree(
        role: str,
        permissions: "Iterable[Mapping[str, Any]]",
        rse_names: "Optional[Callable[[str], Sequence[str]]]" = None,
        human: bool = True,
) -> str:
    """
    Render a role and its permissions as a tree, see :func:`format_tree`.

    Each line of :func:`permission_lines` is one branch, made of the same columns whatever its type,
    aligned across the branches: its TYPE, its identifier and its parameters, i.e. the operations on a
    scope pattern or the limit on an RSE expression. A global limit on an expression matching several
    RSEs lists them one per line, bracketed in the identifier column, its limit on the middle one:

        rse-pro
        |-- SCOPE   *        r--
        |-- SCOPE   atlas    rw-
        |-- LIMIT   MOCK     local: 1 MB
        |         | MOCK2 |
        `-- LIMIT | MOCK3 |- global: 100 kB
                  | MOCK4 |

    :param role: The name of the role, the root of the tree.
    :param permissions: The permissions of the role, as listed by the server.
    :param rse_names: Gives the names of the RSEs an RSE expression currently matches. Without it, every
                      limit holds on one line, with its RSE expression.
    :param human: Render the limits with a storage unit rather than in bytes.
    :returns: The tree, to be used as a single table cell.
    """
    return format_permission_trees([(role, permissions)], rse_names, human)[0]


def format_permission_trees(
        roles: "Sequence[tuple[str, Iterable[Mapping[str, Any]]]]",
        rse_names: "Optional[Callable[[str], Sequence[str]]]" = None,
        human: bool = True,
) -> list[str]:
    """
    Render several roles and their permissions as trees, see :func:`format_permission_tree`.

    The columns of the branches are aligned across all the trees, so that the trees read as one when
    listed one below the other, e.g. in a table of roles.

    :param roles: The roles, as their name, the root of their tree, and their permissions as listed by the server.
    :param rse_names: Gives the names of the RSEs an RSE expression currently matches, see :func:`format_permission_tree`.
    :param human: Render the limits with a storage unit rather than in bytes.
    :returns: The trees, in the order of `roles`, each to be used as a single table cell.
    """
    # each branch of each role as (type, identifier, parameters), the identifier being the RSEs of a global limit if it covers several
    entries_by_role: list[list[tuple[str, Union[str, list[str]], str]]] = []
    for _, permissions in roles:
        entries: list[tuple[str, Union[str, list[str]], str]] = []
        for permission_type, target, operations, limits in permission_lines(permissions, human):
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
        return [format_tree(role, [], placeholder="(no permission assigned)") for role, _ in roles]

    # the bracket of a list of RSEs opens in the gap before the identifier column, so that the RSEs line up
    # with the other identifiers, and closes with '|- ' before the parameter column
    type_width = max(len(permission_type) for permission_type, _, _ in all_entries) + len(TREE_BRACKET_OPEN) + 1
    id_width = max(
        len(identifier) + 2 if isinstance(identifier, str) else max(len(rse) for rse in identifier) + len(TREE_BRACKET_CLOSE) + 2
        for _, identifier, _ in all_entries
    )
    rse_width = id_width - len(TREE_BRACKET_CLOSE) - 2

    trees = []
    for (role, _), entries in zip(roles, entries_by_role):
        branches = []
        for permission_type, identifier, parameters in entries:
            if isinstance(identifier, str):
                branches.append(f"{permission_type.ljust(type_width)}{identifier.ljust(id_width)}{parameters}".rstrip())
                continue
            anchor = (len(identifier) - 1) // 2
            branches.append('\n'.join(
                (permission_type if index == anchor else '').ljust(type_width - len(TREE_BRACKET_OPEN))
                + f"{TREE_BRACKET_OPEN}{rse.ljust(rse_width)}{TREE_BRACKET_CLOSE}"
                + (f"- {parameters}" if index == anchor else '')
                for index, rse in enumerate(identifier)
            ))
        trees.append(format_tree(role, branches, placeholder="(no permission assigned)"))
    return trees


def format_sections(sections: "Sequence[tuple[Sequence[str], Sequence[Sequence[str]]]]") -> str:
    """
    Render tables having the same number of columns one below the other, as one table split into sections.

    Every section has its own header, the columns keeping the same width across all of them. A cell
    may span several lines; the rows of a section are then separated by a dashed line, so that it is
    clear which lines belong together:

        +--------+------------+---------------+
        | TYPE   | IDENTIFIER | LIMIT         |
        |--------+------------+---------------|
        | limit  | MOCK1      | global: 10 MB |
        |        | MOCK2      |               |
        |- - - - |- - - - - - |- - - - - - - -|
        | limit  | MOCK3      | local: 100 kB |
        +--------+------------+---------------+

    :param sections: The sections, each as its headers and its rows.
    :returns: The table, as lines joined by newlines.
    """
    columns = len(sections[0][0])
    widths = [
        max(len(line) for headers, rows in sections for cell in [headers[column], *(row[column] for row in rows)] for line in str(cell).split('\n'))
        for column in range(columns)
    ]

    def _border(char: str = '-', joint: str = '+', edge: str = '+') -> str:
        return edge + joint.join(char * (width + 2) for width in widths) + edge

    def _dashes(width: int) -> str:
        return ('- ' * (width + 2))[:width + 2]

    def _row(cells: "Sequence[str]") -> list[str]:
        cell_lines = [str(cell).split('\n') for cell in cells]
        height = max(len(lines) for lines in cell_lines)
        return [
            '| ' + ' | '.join((lines[line_index] if line_index < len(lines) else '').ljust(width) for lines, width in zip(cell_lines, widths)) + ' |'
            for line_index in range(height)
        ]

    lines = [_border()]
    for section_index, (headers, rows) in enumerate(sections):
        if section_index:
            lines.append(_border())
        lines.extend(_row(headers))
        lines.append(_border(joint='+', edge='|'))
        for row_index, row in enumerate(rows):
            if row_index and any('\n' in str(cell) for cell in (*row, *rows[row_index - 1])):
                lines.append('|' + '|'.join(_dashes(width) for width in widths) + '|')
            lines.extend(_row(row))
    lines.append(_border())
    return '\n'.join(lines)


def wrap_table_column(
    rows: "Sequence[Sequence[Any]]",
    headers: "Sequence[str]",
    column: int,
    min_width: int = 24,
) -> list[list[Any]]:
    """
    Wrap a free-text column so that a tabulated table still fits the terminal.

    The other columns keep their natural width and whatever horizontal space is left over
    is given to `column`, so that long values (e.g. a role description) wrap instead of
    stretching the table far beyond the terminal. Line breaks already present in the text
    are kept, so paragraphs stay intact.

    :param rows: The rows that will be tabulated.
    :param headers: The column headers of the table.
    :param column: Index of the column to wrap.
    :param min_width: Lower bound, so a narrow terminal yields a tall table rather than one character per line.
    :returns: A new list of rows, with `column` wrapped.
    """
    natural_width = 0
    for index, header in enumerate(headers):
        if index == column:
            continue
        # a multi-line cell is as wide as its longest line
        natural_width += max([len(header)] + [len(line) for row in rows for line in str(row[index]).splitlines()])

    # every column is padded and separated by borders, e.g. '| a | b |' in the default 'psql' format
    borders = 3 * len(headers) + 1
    terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns
    width = max(min_width, terminal_width - natural_width - borders)

    wrapped_rows = []
    for row in rows:
        wrapped_row = list(row)
        lines = []
        for line in str(wrapped_row[column]).splitlines():
            # an empty line wraps to nothing, keep it so blank lines between paragraphs survive
            lines.extend(textwrap.wrap(line, width) or [''])
        wrapped_row[column] = '\n'.join(lines)
        wrapped_rows.append(wrapped_row)

    return wrapped_rows


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


class RoleOperations(click.ParamType):
    """
    One or more role operations, in any order and combination.

    Accepted forms, case insensitive:
      - letters among r, w and d, e.g. 'r', 'rw', 'dw', 'rwd';
      - the same letters with '-' placeholders, as shown by `role permission list`, e.g. 'rw-', 'r-d';
      - comma-separated operation names, e.g. 'read', 'read,delete'.
    """

    name = "operations"
    HELP = "any combination of r(ead), w(rite) and d(elete), e.g. 'r', 'rw', 'wd', 'rwd' or 'read,write'"

    def convert(self, value, param, ctx) -> list[ScopeOperationType]:
        """Turn a command line value into the requested operations, deduplicated and in canonical order."""
        if isinstance(value, list):
            return value
        by_letter = {letter: operation for operation, letter in OPERATION_LETTERS.items()}
        by_name = {operation.value: operation for operation in ScopeOperationType}

        requested: set[ScopeOperationType] = set()
        for token in value.lower().replace(' ', '').split(','):
            if token in by_name:
                requested.add(by_name[token])
            elif token and all(char in by_letter or char == '-' for char in token):
                requested.update(by_letter[char] for char in token if char != '-')
            else:
                self.fail(f"{token!r} is not a valid operation, expected {self.HELP}", param, ctx)

        if not requested:
            self.fail(f"{value!r} does not contain any operation, expected {self.HELP}", param, ctx)
        return [operation for operation in OPERATION_LETTERS if operation in requested]


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
