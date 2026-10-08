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
from rucio.common.utils import extract_scope, setup_logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence


SUCCESS = 0
FAILURE = 1


# Client-side representation of the operations a role permission can grant.
class RoleOperationType(Enum):
    READ = 'read'
    WRITE = 'write'
    DELETE = 'delete'


# The letter shown for each operation, in the order the operations are rendered.
OPERATION_LETTERS: dict[RoleOperationType, str] = {
    RoleOperationType.READ: 'r',
    RoleOperationType.WRITE: 'w',
    RoleOperationType.DELETE: 'd',
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


def format_tree(root: str, branches: "Sequence[str]", placeholder: str) -> str:
    """
    Render a node and its branches as a tree, to be used as a single (multi-line) table cell.

    Keeping the whole tree in one cell makes it start right below `root`, even if another column
    of the same row wraps over several lines, and keeps the indentation of the branches, which
    tabulate would strip from single-line cells.

    :param root: The first line of the tree, e.g. a role name or a scope pattern.
    :param branches: One line per branch, listed under `root` in the given order.
    :param placeholder: The line listed under `root` if there is no branch.
    :returns: The lines of the tree, joined by newlines.
    """
    if not branches:
        return '\n'.join([root, f"{TREE_PLACEHOLDER_INDENT}{placeholder}"])

    lines = [root]
    for index, branch in enumerate(branches):
        prefix = TREE_LAST_BRANCH if index == len(branches) - 1 else TREE_BRANCH
        lines.append(f"{prefix}{branch}")
    return '\n'.join(lines)


def format_permission_tree(role: str, permissions: "Iterable[Mapping[str, str]]") -> str:
    """
    Render a role and its permissions as a tree, see :func:`format_tree`.

    Each scope pattern is one branch, showing its operations as in :func:`format_operations`.

    :param role: The name of the role, the root of the tree.
    :param permissions: The permissions of the role, each with an 'operation' and a 'scope_pattern'.
    :returns: The tree, to be used as a single table cell.
    """
    ops_by_scope_pattern: dict[str, set[str]] = {}
    for permission in permissions:
        ops_by_scope_pattern.setdefault(permission['scope_pattern'], set()).add(permission['operation'])

    branches = [
        f"{format_operations(operations)}  {scope_pattern}"
        for scope_pattern, operations in sorted(ops_by_scope_pattern.items())
    ]
    return format_tree(role, branches, placeholder="(no permission assigned)")


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

    def convert(self, value, param, ctx) -> list[RoleOperationType]:
        """Turn a command line value into the requested operations, deduplicated and in canonical order."""
        if isinstance(value, list):
            return value
        by_letter = {letter: operation for operation, letter in OPERATION_LETTERS.items()}
        by_name = {operation.value: operation for operation in RoleOperationType}

        requested: set[RoleOperationType] = set()
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
