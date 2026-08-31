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

"""Shared helpers for the RBAC read/write scripts in tools/rbac/{read,write}."""

import os
import sys
from contextlib import contextmanager
from typing import TYPE_CHECKING

# Ensure `rucio` is importable regardless of the caller's cwd.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tabulate import tabulate  # noqa: E402

from rucio.db.sqla.constants import DatabaseOperationType  # noqa: E402
from rucio.db.sqla.session import db_session  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from sqlalchemy.orm import Session


@contextmanager
def read_session() -> "Iterator[Session]":
    """Yield a session suitable for SELECT-only operations."""
    with db_session(DatabaseOperationType.READ) as session:
        yield session


@contextmanager
def write_session() -> "Iterator[Session]":
    """Yield a session that auto-commits on success, rolls back on error."""
    with db_session(DatabaseOperationType.WRITE) as session:
        yield session


def print_table(rows: "Sequence[Sequence[object]]", headers: "Sequence[str]") -> None:
    """Pretty-print rows, or a friendly message when there are none."""
    if not rows:
        print("(no rows)")
        return
    print(tabulate(rows, headers=headers, tablefmt='psql'))
