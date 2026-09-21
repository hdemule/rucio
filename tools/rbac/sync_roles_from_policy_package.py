#!/usr/bin/env python3
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

"""Synchronise the roles of Rucio with the roles defined by the policy package.

The policy package is the source of truth: a role it defines is created or brought in line
with it, and a role it does not define is deleted, together with the permissions and the
account assignments of that role.

    python tools/rbac/sync_roles_from_policy_package.py --dry-run   # report the changes
    python tools/rbac/sync_roles_from_policy_package.py             # apply them

With --dry-run nothing is written, which is why the session is then opened for reading.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.core import role as role_core  # noqa: E402
from rucio.db.sqla.constants import DatabaseOperationType  # noqa: E402
from rucio.db.sqla.session import db_session  # noqa: E402


def sync_roles_from_policy_package(vo: str = DEFAULT_VO, dry_run: bool = False) -> None:
    """Open a database session and run the synchronisation through it."""
    if dry_run:
        with db_session(DatabaseOperationType.READ) as session:
            role_core.sync_roles_from_policy_package_dry_run(vo=vo, session=session)
        return

    with db_session(DatabaseOperationType.WRITE) as session:
        role_core.sync_roles_from_policy_package(vo=vo, session=session)


def main() -> None:
    """Entry point of the script."""
    parser = argparse.ArgumentParser(description='Synchronise the roles of Rucio with the roles defined by the policy package.')
    parser.add_argument('--vo', default=DEFAULT_VO, help='the VO whose policy package defines the roles (default: %(default)s)')
    parser.add_argument('--dry-run', action='store_true', help='report the changes instead of applying them')
    args = parser.parse_args()

    sync_roles_from_policy_package(vo=args.vo, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
