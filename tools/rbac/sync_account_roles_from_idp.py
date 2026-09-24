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

"""Synchronise the roles of an account with the ones of an IdP, or report what that would do.

The roles an identity provider supplies are given on the command line, so that the
synchronisation can be tried out without an IdP at hand:

    python tools/rbac/sync_account_roles_from_idp.py alice data-scientist admin=2028-01-31 --dry-run
    python tools/rbac/sync_account_roles_from_idp.py alice data-scientist admin=2028-01-31

With --dry-run the core function only reads the roles of the account and of the database, and
prints the changes it would apply. Without it, the changes are applied in a single transaction.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.core import role as role_core  # noqa: E402
from rucio.db.sqla.constants import DatabaseOperationType  # noqa: E402
from rucio.db.sqla.session import db_session  # noqa: E402


def sync_account_roles_from_idp_dry_run(account: str, roles: dict, vo: str = DEFAULT_VO) -> None:
    """Open a database session and run the synchronisation through it."""
    print("Syncing account roles from IDP...")
    # the dry run only reads, so its session is opened for reading
    with db_session(DatabaseOperationType.READ) as session:
        report = role_core.sync_account_roles_from_idp_dry_run(account=account, roles=roles, vo=vo, session=session)
    print("\n".join(report["messages"]))


def sync_account_roles_from_idp(account: str, roles: dict, vo: str = DEFAULT_VO) -> None:
    """Open a database session for writing and apply the synchronisation through it."""
    print("Syncing account roles from IDP...")
    with db_session(DatabaseOperationType.WRITE) as session:
        report = role_core.sync_account_roles_from_idp(account=account, roles=roles, vo=vo, session=session)
    print("\n".join(report["messages"]))


def main() -> None:
    """Entry point of the script."""
    parser = argparse.ArgumentParser(
        description='Synchronise the roles of an account with the ones of an IdP, or with --dry-run only report what that would do.'
    )
    parser.add_argument('account', help='the account whose roles would be synchronised')
    parser.add_argument('roles', nargs='*', metavar='ROLE[=EXPIRES_AT]',
                        help="a role the IdP supplies, optionally with the date at which the assignment expires. "
                        "Examples: one role without expiration => alice data-scientist; "
                        "multiple roles without expiration => alice data-scientist admin; "
                        "mixed expirations => alice data-scientist admin=2028-01-31 analyst")
    parser.add_argument('--vo', default=DEFAULT_VO, help='the VO the account belongs to (default: %(default)s)')
    parser.add_argument('--dry-run', action='store_true', help='do not write anything to the database, only report what would be done (default: %(default)s)')
    args = parser.parse_args()

    # the roles of the IdP as a mapping of role name to expiry date, None meaning that the
    # assignment does not expire
    roles = {}
    for entry in args.roles:
        role, _, expires_at = entry.partition('=')
        roles[role] = expires_at or None

    if args.dry_run:
        sync_account_roles_from_idp_dry_run(args.account, roles, vo=args.vo)
    else:
        sync_account_roles_from_idp(args.account, roles, vo=args.vo)


if __name__ == "__main__":
    main()
