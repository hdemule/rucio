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

"""Report what synchronising the roles of an account with the ones of an IdP would do.

The roles an identity provider supplies are given on the command line, so that the
synchronisation can be tried out without an IdP at hand:

    python tools/rbac/sync_account_roles_from_idp.py alice data-scientist admin=2028-01-31

The core function is a dry run: it only reads the roles of the account and of the database,
and prints the changes it would apply. Nothing is written, which is why the session below is
opened for reading.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.core import role as role_core  # noqa: E402
from rucio.db.sqla.constants import DatabaseOperationType  # noqa: E402
from rucio.db.sqla.session import db_session  # noqa: E402


def sync_account_roles_from_idp(account: str, roles: dict, vo: str = DEFAULT_VO) -> None:
    """Open a database session and run the synchronisation through it."""
    print("Syncing account roles from IDP...")
    # once the synchronisation stops being a dry run, this has to become
    # DatabaseOperationType.WRITE, otherwise the session refuses to write
    with db_session(DatabaseOperationType.READ) as session:
        role_core.sync_account_roles_from_idp(account=account, roles=roles, vo=vo, session=session)


def main() -> None:
    """Entry point of the script."""
    parser = argparse.ArgumentParser(description='Report what synchronising the roles of an account with the ones of an IdP would do.')
    parser.add_argument('account', help='the account whose roles would be synchronised')
    parser.add_argument('roles', nargs='*', metavar='ROLE[=EXPIRES_AT]',
                        help="a role the IdP supplies, optionally with the date at which the assignment expires, e.g. 'admin=2028-01-31'")
    parser.add_argument('--vo', default=DEFAULT_VO, help='the VO the account belongs to (default: %(default)s)')
    args = parser.parse_args()

    # the roles of the IdP as a mapping of role name to expiry date, None meaning that the
    # assignment does not expire
    roles = {}
    for entry in args.roles:
        role, _, expires_at = entry.partition('=')
        roles[role] = expires_at or None

    sync_account_roles_from_idp(args.account, roles, vo=args.vo)


if __name__ == "__main__":
    main()
