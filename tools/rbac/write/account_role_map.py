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

"""Add or delete a row in the `account_role_map` table.

Usage:
    python account_role_map.py --add alice scientist
    python account_role_map.py --delete alice scientist
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_session  # noqa: E402

from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.common.types import InternalAccount  # noqa: E402
from rucio.db.sqla import models  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--add', nargs=2, metavar=('ACCOUNT', 'ROLE'), help='Account and role to associate')
    group.add_argument('--delete', nargs=2, metavar=('ACCOUNT', 'ROLE'), help='Account/role association to remove')
    parser.add_argument('--vo', default=DEFAULT_VO, help=f'VO of the account (default: {DEFAULT_VO})')
    args = parser.parse_args()

    with write_session() as session:
        if args.add:
            account_name, role = args.add
            account = InternalAccount(account_name, vo=args.vo)
            models.AccountRoleAssociation(account=account, role=role).save(flush=True, session=session)
            print(f'Linked account {account_name} -> role {role}')
        else:
            account_name, role = args.delete
            account = InternalAccount(account_name, vo=args.vo)
            mapping = session.get(models.AccountRoleAssociation, (account, role))
            if mapping is None:
                print(f'No mapping found for account {account_name} -> role {role}')
                return
            mapping.delete(session=session)
            print(f'Removed account {account_name} -> role {role}')


if __name__ == '__main__':
    main()
