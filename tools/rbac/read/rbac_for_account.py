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

"""Show all RBAC information (roles + their permissions) for a given account."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import print_table, read_session  # noqa: E402

from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.common.types import InternalAccount  # noqa: E402
from rucio.db.sqla import models  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('account', help='Account name, e.g. alice')
    parser.add_argument('--vo', default=DEFAULT_VO, help=f'VO of the account (default: {DEFAULT_VO})')
    args = parser.parse_args()

    account = InternalAccount(args.account, vo=args.vo)

    with read_session() as session:
        roles = [
            m.role for m in
            session.query(models.AccountRoleAssociation)
            .filter_by(account=account)
            .order_by(models.AccountRoleAssociation.role)
            .all()
        ]

        print(f'Roles for account {args.account}:')
        print_table([(role,) for role in roles], headers=['ROLE'])

        if not roles:
            return

        permissions = (
            session.query(models.RolePermissionAssociation)
            .filter(models.RolePermissionAssociation.role.in_(roles))
            .order_by(models.RolePermissionAssociation.role, models.RolePermissionAssociation.scope, models.RolePermissionAssociation.operation)
            .all()
        )

        print()
        print(f'Permissions granted via those roles for account {args.account}:')
        print_table(
            [(rp.role, rp.operation, str(rp.scope)) for rp in permissions],
            headers=['ROLE', 'OPERATION', 'SCOPE'],
        )


if __name__ == '__main__':
    main()
