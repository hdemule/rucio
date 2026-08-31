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

"""Add or delete a row in the `role_permission_map` table.

Usage:
    python role_permission_map.py --add scientist READ some_scope
    python role_permission_map.py --delete scientist READ some_scope
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_session  # noqa: E402

from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.common.types import InternalScope  # noqa: E402
from rucio.db.sqla import models  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--add', nargs=3, metavar=('ROLE', 'ACTION', 'SCOPE'), help='Role, action and scope to associate')
    group.add_argument('--delete', nargs=3, metavar=('ROLE', 'ACTION', 'SCOPE'), help='Role/action/scope association to remove')
    parser.add_argument('--vo', default=DEFAULT_VO, help=f'VO of the scope (default: {DEFAULT_VO})')
    args = parser.parse_args()

    with write_session() as session:
        if args.add:
            role, action, scope_name = args.add
            scope = InternalScope(scope_name, vo=args.vo)
            models.RolePermissionAssociation(role=role, action=action, scope=scope).save(flush=True, session=session)
            print(f'Linked role {role} -> {action} on {scope_name}')
        else:
            role, action, scope_name = args.delete
            scope = InternalScope(scope_name, vo=args.vo)
            mapping = session.get(models.RolePermissionAssociation, (role, scope, action))
            if mapping is None:
                print(f'No mapping found for role {role} -> {action} on {scope_name}')
                return
            mapping.delete(session=session)
            print(f'Removed role {role} -> {action} on {scope_name}')


if __name__ == '__main__':
    main()
