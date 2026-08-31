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

"""Add or delete a row in the `roles` table.

Usage:
    python roles.py --add scientist
    python roles.py --delete scientist
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_session  # noqa: E402

from rucio.db.sqla import models  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--add', metavar='ROLE', help='Role name to create')
    group.add_argument('--delete', metavar='ROLE', help='Role name to remove')
    args = parser.parse_args()

    with write_session() as session:
        if args.add:
            models.Roles(role=args.add).save(flush=True, session=session)
            print(f'Added role: {args.add}')
        else:
            role = session.get(models.Roles, args.delete)
            if role is None:
                print(f'Role not found: {args.delete}')
                return
            role.delete(session=session)
            print(f'Deleted role: {args.delete}')


if __name__ == '__main__':
    main()
