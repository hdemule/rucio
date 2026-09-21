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

"""Report what synchronising the roles with the policy package would do.

The core function is a dry run: it only reads the roles of the policy package and of the
database, and prints the changes it would apply. Nothing is written, which is why the
session below is opened for reading.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rucio.core import role as role_core  # noqa: E402
from rucio.db.sqla.constants import DatabaseOperationType  # noqa: E402
from rucio.db.sqla.session import db_session  # noqa: E402


def sync_roles_from_policy_package() -> None:
    """Open a database session and run the synchronisation through it."""
    print("Syncing roles from policy package...")
    # once the synchronisation stops being a dry run, this has to become
    # DatabaseOperationType.WRITE, otherwise the session refuses to write
    with db_session(DatabaseOperationType.READ) as session:
        # pass vo='<vo>' to synchronise against the policy package of another VO
        role_core.sync_roles_from_policy_package(session=session)


def main() -> None:
    """Entry point of the script."""
    sync_roles_from_policy_package()


if __name__ == "__main__":
    main()
