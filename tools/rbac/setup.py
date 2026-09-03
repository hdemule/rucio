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

"""Create the database tables used by the RBAC tools."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rucio.db.sqla import models  # noqa: E402
from rucio.db.sqla.session import get_engine  # noqa: E402


def main() -> None:
    """Create the RBAC tables if they do not already exist."""
    tables = [
        models.Roles.__table__,
        models.AccountRoleAssociation.__table__,
        models.RolePermissionAssociation.__table__,
    ]
    models.BASE.metadata.create_all(get_engine(), tables=tables)
    print('RBAC tables are ready.')


if __name__ == '__main__':
    main()
