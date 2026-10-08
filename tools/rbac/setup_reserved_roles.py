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

"""Create the reserved roles of Rucio which do not exist yet.

    python tools/rbac/setup_reserved_roles.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rucio.core import role as role_core
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session

if __name__ == "__main__":
    with db_session(DatabaseOperationType.WRITE) as session:
        role_core.setup_reserved_roles(session=session)
