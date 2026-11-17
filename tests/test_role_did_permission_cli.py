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

from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from rucio.cli.role import did_add

# what the server stores for the operations given: each includes the ones before it
STORED = {'read': ['read'], 'write': ['read', 'write'], 'delete': ['read', 'write', 'delete']}


class _Client:
    """Stands for the role client: it stores the DID permissions of one role as the server does."""

    def __init__(self, permissions):
        self.permissions = dict(permissions)

    def list_role_permissions(self, role):
        return [{'type': 'did', 'did_pattern': did_pattern, 'operations': operations} for did_pattern, operations in self.permissions.items()]

    def add_role_permission(self, role, permission_type, parameters, force=False):
        self.permissions[parameters['did_pattern']] = sorted({stored for operation in parameters['operations'] for stored in STORED[operation]},
                                                             key=['read', 'write', 'delete'].index)


@pytest.mark.parametrize(('operations', 'notice'), [
    ('r', None),
    ('rw', None),
    ('w', "w implies r: stored rw- on atlas:raw*."),
    ('d', "d implies r and w: stored rwd on atlas:raw*."),
    ('wd', "d implies r: stored rwd on atlas:raw*."),
    ('none', None),
])
def test_did_add_tells_the_stored_operations(operations, notice):
    """CLI (ROLE): adding a DID permission tells the operations stored when the server completes those given"""
    result = CliRunner().invoke(did_add, ['user', 'atlas:raw*', operations], obj=SimpleNamespace(client=_Client({})))
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert (notice in lines) if notice else not any('implies' in line for line in lines)


def test_did_add_warns_with_the_stored_operations():
    """CLI (ROLE): the replaced operations and those withdrawn from a wider pattern are told as stored"""
    client = _Client({'atlas:*': ['read', 'write', 'delete'], 'atlas:raw*': ['read']})
    result = CliRunner().invoke(did_add, ['user', 'atlas:raw*', 'w'], obj=SimpleNamespace(client=client))
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [
        "w implies r: stored rw- on atlas:raw*.",
        "Replaced r-- by rw- on atlas:raw*.",
        "Set rw- on atlas:raw* for role 'user'.",
        "Warning: atlas:raw* (rw-) is more specific than atlas:* (rwd), so it decides the DIDs it matches instead: d withdrawn from them within role 'user'.",
    ]
