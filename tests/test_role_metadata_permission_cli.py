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

from rucio.cli.role import metadata_add


class _Client:
    """Stands for the role client: it stores the metadata permissions of one role as the server does, 'write' including 'read'."""

    def __init__(self, permissions):
        self.permissions = dict(permissions)

    def list_role_permissions(self, role):
        return [{'type': 'metadata', 'did_pattern': did_pattern, 'meta_key': key, 'operations': operations}
                for (did_pattern, key), operations in self.permissions.items()]

    def add_role_permission(self, role, permission_type, parameters, force=False):
        operations = ['read', 'write'] if 'write' in parameters['operations'] else list(parameters['operations'])
        for key in parameters.get('keys') or [None]:
            self.permissions[(parameters['did_pattern'], key)] = operations


@pytest.mark.parametrize(('operations', 'notice'), [
    ('r', None),
    ('rw', None),
    ('w', "w implies r: stored rw on project of atlas:*."),
    ('none', None),
])
def test_metadata_add_tells_the_stored_operations(operations, notice):
    """CLI (ROLE): adding a metadata permission tells the operations stored when the server completes those given"""
    result = CliRunner().invoke(metadata_add, ['user', 'atlas:*', operations, 'project'], obj=SimpleNamespace(client=_Client({})))
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert (notice in lines) if notice else not any('implies' in line for line in lines)


def test_metadata_add_replaces_with_the_stored_operations():
    """CLI (ROLE): the replaced operations of a key are told as stored"""
    client = _Client({('atlas:*', 'project'): ['read']})
    result = CliRunner().invoke(metadata_add, ['user', 'atlas:*', 'w', 'project'], obj=SimpleNamespace(client=client))
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [
        "w implies r: stored rw on project of atlas:*.",
        "Replaced r- by rw on project of atlas:*.",
        "Set rw on project of atlas:* for role 'user'.",
    ]
