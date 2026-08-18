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

# To run a single test, use `pytest tests/test_rbac.py::TestDID::test_did_content_list_rbac`

import os

import pytest

from rucio.common.types import InternalScope
from rucio.core.rule import list_rules
from rucio.tests.common import execute

# def test_config():
#     """RBAC(USER): Check that the test config files exist"""
#     assert os.path.exists('etc/rucio-bob.cfg')
#     assert os.path.exists('etc/rucio-alice.cfg')
#     assert os.path.exists('etc/rucio.cfg')

#     # test if accounts exist
#     _, out, _ = execute('rucio account list')
#     assert out.find('bob') != -1
#     assert out.find('alice') != -1
#     assert out.find('root') != -1

#     _, out, _ = execute('rucio account attribute list bob')
#     assert out.find('read_scopes') != -1
#     assert out.find('bob') != -1

#     _, out, _ = execute('rucio account attribute list alice')
#     assert out.find('read_scopes') != -1
#     assert out.find('alice') != -1

#     _, out, _ = execute('rucio account attribute list root')
#     assert out.find('admin') != -1


def _login(account):
    """RBAC(USER): Login as a specific account"""
    original_config = os.environ.get('RUCIO_CONFIG')

    if account == 'root' or account is None:
        os.environ.pop('RUCIO_CONFIG', None)
    else:
        os.environ['RUCIO_CONFIG'] = f'etc/rucio-{account}.cfg'

    return original_config


def _get_rule_id(name, vo):
    """RBAC(USER): Look up the id of the replication rule for alice:<name> directly from the database"""
    scope = InternalScope('alice', vo=vo)
    rules = list(list_rules(filters={'scope': scope, 'name': name}))
    assert rules, f'No replication rule found for alice:{name}'
    return rules[0]['id']


class TestDID:

    @pytest.mark.deprecated
    def test_bulk_list_files(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio list-files alice:square.png alice:triangle.png')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio list-files alice:square.png alice:triangle.png')
        assert exitcode == 0

        exitcode, out, err = execute('rucio list-files alice:square.png root:file1')
        assert exitcode == 2  # AccessDenied Error

        _login('bob')
        exitcode, out, err = execute('rucio list-files alice:square.png alice:triangle.png')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_dataset_by_guid(self):
        pytest.skip("Not implemented yet...")

    def test_get_did(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio did show alice:alice_ds')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio did show alice:alice_ds')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio did show alice:alice_ds')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_get_metadata(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio did metadata list alice:alice_ds')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio did metadata list alice:alice_ds')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio did metadata list alice:alice_ds')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_get_metadata_bulk(self):
        pytest.skip("similar to test_get_metadata, but in a for loop for multiple DIDs")

    def test_get_users_following_did(self):
        pytest.skip("Not implemented yet...")

    def test_list_archive_content(self):
        pytest.skip("Not implemented yet...")

    def test_list_content(self):
        """RBAC(USER): rucio did content list alice:alice_ds is only visible to root and bob, not alice"""

        original_config = _login('root')
        exitcode, out, err = execute('rucio did content list alice:alice_ds')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio did content list alice:alice_ds')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio did content list alice:alice_ds')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_list_content_history(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio did content history alice:square.png')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio did content history alice:square.png')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio did content history alice:square.png')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_list_dids(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio did list alice:*')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio did list alice:*')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio did list alice:*')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    @pytest.mark.deprecated
    def test_list_files(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio list-files alice:alice_ds')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio list-files alice:alice_ds')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio list-files alice:alice_ds')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_list_new_dids(self):
        pytest.skip("Not implemented yet...")

    def test_list_parent_dids(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio did list alice:square.png --parent')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio did list alice:square.png --parent')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio did list alice:square.png --parent')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_scope_list(self):
        pytest.skip("Not implemented yet...")


class TestLOCK:
    def test_get_dataset_locks(self):
        original_config = _login('root')
        # Indirect Call through `rule` command
        exitcode, out, err = execute('rucio rule list --did alice:square.png --traverse')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio rule list --did alice:square.png --traverse')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio rule list --did alice:square.png --traverse')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)


class TestOPENDATA:
    def test_get_opendata_did(self):
        pytest.skip("Not implemented yet...")

    def test_list_opendata_dids(self):
        pytest.skip("Not implemented yet...")


class TestREPLICA:
    def test_get_bad_replicas_summary(self):
        pytest.skip("Not implemented yet...")

    def test_get_did_from_pfns(self):
        pytest.skip("Not implemented yet...")

    def test_get_suspicious_files(self):
        pytest.skip("Not implemented yet...")

    def test_list_bad_replicas_status(self):
        pytest.skip("Not implemented yet...")

    def test_list_dataset_replicas(self):
        pytest.skip("Not implemented yet...")

    def test_list_dataset_replicas_bulk(self):
        pytest.skip("Not implemented yet...")

    def test_list_dataset_replicas_vp(self):
        pytest.skip("Not implemented yet...")

    def test_list_datasets_per_rse(self):
        pytest.skip("Not implemented yet...")

    def test_list_replicas(self):
        pytest.skip("Not implemented yet...")


class TestREQUEST:
    def test_get_request_by_did(self):
        pytest.skip("Not implemented yet...")

    def test_get_request_history_by_did(self):
        pytest.skip("Not implemented yet...")

    def test_list_requests(self):
        pytest.skip("Not implemented yet...")

    def test_list_requests_history(self):
        pytest.skip("Not implemented yet...")


class TestRULE:
    def test_examine_replication_rule(self, vo):
        rule_id = _get_rule_id('square.png', vo)

        original_config = _login('root')
        exitcode, out, err = execute(f'rucio rule show {rule_id} --examine')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute(f'rucio rule show {rule_id} --examine')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute(f'rucio rule show {rule_id} --examine')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_get_replication_rule(self, vo):
        rule_id = _get_rule_id('square.png', vo)

        original_config = _login('root')
        exitcode, out, err = execute(f'rucio rule show {rule_id}')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute(f'rucio rule show {rule_id}')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute(f'rucio rule show {rule_id}')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_list_associated_replication_rules_for_file(self):
        pytest.skip("Not implemented yet...")

    def test_list_replication_rule_full_history(self):
        pytest.skip("Not implemented yet...")

    def test_list_replication_rule_history(self):
        original_config = _login('root')
        exitcode, out, err = execute('rucio rule history alice:square.png')
        assert exitcode == 0

        _login('alice')
        exitcode, out, err = execute('rucio rule history alice:square.png')
        assert exitcode == 0

        _login('bob')
        exitcode, out, err = execute('rucio rule history alice:square.png')
        assert exitcode == 2  # AccessDenied Error

        _login(original_config)

    def test_list_replication_rules(self):
        pytest.skip("Not implemented yet...")


class TestSCOPE:
    def test_get_scopes(self):
        pytest.skip("Not implemented yet...")

    def test_list_scopes(self):
        pytest.skip("Not implemented yet...")

    def test_list_scopes_with_account(self):
        pytest.skip("Not implemented yet...")


class TestSUBSCRIPTION:
    def test_get_subscription_by_id(self):
        pytest.skip("Not implemented yet...")

    def test_list_subscription_rule_states(self):
        pytest.skip("Not implemented yet...")

    def test_list_subscriptions(self):
        pytest.skip("Not implemented yet...")
