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

# To run a single test, use `pytest tests/test_rbac_restapi.py::TestDID::test_get_did`

from typing import Any
from urllib.parse import quote_plus

import pytest
import requests

from rucio.common.config import config_get
from rucio.common.types import InternalScope
from rucio.core.rule import list_rules

# HTTP status code the REST API returns when permission.has_permission() denies the action.
ACCESS_DENIED = 401
OK = 200

# Test accounts and their userpass identities, as provisioned by the dev environment bootstrap.
_USERNAMES = {
    'root': 'ddmlab',
    'alice': 'alice',
    'bob': 'bob',
}
_PASSWORD = 'secret'


def _auth_host() -> str:
    return config_get('client', 'auth_host')


def _rucio_host() -> str:
    return config_get('client', 'rucio_host')


def _ca_cert() -> str:
    return config_get('test', 'cacert')


def _get_token(account: str) -> str:
    """Authenticate as `account` via /auth/userpass and return the auth token."""
    response = requests.get(
        f'{_auth_host()}/auth/userpass',
        headers={
            'X-Rucio-Account': account,
            'X-Rucio-Username': _USERNAMES[account],
            'X-Rucio-Password': _PASSWORD,
        },
        verify=_ca_cert(),
    )
    response.raise_for_status()
    token = response.headers.get('X-Rucio-Auth-Token')
    assert token, f'No auth token returned for account {account}'
    return token


def _request(method: str, path: str, account: str, **kwargs: Any) -> requests.Response:
    """Perform an authenticated REST API call as `account` and return the raw response."""
    # some DID endpoints only accept application/x-json-stream, so advertise both
    headers = {'Accept': 'application/json, application/x-json-stream', 'X-Rucio-Auth-Token': _get_token(account)}
    headers.update(kwargs.pop('headers', {}))
    return requests.request(method, f'{_rucio_host()}{path}', headers=headers, verify=_ca_cert(), **kwargs)


def _get(path: str, account: str, **kwargs: Any) -> requests.Response:
    return _request('GET', path, account, **kwargs)


def _post(path: str, account: str, **kwargs: Any) -> requests.Response:
    return _request('POST', path, account, **kwargs)


def _scope_name_path(resource: str, did: str, *suffix: str) -> str:
    """Build a `/<resource>/<scope>/<name>/<suffix>` path from a `scope:name` DID string."""
    scope, name = did.split(':', 1)
    return '/'.join(['', resource, quote_plus(scope), quote_plus(name), *suffix])


def _did_path(did: str, *suffix: str) -> str:
    """Build a `/dids/<scope>/<name>/<suffix>` path from a `scope:name` DID string."""
    return _scope_name_path('dids', did, *suffix)


def _get_rule_id(name, vo):
    """RBAC(USER): Look up the id of the replication rule for alice:<name> directly from the database"""
    scope = InternalScope('alice', vo=vo)
    rules = list(list_rules(filters={'scope': scope, 'name': name}))
    assert rules, f'No replication rule found for alice:{name}'
    return rules[0]['id']


class TestDID:

    def test_bulk_list_files(self):
        """RBAC(USER): POST /dids/bulkfiles is only visible to root and alice for alice's DIDs"""
        json = {'dids': [{'scope': 'alice', 'name': 'square.png'}, {'scope': 'alice', 'name': 'triangle.png'}]}
        assert _post('/dids/bulkfiles', 'root', json=json).status_code == OK
        assert _post('/dids/bulkfiles', 'alice', json=json).status_code == OK
        assert _post('/dids/bulkfiles', 'bob', json=json).status_code == ACCESS_DENIED

        json = {'dids': [{'scope': 'root', 'name': 'file1'}]}
        assert _post('/dids/bulkfiles', 'alice', json=json).status_code == ACCESS_DENIED

    def test_dataset_by_guid(self):
        pytest.skip("Not implemented yet...")

    def test_get_did(self):
        path = _did_path('alice:alice_ds', 'status')
        params = {'dynamic_depth': 'DATASET'}
        assert _get(path, 'root', params=params).status_code == OK
        assert _get(path, 'alice', params=params).status_code == OK
        assert _get(path, 'bob', params=params).status_code == ACCESS_DENIED

    def test_get_metadata(self):
        path = _did_path('alice:alice_ds', 'meta')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_get_metadata_bulk(self):
        pytest.skip("similar to test_get_metadata, but in a for loop for multiple DIDs")

    def test_get_users_following_did(self):
        pytest.skip("Not implemented yet...")

    def test_list_archive_content(self):
        pytest.skip("Not implemented yet...")

    def test_list_content(self):
        """RBAC(USER): GET /dids/alice/alice_ds/dids is only visible to root and bob, not alice"""
        path = _did_path('alice:alice_ds', 'dids')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_content_history(self):
        path = _did_path('alice:square.png', 'dids', 'history')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_dids(self):
        path = '/dids/alice/dids/search'
        params = {'name': '*'}
        assert _get(path, 'root', params=params).status_code == OK
        assert _get(path, 'alice', params=params).status_code == OK
        assert _get(path, 'bob', params=params).status_code == ACCESS_DENIED

    @pytest.mark.deprecated
    def test_list_files(self):
        path = _did_path('alice:alice_ds', 'files')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_new_dids(self):
        pytest.skip("Not implemented yet...")

    def test_list_parent_dids(self):
        path = _did_path('alice:square.png', 'parents')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_scope_list(self):
        pytest.skip("Not implemented yet...")


class TestLOCK:
    def test_get_dataset_locks(self):
        # Indirect Call through the `rule list --traverse` command
        path = _scope_name_path('locks', 'alice:square.png')
        params = {'did_type': 'dataset'}
        assert _get(path, 'root', params=params).status_code == OK
        assert _get(path, 'alice', params=params).status_code == OK
        assert _get(path, 'bob', params=params).status_code == ACCESS_DENIED


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
        path = _scope_name_path('replicas', 'alice:alice_ds', 'datasets')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_dataset_replicas_bulk(self):
        json = {'dids': [{'scope': 'alice', 'name': 'alice_ds'}, {'scope': 'alice', 'name': 'alice_ds2'}]}
        assert _post('/replicas/datasets_bulk', 'root', json=json).status_code == OK
        assert _post('/replicas/datasets_bulk', 'alice', json=json).status_code == OK
        assert _post('/replicas/datasets_bulk', 'bob', json=json).status_code == ACCESS_DENIED

    def test_list_dataset_replicas_vp(self):
        path = _scope_name_path('replicas', 'alice:alice_ds', 'datasets_vp')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_datasets_per_rse(self):
        pytest.skip("Not implemented yet...")

    def test_list_replicas(self):
        json = {'dids': [{'scope': 'alice', 'name': 'square.png'}]}
        assert _post('/replicas/list', 'root', json=json).status_code == OK
        assert _post('/replicas/list', 'alice', json=json).status_code == OK
        assert _post('/replicas/list', 'bob', json=json).status_code == ACCESS_DENIED


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
        path = f'/rules/{_get_rule_id("square.png", vo)}/analysis'
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_get_replication_rule(self, vo):
        path = f'/rules/{_get_rule_id("square.png", vo)}'
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_associated_replication_rules_for_file(self):
        path = _did_path('alice:square.png', 'associated_rules')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

    def test_list_replication_rule_full_history(self):
        pytest.skip("Not implemented yet...")

    def test_list_replication_rule_history(self):
        path = _scope_name_path('rules', 'alice:square.png', 'history')
        assert _get(path, 'root').status_code == OK
        assert _get(path, 'alice').status_code == OK
        assert _get(path, 'bob').status_code == ACCESS_DENIED

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
