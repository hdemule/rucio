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

import shutil
from typing import Any
from urllib.parse import quote_plus

import pytest
import requests

from rucio.common.config import config_get
from rucio.common.types import InternalScope
from rucio.core.rule import list_rules

# HTTP status code the REST API returns
OK = 200
FORBIDDEN = 403
NOT_FOUND = 404

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
    url = f'{_rucio_host()}{path}'
    response = requests.request(method, url, headers=headers, verify=_ca_cert(), **kwargs)

    # TODO: Temporary prints for debugging test
    # BEGIN TEMP
    status = "SUCCESS" if response.ok else "FAILED"
    terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns
    label = f' {method} {url} '

    print(f"\n\033[94m{label:=^{terminal_width}}\033[0m")
    print(f"Account     : {account}")
    print(f"Status      : {status}")
    print(f"Status code : {response.status_code}")
    if 'json' in kwargs:
        print(f"Request json: {kwargs['json']}")
    if 'params' in kwargs:
        print(f"Request params: {kwargs['params']}")
    print("\033[34m" + "-" * terminal_width + "\033[0m")
    print("Response body:")
    print(response.text or "<empty>")
    print("\033[94m" + "=" * terminal_width + "\033[0m")
    # END TEMP

    return response


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


def _get_rule_id(name, vo, user='alice') -> str:
    """RBAC(USER): Look up the id of the replication rule for <user>:<name> directly from the database"""
    scope = InternalScope(user, vo=vo)
    rules = list(list_rules(filters={'scope': scope, 'name': name}))
    assert rules, f'No replication rule found for {user}:{name}'
    return rules[0]['id']


class TestDID:

    @pytest.mark.parametrize(
        ('payload', 'accounts', 'expected_statuses'),
        [
            ({'dids': [{'scope': 'alice', 'name': 'file1.png'}, {'scope': 'alice', 'name': 'file2.png'}]}, ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN]),
            ({'dids': [{'scope': 'root', 'name': 'file1'}]}, ['alice'], [FORBIDDEN]),
        ],
        ids=['readable scope', 'unauthorized scope'],
    )
    def test_bulk_list_files(self, payload, accounts, expected_statuses):
        """RBAC(USER): POST /dids/bulkfiles is only visible for readable DID scopes"""
        for account, expected_status in zip(accounts, expected_statuses):
            assert _post('/dids/bulkfiles', account, json=payload).status_code == expected_status

    def test_dataset_by_guid(self):
        pytest.skip("Ambiguous Test: Either Deny if scope associated to dataset is wrong, but if it's ok, maybe verify results are filtered according to the caller's readable scopes; also cover an unknown GUID.")

    @pytest.mark.parametrize(
        ('did', 'suffix', 'accounts', 'expected_statuses', 'params'),
        [
            ('alice:alice_ds', 'status', ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN], {'dynamic_depth': 'DATASET'}),
            ('non_existing_scope:alice_ds', 'status', ['root', 'alice', 'bob'], [NOT_FOUND, FORBIDDEN, FORBIDDEN], {'dynamic_depth': 'DATASET'}),
            ('alice:non_existing_ds', 'status', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN], {'dynamic_depth': 'DATASET'}),
            ('alice:alice_ds', 'rules', ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN], None),
            ('non_existing_scope:file1.png', 'rules', ['root', 'alice', 'bob'], [NOT_FOUND, FORBIDDEN, FORBIDDEN], None),
            ('alice:non_existing_file.png', 'rules', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN], None),
        ],
        ids=['status normal case', 'status non-existing scope', 'status non-existing DID', 'rules normal case', 'rules non-existing scope', 'rules non-existing DID'],
    )
    def test_get_did(self, did, suffix, accounts, expected_statuses, params):
        path = _did_path(did, suffix)
        request_kwargs = {'params': params} if params else {}
        for account, expected_status in zip(accounts, expected_statuses):
            assert _get(path, account, **request_kwargs).status_code == expected_status

    @pytest.mark.parametrize(
        ('did', 'accounts', 'expected_statuses'),
        [
            ('alice:alice_ds', ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN]),
            ('non_existing_scope:alice_ds', ['root', 'alice', 'bob'], [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
            ('alice:non_existing_ds', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing dataset'],
    )
    def test_get_metadata(self, did, accounts, expected_statuses):
        path = _did_path(did, 'meta')
        for account, expected_status in zip(accounts, expected_statuses):
            assert _get(path, account).status_code == expected_status

    @pytest.mark.parametrize(
        ('payload', 'accounts', 'expected_statuses', 'empty_responses'),
        [
            ({'dids': [{'scope': 'alice', 'name': 'alice_ds'}, {'scope': 'alice', 'name': 'alice_ds2'}], 'type': 'dataset'}, ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN], [False, False, False]),
            ({'dids': [{'scope': 'non_existing_scope', 'name': 'alice_ds'}], 'type': 'dataset'}, ['root', 'alice', 'bob'], [OK, FORBIDDEN, FORBIDDEN], [True, False, False]),
            ({'dids': [{'scope': 'alice', 'name': 'non_existing_ds'}], 'type': 'dataset'}, ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN], [True, True, False]),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing dataset'],
    )
    def test_get_metadata_bulk(self, payload, accounts, expected_statuses, empty_responses):
        path = '/dids/bulkmeta'
        for account, expected_status, empty_response in zip(accounts, expected_statuses, empty_responses):
            post = _post(path, account, json=payload)
            assert post.status_code == expected_status and (len(post.text) == 0) == empty_response  # equivalent to NOT_FOUND

    def test_get_users_following_did(self):
        pytest.skip("Filtering Test: query followers of a DID owned by alice and verify root/alice access, bob denial, and the response for an unknown scope or DID.")

    def test_list_archive_content(self):
        pytest.skip("Filtering Test: list the files in an archive by scope and name, verifying results are filtered for an unauthorized scope and covering unknown scope/DID behavior.")

    @pytest.mark.parametrize(
        ('did', 'accounts', 'expected_statuses'),
        [
            ('alice:alice_ds', ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN]),
            ('non_existing_scope:alice_ds', ['root', 'alice', 'bob'], [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
            ('alice:non_existing_ds', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_content(self, did, accounts, expected_statuses):
        """RBAC(USER): GET /dids/<scope>/<name>/dids is restricted by scope"""
        path = _did_path(did, 'dids')
        for account, expected_status in zip(accounts, expected_statuses):
            assert _get(path, account).status_code == expected_status

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:file1.png', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:file1.png', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_file.png', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_content_history(self, did, expected_statuses, empty_accounts):
        path = _did_path(did, 'dids', 'history')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    @pytest.mark.parametrize(
        ('scope', 'expected_statuses', 'empty_root'),
        [
            ('alice', [OK, OK, FORBIDDEN], False),
            ('non_existing_scope', [OK, FORBIDDEN, FORBIDDEN], True),
        ],
        ids=['normal case', 'non-existing scope'],
    )
    def test_list_dids(self, scope, expected_statuses, empty_root):
        path = f'/dids/{scope}/dids/search'
        params = {'name': '*'}
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account, params=params)
            assert response.status_code == expected_status
            if account == 'root' and empty_root:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    @pytest.mark.parametrize(
        ('did', 'expected_statuses'),
        [
            ('alice:alice_ds', [OK, OK, FORBIDDEN]),
            ('non_existing_scope:alice_ds', [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
            ('alice:non_existing_ds', [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_files(self, did, expected_statuses):
        path = _did_path(did, 'files')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            assert _get(path, account).status_code == expected_status

    def test_list_new_dids(self):
        pytest.skip("Filtering Test: list newly created DIDs and verify that returned DIDs are filtered according to each account's readable scopes.")

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:file1.png', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:file1.png', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_file.png', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_parent_dids(self, did, expected_statuses, empty_accounts):
        path = _did_path(did, 'parents')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    def test_scope_list(self):
        pytest.skip("Filtering Test: retrieve a DID by scope and verify results for readable and unreadable scopes; cover an unknown scope and DID.")


class TestLOCK:
    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:file1.png', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:file1.png', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_file.png', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_get_dataset_locks(self, did, expected_statuses, empty_accounts):
        path = _scope_name_path('locks', did)
        params = {'did_type': 'dataset'}
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account, params=params)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    @pytest.mark.parametrize(
        ('payload', 'expected_statuses', 'empty_accounts'),
        [
            ({'dids': [{'scope': 'alice', 'name': 'file1.png', 'type': 'dataset'}, {'scope': 'alice', 'name': 'file2.png', 'type': 'dataset'}]}, [OK, OK, FORBIDDEN], []),
            ({'dids': [{'scope': 'non_existing_scope', 'name': 'file1.png', 'type': 'dataset'}]}, [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ({'dids': [{'scope': 'alice', 'name': 'non_existing_file.png', 'type': 'dataset'}]}, [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_get_dataset_locks_bulk(self, payload, expected_statuses, empty_accounts):
        path = '/locks/bulk_locks_for_dids'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _post(path, account, json=payload)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    def test_get_dataset_locks_by_rse(self):
        pytest.skip("Filtering Test: list locks at an RSE and verify that lock records for DIDs in unreadable scopes are filtered.")

    @pytest.mark.parametrize(
        ('rule_owner', 'expected_statuses'),
        [
            ('alice', [OK, OK, FORBIDDEN]),
            ('root', [OK, FORBIDDEN, FORBIDDEN]),
            (None, [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
        ],
        ids=['owner-readable rule', 'root-only rule', 'non-existing rule'],
    )
    def test_get_dataset_locks_for_rule_id(self, vo, rule_owner, expected_statuses):
        rule_id = _get_rule_id('file1.png', vo, rule_owner) if rule_owner else 'non-existent-rule-id'
        path = f'/rules/{rule_id}/locks'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            assert _get(path, account).status_code == expected_status


class TestOPENDATA:
    def test_get_opendata_did(self):
        pytest.skip("Ambiguous: retrieve an open-data DID by scope and name, verifying authorized access, unauthorized-scope behavior, and unknown DID behavior.")

    def test_list_opendata_dids(self):
        pytest.skip("Ambiguous: list open-data DIDs and determine whether regular-account results are filtered to readable scopes or access is denied, while root can see all results.")


class TestREPLICA:
    def test_filter_replicas_by_site(self):
        pytest.skip("Ambiguous: resolve a replica redirect for a DID and determine whether unauthorized scopes are denied or filtered, including unknown DID behavior.")

    def test_get_bad_replicas_summary(self):
        pytest.skip("Filtering Test: list the bad-replica summary and verify that bad replicas from unauthorized scopes are filtered from regular-account results.")

    def test_get_did_from_pfns(self):
        pytest.skip("Filtering Test: resolve PFNs to DIDs and verify that returned DIDs are filtered according to the caller's readable scopes.")

    def test_get_suspicious_files(self):
        pytest.skip("Filtering Test: list suspicious files and verify filtering of files belonging to unauthorized scopes, with root retaining access to all results.")

    def test_list_bad_replicas_status(self):
        pytest.skip("Filtering Test: list bad-replica states and verify filtering of replicas belonging to scopes the caller cannot read.")

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:alice_ds', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:alice_ds', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_ds', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_dataset_replicas(self, did, expected_statuses, empty_accounts):
        path = _scope_name_path('replicas', did, 'datasets')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    @pytest.mark.parametrize(
        ('payload', 'expected_statuses', 'empty_accounts'),
        [
            ({'dids': [{'scope': 'alice', 'name': 'alice_ds'}, {'scope': 'alice', 'name': 'alice_ds2'}]}, [OK, OK, FORBIDDEN], []),
            ({'dids': [{'scope': 'non_existing_scope', 'name': 'alice_ds'}]}, [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ({'dids': [{'scope': 'alice', 'name': 'non_existing_ds'}]}, [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_dataset_replicas_bulk(self, payload, expected_statuses, empty_accounts):
        path = '/replicas/datasets_bulk'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _post(path, account, json=payload)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:alice_ds', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:alice_ds', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_ds', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_dataset_replicas_vp(self, did, expected_statuses, empty_accounts):
        path = _scope_name_path('replicas', did, 'datasets_vp')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    def test_list_datasets_per_rse(self):
        pytest.skip("Filtering Test: list datasets at an RSE and verify that datasets from unauthorized scopes are filtered for a regular account.")

    @pytest.mark.parametrize(
        ('payload', 'expected_statuses', 'empty_accounts'),
        [
            ({'dids': [{'scope': 'alice', 'name': 'file1.png'}]}, [OK, OK, FORBIDDEN], []),
            ({'dids': [{'scope': 'non_existing_scope', 'name': 'file1.png'}]}, [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ({'dids': [{'scope': 'alice', 'name': 'non_existing_file.png'}]}, [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_replicas(self, payload, expected_statuses, empty_accounts):
        path = '/replicas/list'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _post(path, account, json=payload)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND


class TestREQUEST:
    def test_get_request_by_did(self):
        pytest.skip("Permission Test: retrieve a transfer request for a DID as root, the owning account, and an unauthorized account.")

    def test_get_request_history_by_did(self):
        pytest.skip("Permission Test: retrieve request history for a DID at an RSE as root, the owning account, and an unauthorized account.")

    def test_list_requests(self):
        pytest.skip("Ambiguous: list transfer requests and determine whether records for unreadable DID scopes are filtered or access is denied.")

    def test_list_requests_history(self):
        pytest.skip("Ambiguous: list transfer-request history and determine whether records for unreadable DID scopes are filtered or access is denied.")


class TestRULE:
    @pytest.mark.parametrize(
        ('rule_owner', 'expected_statuses'),
        [
            ('alice', [OK, OK, FORBIDDEN]),
            ('root', [OK, FORBIDDEN, FORBIDDEN]),
            (None, [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
        ],
        ids=['owner-readable rule', 'root-only rule', 'non-existing rule'],
    )
    def test_examine_replication_rule(self, vo, rule_owner, expected_statuses):
        rule_id = _get_rule_id('file1.png', vo, rule_owner) if rule_owner else 'non-existent-rule-id'
        path = f'/rules/{rule_id}/analysis'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            assert _get(path, account).status_code == expected_status

    @pytest.mark.parametrize(
        ('rule_owner', 'expected_statuses'),
        [
            ('alice', [OK, OK, FORBIDDEN]),
            ('root', [OK, FORBIDDEN, FORBIDDEN]),
            (None, [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
        ],
        ids=['owner-readable rule', 'root-only rule', 'non-existing rule'],
    )
    def test_get_replication_rule(self, vo, rule_owner, expected_statuses):
        rule_id = _get_rule_id('file1.png', vo, rule_owner) if rule_owner else 'non-existent-rule-id'
        path = f'/rules/{rule_id}'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            assert _get(path, account).status_code == expected_status

    @pytest.mark.parametrize(
        ('did', 'expected_statuses'),
        [
            ('alice:file1.png', [OK, OK, FORBIDDEN]),
            ('non_existing_scope:file1.png', [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
            ('alice:non_existing_file.png', [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_associated_replication_rules_for_file(self, did, expected_statuses):
        path = _did_path(did, 'associated_rules')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            assert _get(path, account).status_code == expected_status

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:file1.png', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:file1.png', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_file.png', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_list_replication_rule_full_history(self, did, expected_statuses, empty_accounts):
        path = _scope_name_path('rules', did, 'history')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    def test_list_replication_rule_history(self):
        pytest.skip("Permission Test: retrieve a rule's history by rule_id and verify access based on the rule's DID scope, including a rule visible only to root and an unknown rule.")

    def test_list_replication_rules(self):
        pytest.skip("Filtering Test: list replication rules by account, DID, or subscription and verify filtering of rules associated with unreadable scopes.")


class TestSCOPE:
    def test_get_scopes(self):
        pytest.skip("Filtering Test: list scopes owned by an account and verify that a regular account sees only permitted scope records.")

    def test_list_scopes(self):
        pytest.skip("Filtering Test: list all scopes and verify that results for a regular account contain only readable scopes.")

    def test_list_scopes_with_account(self):
        pytest.skip("Filtering Test: list scopes together with their owning accounts and verify filtering of scopes unavailable to the caller.")


class TestSUBSCRIPTION:
    def test_get_subscription_by_id(self):
        pytest.skip("Filtering Test: retrieve a subscription by ID and verify filtering based on whether its scope filter contains a readable or unreadable scope.")

    def test_list_subscription_rule_states(self):
        pytest.skip("Ambiguous: list subscription rule states and determine whether states for rules linked to unreadable DID scopes are filtered or access is denied.")

    def test_list_subscriptions(self):
        pytest.skip("Filtering Test: list subscriptions and verify filtering based on the scopes in each subscription's DID filter and generated rules.")
