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

# Assumptions made for the following tests, without which they will fail.
# Accounts:
#   1. root  - admin account; root/admin is the only caller allowed to perform role-management
#              operations (add/delete role, role permissions, account roles), since none of those
#              actions have a dedicated permission check and thus fall back to perm_default
#              (root or an account with the 'admin' attribute).
#   2. alice - regular account; owns scope 'alice' and already has the 'data-scientist' role assigned.
#   3. bob   - regular account; owns no scope of its own and has no roles assigned.
# Roles:
#   1. 'data-scientist' - already exists and grants READ+WRITE permission on scope 'atlas'.
# Scopes:
#   1. 'alice' - owned by account 'alice'.
#   2. 'root'  - owned by account 'root'; also used as a throwaway permission target for role tests.
#   3. 'atlas' - target of the 'data-scientist' role's permissions.
# DIDs:
#   'alice:alice_ds', 'alice:alice_ds2', 'alice:file1.png', 'alice:file2.png' and 'root:file1' exist,
#   with replication rules registered for some of them (see `_get_rule_id`).
# The response filtering tests additionally rely on the cross-scope data of the `rbac_data` fixture,
# which is created once for this module (see `tests/rbac_common.py`).

import json
import shutil
from typing import Any
from urllib.parse import quote_plus
from uuid import uuid4

import pytest
import requests

from rucio.common.config import config_get
from rucio.common.exception import AccessDenied, RuleNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.did import remove_did_from_followed
from rucio.core.rule import list_rules
from rucio.gateway import replica as gateway_replica
from rucio.gateway import rule as gateway_rule
from rucio.gateway.did import list_files

from .rbac_common import RBACTestData, create_rbac_test_data

# HTTP status code the REST API returns
OK = 200
CREATED = 201
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
CONFLICT = 409  # returned for both Duplicate and RoleInUse errors

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


def _delete(path: str, account: str, **kwargs: Any) -> requests.Response:
    return _request('DELETE', path, account, **kwargs)


def _role_path(role_name: str, *suffix: str) -> str:
    """Build a `/roles/<role_name>/<suffix>` path."""
    return '/'.join(['', 'roles', quote_plus(role_name), *suffix])


def _account_roles_path(account: str, *suffix: str) -> str:
    """Build a `/accounts/<account>/roles/<suffix>` path."""
    return '/'.join(['', 'accounts', quote_plus(account), 'roles', *suffix])


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


def _get_file_guid(name, scope='alice', user='alice') -> str:
    """RBAC(USER): Look up the GUID of the file for <user>:<name> directly from the database"""
    files = list(list_files(scope=scope, name=name, issuer='root', long=False))
    assert files, f'No file found for {user}:{name}'
    return files[0]['guid']


def _stream(response: requests.Response) -> list[Any]:
    """Decode a response body holding one JSON document per line (application/x-json-stream)."""
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


def _dids(items: list[Any]) -> set[str]:
    """The 'scope:name' of every item of a response."""
    return {'%s:%s' % (item['scope'], item['name']) for item in items}


def _name(did: str) -> str:
    return did.split(':', 1)[1]


def _assert_visible(response: requests.Response, expected: set[str], decode=_stream, key=_dids) -> None:
    """Assert that the response succeeded and returned exactly the `expected` items, e.g. the `expected` 'scope:name' DIDs."""
    assert response.status_code == OK, response.text
    assert key(decode(response)) == expected


@pytest.fixture(scope='module')
def rbac_data(vo) -> RBACTestData:
    """Data crossing the 'alice' and 'root' scopes, to observe the RBAC response filtering (see `tests/rbac_common.py`)."""
    return create_rbac_test_data(vo)


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

    @pytest.mark.parametrize(
        ('scope', 'file', 'accounts', 'expected_scope', 'expected_visibilities'),
        [
            ('alice', 'file1.png', ['root', 'alice', 'bob'], 'alice', [True, True, False]),
        ],
        ids=['ds by guid filtering'],
    )
    def test_get_dataset_by_guid(self, scope, file, accounts, expected_scope, expected_visibilities):
        """RBAC(USER): GET /dids/{guid}/guid is only visible for readable DID scopes"""
        guid = _get_file_guid(file, scope=scope, user='root')  # get the GUID

        # call /dids/{guid}/guid
        for account, expected_visibility in zip(accounts, expected_visibilities):
            response = _get(f'/dids/{guid}/guid', account)
            scopes = {dataset['scope'] for dataset in map(json.loads, response.text.splitlines())}
            assert (expected_scope in scopes) is expected_visibility

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

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('alice:alice_ds', [OK, OK, FORBIDDEN], []),
            ('non_existing_scope:alice_ds', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_ds', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['normal case', 'non-existing scope', 'non-existing DID'],
    )
    def test_get_users_following_did(self, did, expected_statuses, empty_accounts):
        """RBAC(USER): GET /dids/<scope>/<name>/follow is restricted by scope, an unknown DID simply has no follower"""
        path = _did_path(did, 'follow')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    def test_add_did_to_followed(self, vo, rbac_data):
        """RBAC(USER): POST /dids/<scope>/<name>/follow requires read access on the scope of the followed DID"""
        cases = [
            ('bob', rbac_data.dataset_a, FORBIDDEN),
            ('alice', rbac_data.dataset_r, FORBIDDEN),
            ('alice', 'non_existing_scope:%s' % _name(rbac_data.dataset_a), FORBIDDEN),
            ('alice', rbac_data.dataset_a, CREATED),
            ('root', rbac_data.dataset_r, CREATED),
        ]
        try:
            for account, did, expected_status in cases:
                assert _post(_did_path(did, 'follow'), account, json={'account': account}).status_code == expected_status

            # the followers are then only listed to the accounts which can read the DID
            _assert_visible(_get(_did_path(rbac_data.dataset_a, 'follow'), 'root'), {'alice'}, key=lambda users: {user['user'] for user in users})
            _assert_visible(_get(_did_path(rbac_data.dataset_a, 'follow'), 'alice'), {'alice'}, key=lambda users: {user['user'] for user in users})
            assert _get(_did_path(rbac_data.dataset_a, 'follow'), 'bob').status_code == FORBIDDEN
            assert _get(_did_path(rbac_data.dataset_r, 'follow'), 'alice').status_code == FORBIDDEN
        finally:
            for account, did in (('alice', rbac_data.dataset_a), ('root', rbac_data.dataset_r)):
                scope, name = did.split(':', 1)
                remove_did_from_followed(scope=InternalScope(scope, vo=vo), name=name, account=InternalAccount(account, vo=vo))

    def test_list_archive_content(self, rbac_data):
        """RBAC(USER): GET /archives/<scope>/<name>/files is restricted by scope, and constituents in unreadable scopes are filtered out"""
        path = _scope_name_path('archives', rbac_data.archive, 'files')
        _assert_visible(_get(path, 'root'), {rbac_data.constituent_a, rbac_data.constituent_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.constituent_a})
        assert _get(path, 'bob').status_code == FORBIDDEN

    @pytest.mark.parametrize(
        ('did', 'expected_statuses', 'empty_accounts'),
        [
            ('non_existing_scope:archive.zip', [OK, FORBIDDEN, FORBIDDEN], ['root']),
            ('alice:non_existing_archive.zip', [OK, OK, FORBIDDEN], ['root', 'alice']),
        ],
        ids=['non-existing scope', 'non-existing archive'],
    )
    def test_list_archive_content_unknown(self, did, expected_statuses, empty_accounts):
        """RBAC(USER): GET /archives/<scope>/<name>/files of an unknown archive is empty for whom may read the scope, denied otherwise"""
        path = _scope_name_path('archives', did, 'files')
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(path, account)
            assert response.status_code == expected_status
            if account in empty_accounts:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

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

    def test_list_new_dids(self, rbac_data):
        """RBAC(USER): GET /dids/new only returns the new DIDs in scopes the caller can read"""
        assert _get('/dids/new', 'root').status_code == OK
        for account in ('alice', 'bob'):
            # the scopes an account can read, by ownership or through its roles, are the ones GET /scopes/ lists to it (see TestSCOPE)
            readable_scopes = set(_get('/scopes/', account).json())
            assert 'root' not in readable_scopes
            response = _get('/dids/new', account)
            assert response.status_code == OK
            assert {did['scope'] for did in _stream(response)} <= readable_scopes

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

    @pytest.mark.parametrize(
        ('scope', 'expected_statuses', 'empty_root'),
        [
            ('alice', [OK, OK, FORBIDDEN], False),
            ('non_existing_scope', [OK, FORBIDDEN, FORBIDDEN], True),
        ],
        ids=['normal case', 'non-existing scope'],
    )
    def test_scope_list(self, scope, expected_statuses, empty_root):
        """RBAC(USER): GET /dids/<scope>/ is restricted by scope"""
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            response = _get(f'/dids/{scope}/', account)
            assert response.status_code == expected_status
            if account == 'root' and empty_root:
                assert len(response.text) == 0  # equivalent to NOT_FOUND

    def test_scope_list_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /dids/<scope>/?name=<name> filters out the content of the DID which lives in unreadable scopes"""
        path = '/dids/alice/'
        params = {'name': _name(rbac_data.dataset_a)}
        _assert_visible(_get(path, 'root', params=params), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_get(path, 'alice', params=params), {rbac_data.file_a})
        assert _get(path, 'bob', params=params).status_code == FORBIDDEN

    def test_scope_list_unknown_did(self):
        """RBAC(USER): GET /dids/<scope>/?name=<name> of an unknown DID is only reported as such to whom may read the scope"""
        params = {'name': 'non_existing_ds'}
        for account, expected_status in zip(['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]):
            assert _get('/dids/alice/', account, params=params).status_code == expected_status

    def test_list_content_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /dids/<scope>/<name>/dids filters out the content which lives in unreadable scopes"""
        path = _did_path(rbac_data.dataset_a, 'dids')
        _assert_visible(_get(path, 'root'), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.file_a})
        assert _get(path, 'bob').status_code == FORBIDDEN

    def test_list_content_history_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /dids/<scope>/<name>/dids/history filters out the former content which lives in unreadable scopes"""
        path = _did_path(rbac_data.history_dataset, 'dids', 'history')
        _assert_visible(_get(path, 'root'), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.file_a})
        assert _get(path, 'bob').status_code == FORBIDDEN

    @pytest.mark.parametrize('long', [False, True], ids=['short format', 'long format'])
    def test_list_dids_recursive_filters_other_scopes(self, rbac_data, long):
        """RBAC(USER): GET /dids/<scope>/dids/search?recursive=True does not descend into the content which lives in unreadable scopes"""
        path = '/dids/alice/dids/search'
        params = {'name': _name(rbac_data.dataset_a), 'type': 'all', 'recursive': True, 'long': long}
        # the short format only yields names, the long format yields the scope along with the name
        key = _dids if long else set
        expected = {
            'root': {rbac_data.dataset_a, rbac_data.file_a, rbac_data.file_r},
            'alice': {rbac_data.dataset_a, rbac_data.file_a},
        }
        for account, dids in expected.items():
            _assert_visible(_get(path, account, params=params), dids if long else {_name(did) for did in dids}, key=key)
        assert _get(path, 'bob', params=params).status_code == FORBIDDEN

    def test_list_files_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /dids/<scope>/<name>/files filters out the files which live in unreadable scopes"""
        path = _did_path(rbac_data.dataset_a, 'files')
        _assert_visible(_get(path, 'root'), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.file_a})
        assert _get(path, 'bob').status_code == FORBIDDEN

    def test_bulk_list_files_filters_other_scopes(self, rbac_data):
        """RBAC(USER): POST /dids/bulkfiles filters out the files which live in unreadable scopes"""
        scope, name = rbac_data.dataset_a.split(':', 1)
        payload = {'dids': [{'scope': scope, 'name': name}]}
        _assert_visible(_post('/dids/bulkfiles', 'root', json=payload), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_post('/dids/bulkfiles', 'alice', json=payload), {rbac_data.file_a})
        assert _post('/dids/bulkfiles', 'bob', json=payload).status_code == FORBIDDEN

    def test_list_parent_dids_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /dids/<scope>/<name>/parents filters out the parents which live in unreadable scopes"""
        path = _did_path(rbac_data.file_a, 'parents')
        _assert_visible(_get(path, 'root'), {rbac_data.dataset_a, rbac_data.dataset_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.dataset_a})
        assert _get(path, 'bob').status_code == FORBIDDEN

    def test_delete_metadata(self, rbac_data):
        """RBAC(USER): DELETE /dids/<scope>/<name>/meta requires write access on the scope of the DID"""
        params = {'key': 'rbac_test_key'}
        for account, did in (('bob', rbac_data.dataset_a), ('alice', rbac_data.dataset_r), ('alice', 'non_existing_scope:%s' % _name(rbac_data.dataset_a))):
            assert _delete(_did_path(did, 'meta'), account, params=params).status_code == FORBIDDEN
        # the key does not exist, and not every metadata plugin supports deleting a key: anything but a denial will do
        for account, did in (('alice', rbac_data.dataset_a), ('root', rbac_data.dataset_r)):
            assert _delete(_did_path(did, 'meta'), account, params=params).status_code != FORBIDDEN

    def test_create_did_sample(self, rbac_data):
        """RBAC(USER): POST /dids/sample requires read access on the scope of the sampled collection"""
        def payload(input_did: str, output_scope: str) -> dict[str, Any]:
            input_scope, input_name = input_did.split(':', 1)
            return {'input_scope': input_scope, 'input_name': input_name, 'output_scope': output_scope,
                    'output_name': 'rbac_sample_%s' % uuid4().hex[:12], 'nbfiles': 1}

        assert _post('/dids/sample', 'alice', json=payload(rbac_data.dataset_r, 'alice')).status_code == FORBIDDEN
        assert _post('/dids/sample', 'alice', json=payload('non_existing_scope:%s' % _name(rbac_data.dataset_r), 'alice')).status_code == FORBIDDEN
        assert _post('/dids/sample', 'bob', json=payload(rbac_data.dataset_a, 'alice')).status_code == FORBIDDEN
        assert _post('/dids/sample', 'alice', json=payload(rbac_data.dataset_a, 'alice')).status_code == CREATED


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

    def test_get_dataset_locks_by_rse(self, rbac_data):
        """RBAC(USER): GET /locks/<rse> filters out the dataset locks of DIDs which live in unreadable scopes"""
        path = f'/locks/{rbac_data.rse}'
        params = {'did_type': 'dataset'}
        _assert_visible(_get(path, 'root', params=params), {rbac_data.dataset_a, rbac_data.dataset_r})
        _assert_visible(_get(path, 'alice', params=params), {rbac_data.dataset_a})
        _assert_visible(_get(path, 'bob', params=params), set())

    def test_get_replica_locks_for_rule_id_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /rules/<rule_id>/locks filters out the locks of files which live in unreadable scopes"""
        path = f'/rules/{rbac_data.rule_a}/locks'
        _assert_visible(_get(path, 'root'), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.file_a})
        assert _get(path, 'bob').status_code == FORBIDDEN

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

    def test_get_did_from_pfns(self, vo, rbac_data, monkeypatch):
        """RBAC(USER): the DIDs a list of PFNs resolves to are filtered according to the caller's readable scopes

        POST /replicas/dids resolves the PFNs with the SRM protocol only (https://github.com/rucio/rucio/issues/8567),
        which the test RSE does not provide, so the gateway is called directly with the PFN resolution mocked.
        """
        def resolved_pfns(**kwargs: Any):
            for pfn, did in ((rbac_data.pfn_a, rbac_data.file_a), (rbac_data.pfn_r, rbac_data.file_r)):
                scope, name = did.split(':', 1)
                yield {pfn: {'scope': InternalScope(scope, vo=vo), 'name': name}}

        monkeypatch.setattr(gateway_replica.replica, 'get_did_from_pfns', resolved_pfns)
        expected = {'root': {rbac_data.pfn_a, rbac_data.pfn_r}, 'alice': {rbac_data.pfn_a}, 'bob': set()}
        for account, pfns in expected.items():
            results = gateway_replica.get_did_from_pfns(issuer=account, pfns=[rbac_data.pfn_a, rbac_data.pfn_r], rse=rbac_data.rse, vo=vo)
            assert {pfn for result in results for pfn in result} == pfns

    def test_get_suspicious_files(self, rbac_data):
        """RBAC(USER): GET /replicas/suspicious filters out the suspicious files which live in unreadable scopes"""
        params = {'rse_expression': rbac_data.rse}
        _assert_visible(_get('/replicas/suspicious', 'root', params=params), {rbac_data.file_a, rbac_data.file_r}, decode=requests.Response.json)
        _assert_visible(_get('/replicas/suspicious', 'alice', params=params), {rbac_data.file_a}, decode=requests.Response.json)
        _assert_visible(_get('/replicas/suspicious', 'bob', params=params), set(), decode=requests.Response.json)

    def test_list_bad_replicas_status(self, rbac_data):
        """RBAC(USER): GET /replicas/bad/states filters out the bad replicas which live in unreadable scopes"""
        params = {'state': 'S', 'rse': rbac_data.rse}
        _assert_visible(_get('/replicas/bad/states', 'root', params=params), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_get('/replicas/bad/states', 'alice', params=params), {rbac_data.file_a})
        _assert_visible(_get('/replicas/bad/states', 'bob', params=params), set())

    def test_list_bad_replicas_status_pfns(self, rbac_data):
        """RBAC(USER): GET /replicas/bad/states?list_pfns=True does not disclose the PFNs, which embed scope and name, of unreadable bad replicas"""
        params = {'state': 'S', 'rse': rbac_data.rse, 'list_pfns': True}
        _assert_visible(_get('/replicas/bad/states', 'root', params=params), {rbac_data.pfn_a, rbac_data.pfn_r}, key=set)
        _assert_visible(_get('/replicas/bad/states', 'alice', params=params), {rbac_data.pfn_a}, key=set)
        _assert_visible(_get('/replicas/bad/states', 'bob', params=params), set(), key=set)

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

    def test_list_datasets_per_rse(self, rbac_data):
        """RBAC(USER): GET /replicas/rse/<rse> filters out the dataset replicas of datasets which live in unreadable scopes"""
        path = f'/replicas/rse/{rbac_data.rse}'
        _assert_visible(_get(path, 'root'), {rbac_data.dataset_a, rbac_data.dataset_r})
        _assert_visible(_get(path, 'alice'), {rbac_data.dataset_a})
        _assert_visible(_get(path, 'bob'), set())

    def test_list_replicas_filters_other_scopes(self, rbac_data):
        """RBAC(USER): POST /replicas/list filters out the replicas of the files of a collection which live in unreadable scopes"""
        scope, name = rbac_data.dataset_a.split(':', 1)
        payload = {'dids': [{'scope': scope, 'name': name}]}
        _assert_visible(_post('/replicas/list', 'root', json=payload), {rbac_data.file_a, rbac_data.file_r})
        _assert_visible(_post('/replicas/list', 'alice', json=payload), {rbac_data.file_a})
        assert _post('/replicas/list', 'bob', json=payload).status_code == FORBIDDEN

    def test_list_replicas_resolve_parents_filters_other_scopes(self, rbac_data):
        """RBAC(USER): POST /replicas/list with resolve_parents does not disclose the parents which live in unreadable scopes"""
        scope, name = rbac_data.file_a.split(':', 1)
        payload = {'dids': [{'scope': scope, 'name': name}], 'resolve_parents': True}

        def parents(replicas: list[Any]) -> set[str]:
            return {parent for replica in replicas for parent in replica['parents']}

        _assert_visible(_post('/replicas/list', 'root', json=payload), {rbac_data.dataset_a, rbac_data.dataset_r}, key=parents)
        _assert_visible(_post('/replicas/list', 'alice', json=payload), {rbac_data.dataset_a}, key=parents)

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

    @pytest.mark.parametrize(
        ('did', 'rse', 'accounts', 'expected_statuses'),
        [
            ('alice:file1.png', 'MOCK-POSIX', ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN]),
            ('non_existing_scope:file1.png', 'MOCK-POSIX', ['root', 'alice', 'bob'], [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
            ('alice:non_existing_file.png', 'MOCK-POSIX', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
            ('alice:file1.png', 'NON_EXISTING_RSE', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
        ],
        ids=['status normal case', 'status non-existing scope', 'status non-existing DID', 'status non-existing RSE'],
    )
    def test_get_request_by_did(self, did, rse, accounts, expected_statuses):
        scope, name = did.split(':')
        path = f'/requests/{scope}/{name}/{rse}'
        for account, expected_status in zip(accounts, expected_statuses):
            assert _get(path, account).status_code == expected_status

    @pytest.mark.parametrize(
        ('did', 'rse', 'accounts', 'expected_statuses'),
        [
            ('alice:file1.png', 'MOCK-POSIX', ['root', 'alice', 'bob'], [OK, OK, FORBIDDEN]),
            ('non_existing_scope:file1.png', 'MOCK-POSIX', ['root', 'alice', 'bob'], [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
            ('alice:non_existing_file.png', 'MOCK-POSIX', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
            ('alice:file1.png', 'NON_EXISTING_RSE', ['root', 'alice', 'bob'], [NOT_FOUND, NOT_FOUND, FORBIDDEN]),
        ],
        ids=['status normal case', 'status non-existing scope', 'status non-existing DID', 'status non-existing RSE'],
    )
    def test_get_request_history_by_did(self, did, rse, accounts, expected_statuses):
        scope, name = did.split(':')
        path = f'/requests/history/{scope}/{name}/{rse}'
        for account, expected_status in zip(accounts, expected_statuses):
            assert _get(path, account).status_code == expected_status

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

    @pytest.mark.parametrize(
        ('rule', 'expected_statuses'),
        [
            ('rule_a', [OK, OK, FORBIDDEN]),
            ('rule_r', [OK, FORBIDDEN, FORBIDDEN]),
            (None, [NOT_FOUND, FORBIDDEN, FORBIDDEN]),
        ],
        ids=['owner-readable rule', 'root-only rule', 'non-existing rule'],
    )
    def test_list_replication_rule_history(self, vo, rbac_data, rule, expected_statuses):
        """RBAC(USER): the history of a rule is restricted by the scope of the DID of the rule

        GET /rules/<rule_id>/history is shadowed by the DID history route GET /rules/<scope>/<name>/history,
        which answers 400 as it cannot parse a rule id into a scope and a name, so the gateway is called directly.
        """
        rule_id = getattr(rbac_data, rule) if rule else 'non-existent-rule-id'
        for account, expected_status in zip(['root', 'alice', 'bob'], expected_statuses):
            try:
                list(gateway_rule.list_replication_rule_history(rule_id, issuer=account, vo=vo))
                status = OK
            except AccessDenied:
                status = FORBIDDEN
            except RuleNotFound:
                status = NOT_FOUND
            assert status == expected_status, f'{account} got {status} for rule {rule_id}'

    def test_list_replication_rules(self, rbac_data):
        """RBAC(USER): GET /rules/ filters out the rules on DIDs which live in unreadable scopes"""
        params = {'rse_expression': rbac_data.rse}

        def ids(rules: list[Any]) -> set[str]:
            return {rule['id'] for rule in rules}

        _assert_visible(_get('/rules/', 'root', params=params), {rbac_data.rule_a, rbac_data.rule_r}, key=ids)
        _assert_visible(_get('/rules/', 'alice', params=params), {rbac_data.rule_a}, key=ids)
        _assert_visible(_get('/rules/', 'bob', params=params), set(), key=ids)

        # filtering on an unreadable scope answers like filtering on a scope which does not exist
        for scope in ('root', 'non_existing_scope'):
            _assert_visible(_get('/rules/', 'alice', params={'scope': scope, 'name': _name(rbac_data.dataset_r)}), set(), key=ids)

    def test_list_replication_rules_of_account(self, rbac_data):
        """RBAC(USER): GET /accounts/<account>/rules filters out the rules on DIDs which live in unreadable scopes"""
        params = {'rse_expression': rbac_data.rse}

        def ids(rules: list[Any]) -> set[str]:
            return {rule['id'] for rule in rules}

        _assert_visible(_get('/accounts/root/rules', 'root', params=params), {rbac_data.rule_r}, key=ids)
        _assert_visible(_get('/accounts/root/rules', 'alice', params=params), set(), key=ids)

    def test_list_associated_replication_rules_filters_other_scopes(self, rbac_data):
        """RBAC(USER): GET /dids/<scope>/<name>/associated_rules filters out the rules set on parents which live in unreadable scopes"""
        path = _did_path(rbac_data.file_a, 'associated_rules')

        def ids(rules: list[Any]) -> set[str]:
            return {rule['id'] for rule in rules}

        _assert_visible(_get(path, 'root'), {rbac_data.rule_a, rbac_data.rule_r}, key=ids)
        _assert_visible(_get(path, 'alice'), {rbac_data.rule_a}, key=ids)
        assert _get(path, 'bob').status_code == FORBIDDEN


class TestSCOPE:
    @pytest.mark.parametrize('path', ['/scopes/{account}/scopes', '/accounts/{account}/scopes/'], ids=['scopes endpoint', 'accounts endpoint'])
    def test_get_scopes(self, path):
        """RBAC(USER): the scopes of an account are only listed to the callers which can read them"""
        for account in ('root', 'alice'):
            response = _get(path.format(account=account), account)
            assert response.status_code == OK
            assert account in response.json()

        # an account whose scopes are all unreadable looks like an account without any scope
        for caller, owner in (('alice', 'root'), ('bob', 'alice'), ('bob', 'root')):
            response = _get(path.format(account=owner), caller)
            assert response.status_code in (OK, NOT_FOUND)
            if response.status_code == OK:
                assert owner not in response.json()

    def test_list_scopes(self):
        """RBAC(USER): GET /scopes/ only lists the scopes the caller can read"""
        scopes = {account: set(_get('/scopes/', account).json()) for account in ('root', 'alice', 'bob')}
        assert {'root', 'alice'} <= scopes['root']
        assert 'alice' in scopes['alice'] and 'root' not in scopes['alice']
        assert not {'root', 'alice'} & scopes['bob']

    def test_list_scopes_with_account(self):
        """RBAC(USER): GET /scopes/owner/ only lists the scopes the caller can read, along with their owner"""
        scopes = {account: {entry['scope'] for entry in _get('/scopes/owner/', account).json()} for account in ('root', 'alice', 'bob')}
        assert {'root', 'alice'} <= scopes['root']
        assert 'alice' in scopes['alice'] and 'root' not in scopes['alice']
        assert not {'root', 'alice'} & scopes['bob']


class TestLIFETIMEEXCEPTION:
    pytestmark = pytest.mark.skip(reason="Temporarily skipped")

    def test_add_exception(self, rbac_data):
        pass

    def test_list_exceptions(self, rbac_data):
        pass

    def test_get_exception(self, rbac_data):
        pass

class TestSUBSCRIPTION:
    def test_get_subscription_by_id(self):
        pytest.skip("Filtering Test: retrieve a subscription by ID and verify filtering based on whether its scope filter contains a readable or unreadable scope.")

    def test_list_subscription_rule_states(self):
        pytest.skip("Ambiguous: list subscription rule states and determine whether states for rules linked to unreadable DID scopes are filtered or access is denied.")

    def test_list_subscriptions(self):
        pytest.skip("Filtering Test: list subscriptions and verify filtering based on the scopes in each subscription's DID filter and generated rules.")


class TestROLE:
    """
    RBAC role management (`/roles` and `/accounts/<account>/roles`). See the assumptions note at the top of this file.
    """

    # --- read-only listing, only root/admin is authorized (perm_default) ---------------------

    def test_list_roles(self):
        """RBAC(ADMIN): GET /roles/ is only visible to root/admin and lists each role with its description, assignable and protected state"""
        response = _get('/roles/', 'root')
        assert response.status_code == OK
        roles = response.json()
        assert 'data-scientist' in [role['role'] for role in roles]
        # every entry carries a description, which is null for roles without one, and its assignable and protected states
        assert all({'description', 'assignable', 'protected'} <= set(role) for role in roles)
        for account in ('alice', 'bob'):
            assert _get('/roles/', account).status_code == FORBIDDEN

    def test_list_role_permissions(self):
        """RBAC(ADMIN/USER): GET /roles/<role>/permissions is visible to root/admin and to accounts holding that role"""
        def covers_atlas(scope_pattern: str) -> bool:
            # a scope pattern is either a scope, or a prefix closed by the '*' wildcard
            return scope_pattern == 'atlas' or (scope_pattern.endswith('*') and 'atlas'.startswith(scope_pattern[:-1]))

        for account in ('root', 'alice'):
            response = _get(_role_path('data-scientist', 'permissions'), account)
            assert response.status_code == OK
            granted = {perm['operation'] for perm in response.json() if covers_atlas(perm['scope_pattern'])}
            assert {'read', 'write'} <= granted
        assert _get(_role_path('data-scientist', 'permissions'), 'bob').status_code == FORBIDDEN

    def test_list_role_accounts(self):
        """RBAC(ADMIN): GET /roles/<role>/accounts is only visible to root/admin and lists each account holding the role with its expiry date"""
        response = _get(_role_path('data-scientist', 'accounts'), 'root')
        assert response.status_code == OK
        assignments = response.json()
        assert 'alice' in [assignment['account'] for assignment in assignments]
        assert all({'account', 'expires_at'} <= set(assignment) for assignment in assignments)
        assert _get(_role_path('does-not-exist', 'accounts'), 'root').status_code == NOT_FOUND
        for account in ('alice', 'bob'):
            assert _get(_role_path('data-scientist', 'accounts'), account).status_code == FORBIDDEN

    def test_list_account_roles(self):
        """RBAC(ADMIN/USER): GET /accounts/<account>/roles is visible to root/admin and to accounts if they are querying their own roles"""
        for account in ('root', 'alice'):
            response = _get(_account_roles_path('alice'), account)
            assert response.status_code == OK
            roles = response.json()['roles']
            assert 'data-scientist' in [role['role'] for role in roles]
            # the description of each assigned role is reported alongside its expiry date
            assert all({'expires_at', 'description'} <= set(role) for role in roles)
        assert _get(_account_roles_path('bob'), account).status_code == FORBIDDEN

    # --- write operations are refused for every non-admin caller, whatever their own roles ----

    @pytest.mark.parametrize(
        ('method', 'path', 'payload'),
        [
            ('POST', _role_path('tmp_probe'), None),
            ('DELETE', _role_path('data-scientist'), None),
            ('POST', _role_path('data-scientist', 'permissions', 'read', 'atlas'), None),
            ('DELETE', _role_path('data-scientist', 'permissions', 'read', 'atlas'), None),
            ('POST', _account_roles_path('bob', 'data-scientist'), None),
            ('DELETE', _account_roles_path('alice', 'data-scientist'), None),
            ('PUT', _role_path('data-scientist'), {'protected': True}),
            ('PUT', _role_path('data-scientist'), {'assignable': False}),
        ],
        ids=['add role', 'delete role', 'add permission', 'remove permission', 'assign account role', 'unassign account role', 'protect role', 'make role unassignable'],
    )
    def test_non_admin_cannot_write_role_data(self, method, path, payload):
        """RBAC(USER): role management write operations are restricted to root/admin regardless of the caller's own RBAC assignments"""
        kwargs = {'json': payload} if payload is not None else {}
        for account in ('alice', 'bob'):
            assert _request(method, path, account, **kwargs).status_code == FORBIDDEN

    # --- lifecycle & error-code scenarios, run by root -----------------------------------

    def test_add_role_duplicate_then_delete(self):
        """RBAC(ADMIN): creating the same role twice is refused with 409, deleting it twice 404s the second time"""
        role_name = 'tmp'
        try:
            assert _post(_role_path(role_name), 'root').status_code == CREATED
            assert _post(_role_path(role_name), 'root').status_code == CONFLICT
        finally:
            assert _delete(_role_path(role_name), 'root').status_code == OK
        assert _delete(_role_path(role_name), 'root').status_code == NOT_FOUND

    def test_delete_role_refused_while_assigned_to_account(self):
        """RBAC(ADMIN): a role still assigned to an account cannot be deleted until the assignment is removed"""
        role_name = 'tmp'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert _post(_account_roles_path('alice', role_name), 'root').status_code == CREATED
            assert _delete(_role_path(role_name), 'root').status_code == CONFLICT
            assert _delete(_account_roles_path('alice', role_name), 'root').status_code == OK
        finally:
            # the assignment has to go first: a role still assigned to an account cannot be deleted
            _delete(_account_roles_path('alice', role_name), 'root')
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_delete_role_drops_its_permissions(self):
        """RBAC(ADMIN): the permissions of a role do not keep it from being deleted, they are deleted along with it"""
        role_name = 'tmp'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert _post(_role_path(role_name, 'permissions', 'write', 'root'), 'root').status_code == CREATED
            assert _delete(_role_path(role_name), 'root').status_code == OK
            assert _get(_role_path(role_name, 'permissions'), 'root').status_code == NOT_FOUND

            # a role created again under the same name does not inherit the permissions of the deleted one
            assert _post(_role_path(role_name), 'root').status_code == CREATED
            assert _get(_role_path(role_name, 'permissions'), 'root').json() == []
        finally:
            _delete(_role_path(role_name), 'root', json={'force': True})

    def test_force_delete_role_in_use(self):
        """RBAC(ADMIN): a forced deletion removes a role still assigned to accounts and carrying permissions, along with those references"""
        role_name = 'tmp_force_delete'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert _post(_role_path(role_name, 'permissions', 'write', 'root'), 'root').status_code == CREATED
            assert _post(_account_roles_path('alice', role_name), 'root').status_code == CREATED
            assert _delete(_role_path(role_name), 'root', json={'force': True}).status_code == OK

            assert _get(_role_path(role_name, 'accounts'), 'root').status_code == NOT_FOUND
            roles = _get(_account_roles_path('alice'), 'root').json()['roles']
            assert role_name not in [role['role'] for role in roles]
        finally:
            # only needed if the forced deletion failed, in which case the role is still in use
            _delete(_account_roles_path('alice', role_name), 'root')
            _delete(_role_path(role_name, 'permissions', 'write', 'root'), 'root')
            _delete(_role_path(role_name), 'root')

    def test_non_admin_cannot_force_delete_role(self):
        """RBAC(USER): a forced role deletion is restricted to root/admin like any other role deletion"""
        for account in ('alice', 'bob'):
            assert _delete(_role_path('data-scientist'), account, json={'force': True}).status_code == FORBIDDEN

    def _role_state(self, role_name: str) -> dict[str, Any]:
        """Read the listing entry of `role_name` back from GET /roles/."""
        roles = _get('/roles/', 'root').json()
        return [role for role in roles if role['role'] == role_name][0]

    def test_protect_and_unprotect_role(self):
        """RBAC(ADMIN): a role is created assignable and unprotected, and a protected role is only altered or deleted when forced"""
        role_name = 'tmp_protected'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            state = self._role_state(role_name)
            assert state['assignable'] is True and state['protected'] is False

            assert _request('PUT', _role_path(role_name), 'root', json={'protected': True}).status_code == OK
            assert self._role_state(role_name)['protected'] is True

            # a protected role can neither be altered nor deleted unless forced
            assert _request('PUT', _role_path(role_name), 'root', json={'description': 'nope'}).status_code == FORBIDDEN
            assert _delete(_role_path(role_name), 'root').status_code == FORBIDDEN
            assert _request('PUT', _role_path(role_name), 'root', json={'description': 'forced', 'force': True}).status_code == OK
            assert self._role_state(role_name)['description'] == 'forced'

            # changing the protected state itself is always allowed, so that a role can be unprotected
            assert _request('PUT', _role_path(role_name), 'root', json={'protected': False}).status_code == OK
            assert self._role_state(role_name)['protected'] is False
        finally:
            _delete(_role_path(role_name), 'root', json={'force': True})

    def test_role_assignable_state(self):
        """RBAC(ADMIN): the assignable state of a role can be toggled via PUT"""
        role_name = 'tmp_assignable'
        assert _post(_role_path(role_name), 'root', json={'assignable': False}).status_code == CREATED
        try:
            assert self._role_state(role_name)['assignable'] is False
            assert _request('PUT', _role_path(role_name), 'root', json={'assignable': True}).status_code == OK
            assert self._role_state(role_name)['assignable'] is True
        finally:
            _delete(_role_path(role_name), 'root', json={'force': True})

    # --- expiry date of a role assigned to an account -----------------------------------

    def _account_role_expires_at(self, account: str, role_name: str) -> Any:
        """Read the `expires_at` of `role_name` for `account` back from GET /accounts/<account>/roles."""
        roles = _get(_account_roles_path(account), 'root').json()['roles']
        return [role['expires_at'] for role in roles if role['role'] == role_name][0]

    def test_account_role_expires_at_lifecycle(self):
        """RBAC(ADMIN): an assignment does not expire unless an expiry date is given, which can be set on assignment, overwritten via PUT and cleared"""
        role_name = 'tmp_expiring'
        expires_at = 'Mon, 31 Jan 2028 12:00:00 UTC'
        later = 'Tue, 29 Feb 2028 12:00:00 UTC'

        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            # an assignment without an expiry date never expires
            assert _post(_account_roles_path('alice', role_name), 'root').status_code == CREATED
            assert self._account_role_expires_at('alice', role_name) is None

            # PUT sets the expiry date of an assignment that had none
            assert _request('PUT', _account_roles_path('alice', role_name), 'root', json={'expires_at': expires_at}).status_code == OK
            assert self._account_role_expires_at('alice', role_name) == expires_at

            # PUT overwrites an existing expiry date, and a null value clears it
            assert _request('PUT', _account_roles_path('alice', role_name), 'root', json={'expires_at': later}).status_code == OK
            assert self._account_role_expires_at('alice', role_name) == later
            assert _request('PUT', _account_roles_path('alice', role_name), 'root', json={'expires_at': None}).status_code == OK
            assert self._account_role_expires_at('alice', role_name) is None

            # the expiry date can be given right away when the role is assigned
            assert _delete(_account_roles_path('alice', role_name), 'root').status_code == OK
            assert _post(_account_roles_path('alice', role_name), 'root', json={'expires_at': expires_at}).status_code == CREATED
            assert self._account_role_expires_at('alice', role_name) == expires_at
        finally:
            # the assignment has to go first: a role still assigned to an account cannot be deleted
            _delete(_account_roles_path('alice', role_name), 'root')
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_expired_account_role_grants_no_scope_access(self):
        """RBAC(USER): a role only grants its permissions while its assignment has not expired"""
        role_name = 'tmp_expired_access'
        path = '/dids/alice/dids/search'
        params = {'name': '*'}

        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert _post(_role_path(role_name, 'permissions', 'read', 'alice'), 'root').status_code == CREATED
            assert _post(_account_roles_path('bob', role_name), 'root').status_code == CREATED
            # an assignment without an expiry date grants access
            assert _get(path, 'bob', params=params).status_code == OK

            # once the expiry date is in the past, the role no longer grants anything
            assert _request('PUT', _account_roles_path('bob', role_name), 'root', json={'expires_at': 'Mon, 01 Jan 2024 00:00:00 UTC'}).status_code == OK
            assert _get(path, 'bob', params=params).status_code == FORBIDDEN

            # an expiry date in the future grants access again
            assert _request('PUT', _account_roles_path('bob', role_name), 'root', json={'expires_at': 'Fri, 01 Jan 2100 00:00:00 UTC'}).status_code == OK
            assert _get(path, 'bob', params=params).status_code == OK
        finally:
            # the assignment and the permission have to go first: a role still in use cannot be deleted
            _delete(_account_roles_path('bob', role_name), 'root')
            _delete(_role_path(role_name, 'permissions', 'read', 'alice'), 'root')
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_invalid_account_role_expires_at_is_rejected(self):
        """RBAC(ADMIN): a missing or unparsable expires_at is refused with 400"""
        role_name = 'tmp_invalid_expires_at'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert _post(_account_roles_path('alice', role_name), 'root', json={'expires_at': 'not a date'}).status_code == BAD_REQUEST
            assert _post(_account_roles_path('alice', role_name), 'root').status_code == CREATED
            # 'expires_at' is mandatory on PUT, so that clearing it has to be explicit
            assert _request('PUT', _account_roles_path('alice', role_name), 'root', json={}).status_code == BAD_REQUEST
            assert _request('PUT', _account_roles_path('alice', role_name), 'root', json={'expires_at': 'not a date'}).status_code == BAD_REQUEST
            assert self._account_role_expires_at('alice', role_name) is None
        finally:
            # the assignment has to go first: a role still assigned to an account cannot be deleted
            _delete(_account_roles_path('alice', role_name), 'root')
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_set_expires_at_of_role_not_assigned_to_account_returns_not_found(self):
        """RBAC(ADMIN): setting the expiry date of a role that is not assigned to the account returns 404"""
        assert _request('PUT', _account_roles_path('bob', 'data-scientist'), 'root', json={'expires_at': None}).status_code == NOT_FOUND

    def test_non_admin_cannot_set_account_role_expires_at(self):
        """RBAC(USER): setting the expiry date of an account's role is restricted to root/admin"""
        for account in ('alice', 'bob'):
            assert _request('PUT', _account_roles_path('alice', 'data-scientist'), account, json={'expires_at': None}).status_code == FORBIDDEN

    # --- role descriptions -------------------------------------------------------------

    def _role_description(self, role_name: str) -> Any:
        """Read the description of `role_name` back from GET /roles/."""
        roles = _get('/roles/', 'root').json()
        return [role['description'] for role in roles if role['role'] == role_name][0]

    def test_role_description_is_optional_on_add(self):
        """RBAC(ADMIN): a role added without a description has a null description"""
        role_name = 'tmp_no_description'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert self._role_description(role_name) is None
        finally:
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_role_description_lifecycle(self):
        """RBAC(ADMIN): a description can be set on add, overwritten via PUT and cleared with an empty string"""
        role_name = 'tmp_described'
        assert _post(_role_path(role_name), 'root', json={'description': 'Initial description'}).status_code == CREATED
        try:
            assert self._role_description(role_name) == 'Initial description'

            # PUT overwrites the existing description
            assert _request('PUT', _role_path(role_name), 'root', json={'description': 'Overwritten description'}).status_code == OK
            assert self._role_description(role_name) == 'Overwritten description'

            # an empty description clears the field
            assert _request('PUT', _role_path(role_name), 'root', json={'description': ''}).status_code == OK
            assert self._role_description(role_name) is None

            # a role that has no description can be described afterwards, surrounding whitespace is trimmed
            assert _request('PUT', _role_path(role_name), 'root', json={'description': '  Trimmed description  '}).status_code == OK
            assert self._role_description(role_name) == 'Trimmed description'

            # a whitespace-only description clears the field too
            assert _request('PUT', _role_path(role_name), 'root', json={'description': '   '}).status_code == OK
            assert self._role_description(role_name) is None
        finally:
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_role_description_is_reported_for_assigned_roles(self):
        """RBAC(ADMIN): GET /accounts/<account>/roles reports the description of each assigned role"""
        role_name = 'tmp_described_assignment'
        assert _post(_role_path(role_name), 'root', json={'description': 'Assigned role description'}).status_code == CREATED
        try:
            assert _post(_account_roles_path('alice', role_name), 'root').status_code == CREATED
            roles = _get(_account_roles_path('alice'), 'root').json()['roles']
            assert [role['description'] for role in roles if role['role'] == role_name] == ['Assigned role description']
            assert _delete(_account_roles_path('alice', role_name), 'root').status_code == OK
        finally:
            # the assignment has to go first: a role still assigned to an account cannot be deleted
            _delete(_account_roles_path('alice', role_name), 'root')
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_invalid_role_description_is_rejected(self):
        """RBAC(ADMIN): a non-string description is refused with 400, while a PUT without any field leaves the role untouched"""
        role_name = 'tmp_invalid_description'
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            # PUT only changes the fields it is given, so that clearing the description has to be explicit
            assert _request('PUT', _role_path(role_name), 'root', json={}).status_code == OK
            assert _request('PUT', _role_path(role_name), 'root', json={'description': 42}).status_code == BAD_REQUEST
            assert self._role_description(role_name) is None
        finally:
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_long_role_description_is_accepted(self):
        """RBAC(ADMIN): `roles.description` is an unbounded text column, so long descriptions are stored as-is"""
        role_name = 'tmp_long_description'
        long_description = 'x' * 4096
        assert _post(_role_path(role_name), 'root', json={'description': long_description}).status_code == CREATED
        try:
            assert self._role_description(role_name) == long_description
        finally:
            assert _delete(_role_path(role_name), 'root').status_code == OK

    def test_set_description_of_nonexistent_role_returns_not_found(self):
        """RBAC(ADMIN): describing a role that does not exist returns 404"""
        assert _request('PUT', _role_path('non_existing_role'), 'root', json={'description': 'nope'}).status_code == NOT_FOUND

    def test_non_admin_cannot_set_role_description(self):
        """RBAC(USER): setting a role description is restricted to root/admin"""
        for account in ('alice', 'bob'):
            assert _request('PUT', _role_path('data-scientist'), account, json={'description': 'nope'}).status_code == FORBIDDEN

    @pytest.mark.parametrize(
        ('method', 'path'),
        [
            ('DELETE', _role_path('non_existing_role')),
            ('POST', _account_roles_path('alice', 'non_existing_role')),
            ('POST', _account_roles_path('non_existing_account', 'data-scientist')),
            ('DELETE', _account_roles_path('bob', 'data-scientist')),
            ('POST', _role_path('non_existing_role', 'permissions', 'read', 'atlas')),
            ('DELETE', _role_path('data-scientist', 'permissions', 'read', 'root')),
        ],
        ids=[
            'delete non-existing role',
            'assign non-existing role to account',
            'assign role to non-existing account',
            'unassign role not assigned to account',
            'add permission to non-existing role',
            'remove permission not granted to role',
        ],
    )
    def test_operations_on_nonexistent_targets_return_not_found(self, method, path):
        """RBAC(ADMIN): referencing a non-existing role, account or assignment returns 404"""
        assert _request(method, path, 'root').status_code == NOT_FOUND

    def test_permission_on_scope_pattern_without_existing_scope(self):
        """RBAC(ADMIN): a scope pattern is not checked against the existing scopes, so that it also covers scopes created later"""
        role_name = 'tmp_future_scope'
        scope_pattern = 'rbac_future_%s' % uuid4().hex[:12]
        assert _post(_role_path(role_name), 'root').status_code == CREATED
        try:
            assert _post(_role_path(role_name, 'permissions', 'read', scope_pattern), 'root').status_code == CREATED
            permissions = _get(_role_path(role_name, 'permissions'), 'root').json()
            assert [(perm['operation'], perm['scope_pattern']) for perm in permissions] == [('read', scope_pattern)]
        finally:
            _delete(_role_path(role_name), 'root', json={'force': True})

    @pytest.mark.parametrize('scope_pattern', ['*atlas', 'at*las', 'at**'], ids=['leading wildcard', 'embedded wildcard', 'several wildcards'])
    def test_invalid_scope_pattern_is_rejected(self, scope_pattern):
        """RBAC(ADMIN): a '*' is only accepted on its own or closing a scope pattern"""
        assert _post(_role_path('data-scientist', 'permissions', 'read', quote_plus(scope_pattern)), 'root').status_code == BAD_REQUEST

    @pytest.mark.parametrize(
        'path',
        [
            _role_path('data-scientist'),
            _role_path('data-scientist', 'permissions', 'read', 'atlas'),
            _role_path('data-scientist', 'permissions', 'write', 'atlas'),
            _account_roles_path('alice', 'data-scientist'),
        ],
        ids=['duplicate role', 'duplicate read permission', 'duplicate write permission', 'duplicate account role assignment'],
    )
    def test_operations_on_already_existing_targets_return_conflict(self, path):
        """RBAC(ADMIN): re-creating an already-existing role, permission or account role assignment returns 409"""
        # the target is expected to exist already (see the assumptions at the top of this file),
        # in which case this first call is the duplicate and answers 409. Should it not exist,
        # it is created here and removed again in the cleanup below, so that the test leaves the
        # database as it found it either way.
        created = _post(path, 'root').status_code == CREATED
        try:
            assert _post(path, 'root').status_code == CONFLICT
        finally:
            if created:
                assert _delete(path, 'root').status_code == OK
