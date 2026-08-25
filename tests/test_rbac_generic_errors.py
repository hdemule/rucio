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

# To run a single test, use `pytest tests/test_rbac_generic_errors.py::TestDID::test_get_did`

import re
from typing import Any
from urllib.parse import quote_plus

import pytest
import requests

from rucio.common.config import config_get
from rucio.common.types import InternalScope
from rucio.core.rule import list_rules

FORBIDDEN = 403

_USERNAMES = {'root': 'ddmlab', 'alice': 'alice', 'bob': 'bob'}
_PASSWORD = 'secret'
_ACCOUNTS = ('root', 'alice', 'bob')


def _auth_host() -> str:
    return config_get('client', 'auth_host')


def _rucio_host() -> str:
    return config_get('client', 'rucio_host')


def _ca_cert() -> str:
    return config_get('test', 'cacert')


def _get_token(account: str) -> str:
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
    headers = {
        'Accept': 'application/json, application/x-json-stream',
        'X-Rucio-Auth-Token': _get_token(account),
    }
    headers.update(kwargs.pop('headers', {}))
    response = requests.request(
        method,
        f'{_rucio_host()}{path}',
        headers=headers,
        verify=_ca_cert(),
        **kwargs,
    )
    return response


def _get(path: str, account: str, **kwargs: Any) -> requests.Response:
    return _request('GET', path, account, **kwargs)


def _post(path: str, account: str, **kwargs: Any) -> requests.Response:
    return _request('POST', path, account, **kwargs)


def _scope_name_path(resource: str, did: str, *suffix: str) -> str:
    scope, name = did.split(':', 1)
    return '/'.join(['', resource, quote_plus(scope), quote_plus(name), *suffix])


def _did_path(did: str, *suffix: str) -> str:
    return _scope_name_path('dids', did, *suffix)


def _get_rule_id(name: str, vo: str, user: str = 'alice') -> str:
    scope = InternalScope(user, vo=vo)
    rules = list(list_rules(filters={'scope': scope, 'name': name}))
    assert rules, f'No replication rule found for {user}:{name}'
    return rules[0]['id']


def _error_signature(response: requests.Response) -> tuple[str, str]:
    try:
        error = response.json()
    except ValueError:
        return '', response.text

    message = error.get('ExceptionMessage', '')
    message = re.sub(r"Rule ID '[^']+'", "Rule ID '{rule_id}'", message)
    message = re.sub(r'(?i)(account )[^ .]+', r'\1{account}', message)
    message = re.sub(r'(?i)(scope )[^ .]+', r'\1{scope}', message)
    message = re.sub(r'(?i)(DID )[^ .]+', r'\1{did}', message)
    return error.get('ExceptionClass', ''), message


@pytest.fixture(scope='module')
def generic_error() -> tuple[str, str]:
    response = _post(
        '/dids/bulkfiles',
        'alice',
        json={'dids': [{'scope': 'root', 'name': 'file1'}]},
    )
    assert response.status_code == FORBIDDEN, (
        f'Canonical forbidden request returned {response.status_code}, expected {FORBIDDEN}. '
        f'Response body: {response.text!r}'
    )
    return _error_signature(response)


def _assert_generic_error(response: requests.Response, generic_error: tuple[str, str], description: str) -> None:
    actual_error = _error_signature(response)
    assert response.status_code == FORBIDDEN, (
        f'{description} returned HTTP {response.status_code}, expected {FORBIDDEN}. '
        f'Response body: {response.text!r}'
    )
    assert actual_error == generic_error, (
        f'{description} returned a different generic error.\n'
        f'Expected normalized error: {generic_error!r}\n'
        f'Actual normalized error: {actual_error!r}\n'
        f'Actual response body: {response.text!r}'
    )


class TestDID:
    @pytest.mark.parametrize(
        ('account', 'payload'),
        [
            ('alice', {'dids': [{'scope': 'root', 'name': 'file1'}]}),
            ('bob', {'dids': [{'scope': 'alice', 'name': 'file1.png'}]}),
        ],
        ids=['unauthorized scope', 'other account'],
    )
    def test_bulk_list_files(self, generic_error, account, payload):
        _assert_generic_error(_post('/dids/bulkfiles', account, json=payload), generic_error, f'bulk files as {account}')

    @pytest.mark.parametrize(
        ('suffix', 'did', 'account', 'params'),
        [
            ('status', 'alice:alice_ds', 'bob', {'dynamic_depth': 'DATASET'}),
            ('status', 'non_existing_scope:file1.png', 'alice', {'dynamic_depth': 'DATASET'}),
            ('status', 'non_existing_scope:file1.png', 'bob', {'dynamic_depth': 'DATASET'}),
            ('status', 'alice:non_existing_file.png', 'bob', {'dynamic_depth': 'DATASET'}),
            ('rules', 'alice:alice_ds', 'bob', {}),
            ('rules', 'non_existing_scope:file1.png', 'alice', {}),
            ('rules', 'non_existing_scope:file1.png', 'bob', {}),
            ('rules', 'alice:non_existing_file.png', 'bob', {}),
        ],
        ids=['status other account', 'status bad scope', 'status bad scope other account', 'status missing DID', 'rules other account', 'rules bad scope', 'rules bad scope other account', 'rules missing DID'],
    )
    def test_get_did(self, generic_error, suffix, did, account, params):
        _assert_generic_error(_get(_did_path(did, suffix), account, params=params), generic_error, f'get DID {suffix} for {did} as {account}')

    @pytest.mark.parametrize(
        ('did', 'account'),
        [
            ('alice:alice_ds', 'bob'),
            ('non_existing_scope:file1.png', 'alice'),
            ('non_existing_scope:file1.png', 'bob'),
            ('alice:non_existing_file.png', 'bob'),
        ],
        ids=['other account', 'bad scope', 'bad scope other account', 'missing DID other account'],
    )
    def test_get_metadata(self, generic_error, did, account):
        _assert_generic_error(_get(_did_path(did, 'meta'), account), generic_error, f'get metadata for {did} as {account}')

    @pytest.mark.parametrize(
        ('account', 'payload'),
        [
            ('bob', {'dids': [{'scope': 'alice', 'name': 'alice_ds'}, {'scope': 'alice', 'name': 'alice_ds2'}], 'type': 'dataset'}),
            ('alice', {'dids': [{'scope': 'non_existing_scope', 'name': 'alice_ds'}], 'type': 'dataset'}),
            ('bob', {'dids': [{'scope': 'alice', 'name': 'non_existing_ds'}], 'type': 'dataset'}),
        ],
        ids=['other account', 'bad scope', 'missing DID'],
    )
    def test_get_metadata_bulk(self, generic_error, account, payload):
        _assert_generic_error(_post('/dids/bulkmeta', account, json=payload), generic_error, f'bulk metadata as {account}')

    @pytest.mark.parametrize(
        ('endpoint', 'did', 'account'),
        [
            ('content', 'alice:alice_ds', 'bob'), ('content', 'non_existing_scope:file1.png', 'alice'),
            ('files', 'alice:alice_ds', 'bob'), ('files', 'non_existing_scope:file1.png', 'alice'),
            ('parents', 'alice:file1.png', 'bob'), ('parents', 'non_existing_scope:file1.png', 'alice'),
            ('history', 'alice:file1.png', 'bob'), ('history', 'non_existing_scope:file1.png', 'alice'),
            ('search', 'alice', 'bob'), ('search', 'non_existing_scope', 'alice'),
        ],
        ids=['content other account', 'content bad scope', 'files other account', 'files bad scope', 'parents other account', 'parents bad scope', 'history other account', 'history bad scope', 'search other account', 'search bad scope'],
    )
    def test_did_listing(self, generic_error, endpoint, did, account):
        if endpoint == 'search':
            response = _get(f'/dids/{did}/dids/search', account, params={'name': '*'})
        elif endpoint == 'history':
            response = _get(_did_path(did, 'dids', 'history'), account)
        else:
            response = _get(_did_path(did, endpoint), account)
        _assert_generic_error(response, generic_error, f'{endpoint} for {did} as {account}')


class TestLOCK:
    @pytest.mark.parametrize(
        ('did', 'account'),
        [
            ('alice:file1.png', 'bob'), ('non_existing_scope:file1.png', 'alice'),
            ('non_existing_scope:file1.png', 'bob'), ('alice:non_existing_file.png', 'bob'),
        ],
        ids=['other account', 'bad scope', 'bad scope other account', 'missing DID other account'],
    )
    def test_get_dataset_locks(self, generic_error, did, account):
        response = _get(_scope_name_path('locks', did), account, params={'did_type': 'dataset'})
        _assert_generic_error(response, generic_error, f'dataset locks for {did} as {account}')

    @pytest.mark.parametrize(
        ('scope', 'account'),
        [('alice', 'bob'), ('non_existing_scope', 'alice'), ('non_existing_scope', 'bob')],
        ids=['other account', 'bad scope', 'bad scope other account'],
    )
    def test_get_dataset_locks_bulk(self, generic_error, scope, account):
        payload = {'dids': [{'scope': scope, 'name': 'file1.png', 'type': 'dataset'}]}
        _assert_generic_error(_post('/locks/bulk_locks_for_dids', account, json=payload), generic_error, f'bulk locks for {scope} as {account}')

    @pytest.mark.parametrize(
        ('rule_case', 'account'),
        [('root-owned rule', 'alice'), ('root-owned rule', 'bob'), ('nonexistent rule', 'alice'), ('nonexistent rule', 'bob')],
        ids=['root-owned rule alice', 'root-owned rule bob', 'nonexistent rule alice', 'nonexistent rule bob'],
    )
    def test_get_dataset_locks_for_rule_id(self, generic_error, vo, rule_case, account):
        rule_id = _get_rule_id('file1.png', vo, 'root') if rule_case == 'root-owned rule' else 'non-existent-rule-id'
        _assert_generic_error(_get(f'/rules/{rule_id}/locks', account), generic_error, f'rule locks ({rule_case}) as {account}')


class TestREPLICA:
    @pytest.mark.parametrize(
        ('endpoint', 'did', 'account'),
        [
            ('datasets', 'alice:alice_ds', 'bob'), ('datasets', 'non_existing_scope:alice_ds', 'alice'),
            ('datasets_vp', 'alice:alice_ds', 'bob'), ('datasets_vp', 'non_existing_scope:alice_ds', 'alice'),
            ('list', 'alice:file1.png', 'bob'), ('list', 'non_existing_scope:file1.png', 'alice'),
        ],
        ids=['datasets other account', 'datasets bad scope', 'datasets VP other account', 'datasets VP bad scope', 'list other account', 'list bad scope'],
    )
    def test_replicas(self, generic_error, endpoint, did, account):
        if endpoint == 'list':
            scope, name = did.split(':', 1)
            response = _post('/replicas/list', account, json={'dids': [{'scope': scope, 'name': name}]})
        else:
            response = _get(_scope_name_path('replicas', did, endpoint), account)
        _assert_generic_error(response, generic_error, f'replicas {endpoint} for {did} as {account}')


class TestRULE:
    @pytest.mark.parametrize(
        ('endpoint', 'did', 'account'),
        [
            ('analysis', 'root:file1.png', 'alice'), ('analysis', 'root:file1.png', 'bob'),
            ('details', 'root:file1.png', 'alice'), ('details', 'root:file1.png', 'bob'),
            ('history', 'alice:file1.png', 'bob'), ('history', 'non_existing_scope:file1.png', 'alice'),
            ('associated', 'alice:file1.png', 'bob'), ('associated', 'non_existing_scope:file1.png', 'alice'),
        ],
        ids=['analysis root-owned rule alice', 'analysis root-owned rule bob', 'details root-owned rule alice', 'details root-owned rule bob', 'history other account', 'history bad scope', 'associated other account', 'associated bad scope'],
    )
    def test_rules(self, generic_error, vo, endpoint, did, account):
        if endpoint in ('analysis', 'details'):
            rule_id = _get_rule_id('file1.png', vo, 'root')
            path = f'/rules/{rule_id}/analysis' if endpoint == 'analysis' else f'/rules/{rule_id}'
        elif endpoint == 'history':
            path = _scope_name_path('rules', did, 'history')
        else:
            path = _did_path(did, 'associated_rules')
        _assert_generic_error(_get(path, account), generic_error, f'rules {endpoint} for {did} as {account}')
