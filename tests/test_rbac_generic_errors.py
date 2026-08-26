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
from typing import Any, Optional
from urllib.parse import quote_plus

import pytest
import requests

from rucio.common.config import config_get
from rucio.common.types import InternalScope
from rucio.core.rule import list_rules

FORBIDDEN = 403

_ANSI_GREEN = '\033[92m'
_ANSI_RESET = '\033[0m'

_USERNAMES = {'root': 'ddmlab', 'alice': 'alice', 'bob': 'bob'}
_PASSWORD = 'secret'
_ACCOUNTS = ('root', 'alice', 'bob')
_DID_TOKEN_PATTERN = r'[\w.-]+:[\w./-]+'
_RULE_ID_TOKEN_PATTERN = r'[A-Za-z0-9-]+'


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
    url = f'{_rucio_host()}{path}'
    response = requests.request(
        method,
        url,
        headers=headers,
        verify=_ca_cert(),
        **kwargs,
    )
    # Attach request context so assertion errors can print reproducible request details.
    setattr(response, '_rbac_request_context', {
        'method': method,
        'url': url,
        'path': path,
        'account': account,
        'params': kwargs.get('params'),
        'json': kwargs.get('json'),
        'status_code': response.status_code,
    })
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


def _context_placeholders(response: requests.Response) -> dict[str, Optional[str]]:
    placeholders: dict[str, Optional[str]] = {'account': None, 'did': None, 'scope': None, 'rule_id': None}
    context = getattr(response, '_rbac_request_context', None)
    if isinstance(context, dict) and isinstance(context.get('account'), str):
        placeholders['account'] = context['account']

    context_did, context_scope = _did_scope_from_request_context(response)
    placeholders['did'] = context_did
    placeholders['scope'] = context_scope
    placeholders['rule_id'] = _rule_id_from_request_context(response)
    return placeholders


def _error_signature(response: requests.Response) -> tuple[str, str]:
    try:
        error = response.json()
    except ValueError:
        return '', response.text

    message = error.get('ExceptionMessage', '')

    # First, normalize by replacing concrete values derived from request context.
    placeholders = _context_placeholders(response)
    for key in ('did', 'rule_id', 'account', 'scope'):
        value = placeholders.get(key)
        if value:
            message = re.sub(re.escape(value), '{' + key + '}', message)

    # Then apply lightweight fallbacks for messages where values are not present in context.
    message = re.sub(r"Rule ID '[^']+'", "Rule ID '{rule_id}'", message)
    message = re.sub(
        r'(?i)(replication rule (?:with id |id ))(' + _RULE_ID_TOKEN_PATTERN + r')(?=[.,;]?(?:\s|$)|$)',
        r'\1{rule_id}',
        message,
    )
    message = re.sub(
        r'(?i)(replication rule )(' + _RULE_ID_TOKEN_PATTERN + r')(?=[.,;](?:\s|$)|$)',
        r'\1{rule_id}',
        message,
    )
    message = re.sub(r'(?i)(account )([^\s,]+?)(?=[.,;]?(?:\s|$))', r'\1{account}', message)
    message = re.sub(r'(?i)(scope )([^\s,]+?)(?=[.,;]?(?:\s|$))', r'\1{scope}', message)
    message = re.sub(r'(?i)(data identifier )(' + _DID_TOKEN_PATTERN + r')(?=[.,;]?(?:\s|$))', r'\1{did}', message)
    message = re.sub(r'(?i)(DID )(' + _DID_TOKEN_PATTERN + r')(?=[.,;]?(?:\s|$))', r'\1{did}', message)
    message = re.sub(r'\b' + _DID_TOKEN_PATTERN + r'\b', '{did}', message)
    return error.get('ExceptionClass', ''), message


def _did_scope_from_request_context(response: requests.Response) -> tuple[Optional[str], Optional[str]]:
    context = getattr(response, '_rbac_request_context', None)
    if not context:
        return None, None

    payload = context.get('json') if isinstance(context, dict) else None
    if isinstance(payload, dict):
        dids = payload.get('dids')
        if isinstance(dids, list) and dids and isinstance(dids[0], dict):
            first = dids[0]
            scope = first.get('scope')
            name = first.get('name')
            if isinstance(scope, str) and isinstance(name, str):
                return f'{scope}:{name}', scope

    path = context.get('path') if isinstance(context, dict) else None
    if not isinstance(path, str):
        return None, None

    did_endpoint_match = re.match(r'^/dids/([^/]+)/([^/]+)/(status|rules|meta|dids|files|parents|associated_rules|history)$', path)
    if did_endpoint_match:
        scope = did_endpoint_match.group(1)
        name = did_endpoint_match.group(2)
        return f'{scope}:{name}', scope

    lock_replica_match = re.match(r'^/(locks|replicas)/([^/]+)/([^/]+)(?:/|$)', path)
    if lock_replica_match:
        scope = lock_replica_match.group(2)
        name = lock_replica_match.group(3)
        return f'{scope}:{name}', scope

    rules_history_match = re.match(r'^/rules/([^/]+)/([^/]+)/history$', path)
    if rules_history_match:
        scope = rules_history_match.group(1)
        name = rules_history_match.group(2)
        return f'{scope}:{name}', scope

    return None, None


def _rule_id_from_request_context(response: requests.Response) -> Optional[str]:
    context = getattr(response, '_rbac_request_context', None)
    if not isinstance(context, dict):
        return None

    path = context.get('path')
    if not isinstance(path, str):
        return None

    # /rules/<scope>/<name>/history is DID history endpoint, not a rule_id endpoint.
    if re.match(r'^/rules/[^/]+/[^/]+/history$', path):
        return None

    rule_match = re.match(r'^/rules/([^/]+)(?:/|$)', path)
    if rule_match:
        return rule_match.group(1)
    return None


def _extract_placeholders(response: requests.Response) -> dict[str, Optional[str]]:
    placeholders = _context_placeholders(response)
    try:
        error = response.json()
    except ValueError:
        return placeholders

    message = error.get('ExceptionMessage', '')

    if placeholders['account'] is None:
        account_match = re.search(r'(?i)\baccount\s+([^\s]+)', message)
        if account_match:
            placeholders['account'] = account_match.group(1).rstrip('.,;')

    if placeholders['did'] is None:
        did_match = re.search(r'(?i)\bdata identifier\s+(' + _DID_TOKEN_PATTERN + r')\b', message)
        if not did_match:
            did_match = re.search(r'(?i)\bDID\s+(' + _DID_TOKEN_PATTERN + r')\b', message)
        if not did_match:
            did_match = re.search(r'\b(' + _DID_TOKEN_PATTERN + r')\b', message)
        if did_match:
            placeholders['did'] = did_match.group(1).rstrip('.,;')

    if placeholders['rule_id'] is None:
        rule_id_match = re.search(
            r'(?i)\breplication rule (?:with id |id )(' + _RULE_ID_TOKEN_PATTERN + r')(?=[.,;]?(?:\s|$)|$)',
            message,
        )
        if not rule_id_match:
            rule_id_match = re.search(
                r'(?i)\breplication rule\s+(' + _RULE_ID_TOKEN_PATTERN + r')(?=[.,;](?:\s|$)|$)',
                message,
            )
        if not rule_id_match:
            rule_id_match = re.search(r"Rule ID '\s*([^']+?)\s*'", message)
        if rule_id_match:
            placeholders['rule_id'] = rule_id_match.group(1).rstrip('.,;')

    if placeholders['scope'] is None:
        scope_match = re.search(r'(?i)\bscope\s+([^\s]+)', message)
        if scope_match:
            placeholders['scope'] = scope_match.group(1).rstrip('.,;')
        elif placeholders['did'] and ':' in placeholders['did']:
            placeholders['scope'] = placeholders['did'].split(':', 1)[0]

    return placeholders


def _format_request_context(response: requests.Response) -> str:
    context = getattr(response, '_rbac_request_context', None)
    if not context:
        return 'Request context: unavailable'

    lines = [
        'Request context:',
        f"  command: {context['method']} {context['path']}",
        f"  account: {context['account']}",
        f"  params: {context['params']!r}",
        f"  json: {context['json']!r}",
        f"  status: {context['status_code']}",
    ]
    return '\n'.join(lines)


def _request_context_values(response: requests.Response) -> dict[str, Any]:
    context = getattr(response, '_rbac_request_context', None)
    if not context:
        return {
            'method': '<unknown>',
            'path': '<unknown>',
            'account': '<unknown>',
            'params': None,
            'json': None,
            'status_code': response.status_code,
        }
    return {
        'method': context.get('method', '<unknown>'),
        'path': context.get('path', '<unknown>'),
        'account': context.get('account', '<unknown>'),
        'params': context.get('params'),
        'json': context.get('json'),
        'status_code': context.get('status_code', response.status_code),
    }


def _format_request_context_pair(response1: requests.Response, response2: requests.Response) -> str:
    context1 = _request_context_values(response1)
    context2 = _request_context_values(response2)
    return '\n'.join([
        'Request context:',
        f"  command1: {context1['method']} {context1['path']}",
        f"  command2: {context2['method']} {context2['path']}",
        f"  account1: {context1['account']!r}",
        f"  account2: {context2['account']!r}",
        f"  params1: {context1['params']!r}",
        f"  params2: {context2['params']!r}",
        f"  json1: {context1['json']!r}",
        f"  json2: {context2['json']!r}",
        f"  status1: {context1['status_code']!r}",
        f"  status2: {context2['status_code']!r}",
    ])


def _format_pass_summary_line(description: str, response: requests.Response) -> str:
    context = _request_context_values(response)
    error_class, error_message = _error_signature(response)
    placeholders = _extract_placeholders(response)

    mapping_parts = []
    for key in ('account', 'did', 'scope', 'rule_id'):
        value = placeholders.get(key)
        if value is not None:
            mapping_parts.append(f'{key}={value}')

    mapping_line = (
        f'{_ANSI_GREEN}    mapping : ' + ' | '.join(mapping_parts) + f'{_ANSI_RESET}'
        if mapping_parts
        else f'{_ANSI_GREEN}    mapping :{_ANSI_RESET}'
    )

    return '\n'.join([
        f'{_ANSI_GREEN}  - {description}{_ANSI_RESET}',
        f'{_ANSI_GREEN}    request : {context["method"]} {context["path"]}{_ANSI_RESET}',
        f'{_ANSI_GREEN}    status  : {context["status_code"]}{_ANSI_RESET}',
        mapping_line,
        f'{_ANSI_GREEN}    response: {error_class}: {error_message}{_ANSI_RESET}',
    ])


def _assert_forbidden(response: requests.Response, description: str) -> None:
    if response.status_code != FORBIDDEN:
        pytest.fail(
            f'{description} returned HTTP {response.status_code}, expected {FORBIDDEN}.\n'
            f'Actual response body: {response.text!r}\n'
            f'{_format_request_context(response)}'
        )


def _assert_same_generic_error(
    response1: requests.Response,
    description1: str,
    response2: requests.Response,
    description2: str,
) -> None:
    error1 = _error_signature(response1)
    error2 = _error_signature(response2)
    placeholders1 = _extract_placeholders(response1)
    placeholders2 = _extract_placeholders(response2)

    keys_to_show = [
        key for key in ('account', 'did', 'scope', 'rule_id')
        if placeholders1.get(key) is not None or placeholders2.get(key) is not None
    ]
    placeholders_lines = ['Placeholders:']
    for key in keys_to_show:
        placeholders_lines.append(f"  {key}1: {placeholders1.get(key)!r}")
        placeholders_lines.append(f"  {key}2: {placeholders2.get(key)!r}")
    placeholders_text = '\n'.join(placeholders_lines)

    if error1 != error2:
        pytest.fail(
            f'{"=" * 54}\n'
            f'Pairwise generic error mismatch.\n'
            f'  Request 1: {description1}\n'
            f'  Request 2: {description2}\n'
            f'{"-" * 75}\n'
            f'  Expected class (R1): {error1[0]!r}\n'
            f'  Actual class (R2): {error2[0]!r}\n'
            f'{"-" * 75}\n'
            f'  Expected message (R1): {error1[1]!r}\n'
            f'  Actual message (R2): {error2[1]!r}\n'
            f'{"-" * 75}\n'
            f'{placeholders_text}\n'
            f'{"-" * 75}\n'
            f'{_format_request_context_pair(response1, response2)}\n'
            f'{"=" * 54}'
        )


def _assert_generic_error_chain(responses: list[tuple[requests.Response, str]], summary_label: str) -> None:
    assert len(responses) >= 2, 'Need at least two requests for pairwise comparison'
    previous_response, previous_description = responses[0]
    _assert_forbidden(previous_response, previous_description)

    for current_response, current_description in responses[1:]:
        _assert_forbidden(current_response, current_description)
        _assert_same_generic_error(previous_response, previous_description, current_response, current_description)
        previous_response, previous_description = current_response, current_description

    print(f'{_ANSI_GREEN}PASS summary [{summary_label}]{_ANSI_RESET}')
    print(f'{_ANSI_GREEN}{"=" * 96}{_ANSI_RESET}')
    for response, description in responses:
        print(_format_pass_summary_line(description, response))
        print(f'{_ANSI_GREEN}{"-" * 96}{_ANSI_RESET}')


class TestDID:
    def test_bulk_list_files(self):
        cases = [
            ('unauthorized scope', 'alice', {'dids': [{'scope': 'root', 'name': 'file1.png'}]}),
            ('other account', 'bob', {'dids': [{'scope': 'alice', 'name': 'file1.png'}]}),
        ]
        responses = [
            (_post('/dids/bulkfiles', account, json=payload), f'bulk files [{case_id}] as {account}')
            for case_id, account, payload in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_bulk_list_files')

    def test_dataset_by_guid(self):
        pytest.skip("Ambiguous Test: Either Deny if scope associated to dataset is wrong, but if it's ok, maybe verify results are filtered according to the caller's readable scopes; also cover an unknown GUID.")

    def test_get_did(self):
        status_cases = [
            ('status other account', 'status', 'alice:alice_ds', 'bob', {'dynamic_depth': 'DATASET'}),
            ('status bad scope', 'status', 'non_existing_scope:file1.png', 'alice', {'dynamic_depth': 'DATASET'}),
            ('status bad scope other account', 'status', 'non_existing_scope:file1.png', 'bob', {'dynamic_depth': 'DATASET'}),
            ('status missing DID', 'status', 'alice:non_existing_file.png', 'bob', {'dynamic_depth': 'DATASET'}),
        ]
        status_responses = [
            (_get(_did_path(did, suffix), account, params=params), f'get DID [{case_id}] for {did} as {account}')
            for case_id, suffix, did, account, params in status_cases
        ]
        _assert_generic_error_chain(status_responses, 'TestDID.test_get_did.status')

        rules_cases = [
            ('rules other account', 'rules', 'alice:alice_ds', 'bob', {}),
            ('rules bad scope', 'rules', 'non_existing_scope:file1.png', 'alice', {}),
            ('rules bad scope other account', 'rules', 'non_existing_scope:file1.png', 'bob', {}),
            ('rules missing DID', 'rules', 'alice:non_existing_file.png', 'bob', {}),
        ]
        rules_responses = [
            (_get(_did_path(did, suffix), account, params=params), f'get DID [{case_id}] for {did} as {account}')
            for case_id, suffix, did, account, params in rules_cases
        ]
        _assert_generic_error_chain(rules_responses, 'TestDID.test_get_did.rules')

    def test_get_metadata(self):
        cases = [
            ('other account', 'alice:alice_ds', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = [
            (_get(_did_path(did, 'meta'), account), f'get metadata [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_get_metadata')

    def test_get_metadata_bulk(self):
        cases = [
            ('other account', 'bob', {'dids': [{'scope': 'alice', 'name': 'alice_ds'}, {'scope': 'alice', 'name': 'alice_ds2'}], 'type': 'dataset'}),
            ('bad scope', 'alice', {'dids': [{'scope': 'non_existing_scope', 'name': 'alice_ds'}], 'type': 'dataset'}),
            ('missing DID', 'bob', {'dids': [{'scope': 'alice', 'name': 'non_existing_ds'}], 'type': 'dataset'}),
        ]
        responses = [
            (_post('/dids/bulkmeta', account, json=payload), f'bulk metadata [{case_id}] as {account}')
            for case_id, account, payload in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_get_metadata_bulk')

    def test_get_users_following_did(self):
        pytest.skip("Filtering Test: query followers of a DID owned by alice and verify root/alice access, bob denial, and the response for an unknown scope or DID.")

    def test_list_archive_content(self):
        pytest.skip("Filtering Test: list the files in an archive by scope and name, verifying results are filtered for an unauthorized scope and covering unknown scope/DID behavior.")

    def test_list_content(self):
        cases = [
            ('other account', 'alice:alice_ds', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_ds', 'bob'),
        ]
        responses = [
            (_get(_did_path(did, 'dids'), account), f'list content [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_list_content')

    def test_list_content_history(self):
        cases = [
            ('other account', 'alice:file1.png', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = [
            (_get(_did_path(did, 'dids', 'history'), account), f'list content history [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_list_content_history')

    def test_list_dids(self):
        cases = [
            ('other account', 'alice', 'bob'),
            ('bad scope', 'non_existing_scope', 'alice'),
            ('bad scope other account', 'non_existing_scope', 'bob'),
        ]
        responses = [
            (_get(f'/dids/{scope}/dids/search', account, params={'name': '*'}), f'list dids [{case_id}] for {scope} as {account}')
            for case_id, scope, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_list_dids')

    def test_list_files(self):
        cases = [
            ('other account', 'alice:alice_ds', 'bob'),
            ('bad scope', 'non_existing_scope:alice_ds', 'alice'),
            ('bad scope other account', 'non_existing_scope:alice_ds', 'bob'),
            ('missing DID other account', 'alice:non_existing_ds', 'bob'),
        ]
        responses = [
            (_get(_did_path(did, 'files'), account), f'list files [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_list_files')

    def test_list_new_dids(self):
        pytest.skip("Filtering Test: list newly created DIDs and verify that returned DIDs are filtered according to each account's readable scopes.")

    def test_list_parent_dids(self):
        cases = [
            ('other account', 'alice:file1.png', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = [
            (_get(_did_path(did, 'parents'), account), f'list parent dids [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestDID.test_list_parent_dids')

    def test_scope_list(self):
        pytest.skip("Filtering Test: retrieve a DID by scope and verify results for readable and unreadable scopes; cover an unknown scope and DID.")


class TestLOCK:
    def test_get_dataset_locks(self):
        cases = [
            ('other account', 'alice:file1.png', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = [
            (_get(_scope_name_path('locks', did), account, params={'did_type': 'dataset'}), f'dataset locks [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestLOCK.test_get_dataset_locks')

    def test_get_dataset_locks_bulk(self):
        cases = [
            ('other account', 'alice', 'bob'),
            ('bad scope', 'non_existing_scope', 'alice'),
            ('bad scope other account', 'non_existing_scope', 'bob'),
        ]
        responses = []
        for case_id, scope, account in cases:
            payload = {'dids': [{'scope': scope, 'name': 'file1.png', 'type': 'dataset'}]}
            responses.append((_post('/locks/bulk_locks_for_dids', account, json=payload), f'bulk locks [{case_id}] for {scope} as {account}'))
        _assert_generic_error_chain(responses, 'TestLOCK.test_get_dataset_locks_bulk')

    def test_get_dataset_locks_by_rse(self):
        pytest.skip("Filtering Test: list locks at an RSE and verify that lock records for DIDs in unreadable scopes are filtered.")

    def test_get_dataset_locks_for_rule_id(self, vo):
        cases = [
            ('root-owned rule alice', 'root-owned rule', 'alice'),
            ('root-owned rule bob', 'root-owned rule', 'bob'),
            ('nonexistent rule alice', 'nonexistent rule', 'alice'),
            ('nonexistent rule bob', 'nonexistent rule', 'bob'),
        ]
        responses = []
        for case_id, rule_case, account in cases:
            rule_id = _get_rule_id('file1.png', vo, 'root') if rule_case == 'root-owned rule' else 'non-existent-rule-id'
            responses.append((_get(f'/rules/{rule_id}/locks', account), f'rule locks [{case_id}] as {account}'))
        _assert_generic_error_chain(responses, 'TestLOCK.test_get_dataset_locks_for_rule_id')


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

    def test_list_dataset_replicas(self):
        cases = [
            ('other account', 'alice:alice_ds', 'bob'),
            ('bad scope', 'non_existing_scope:alice_ds', 'alice'),
            ('bad scope other account', 'non_existing_scope:alice_ds', 'bob'),
            ('missing DID other account', 'alice:non_existing_ds', 'bob'),
        ]
        responses = [
            (_get(_scope_name_path('replicas', did, 'datasets'), account), f'list dataset replicas [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestREPLICA.test_list_dataset_replicas')

    def test_list_dataset_replicas_bulk(self):
        cases = [
            ('other account', 'bob', {'dids': [{'scope': 'alice', 'name': 'alice_ds'}, {'scope': 'alice', 'name': 'alice_ds2'}]}),
            ('bad scope', 'alice', {'dids': [{'scope': 'non_existing_scope', 'name': 'alice_ds'}]}),
            ('missing DID', 'bob', {'dids': [{'scope': 'alice', 'name': 'non_existing_ds'}]}),
        ]
        responses = [
            (_post('/replicas/datasets_bulk', account, json=payload), f'list dataset replicas bulk [{case_id}] as {account}')
            for case_id, account, payload in cases
        ]
        _assert_generic_error_chain(responses, 'TestREPLICA.test_list_dataset_replicas_bulk')

    def test_list_dataset_replicas_vp(self):
        cases = [
            ('other account', 'alice:alice_ds', 'bob'),
            ('bad scope', 'non_existing_scope:alice_ds', 'alice'),
            ('bad scope other account', 'non_existing_scope:alice_ds', 'bob'),
            ('missing DID other account', 'alice:non_existing_ds', 'bob'),
        ]
        responses = [
            (_get(_scope_name_path('replicas', did, 'datasets_vp'), account), f'list dataset replicas vp [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestREPLICA.test_list_dataset_replicas_vp')

    def test_list_datasets_per_rse(self):
        pytest.skip("Filtering Test: list datasets at an RSE and verify that datasets from unauthorized scopes are filtered for a regular account.")

    def test_list_replicas(self):
        cases = [
            ('other account', 'alice:file1.png', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = []
        for case_id, did, account in cases:
            scope, name = did.split(':', 1)
            responses.append((_post('/replicas/list', account, json={'dids': [{'scope': scope, 'name': name}]}), f'list replicas [{case_id}] for {did} as {account}'))
        _assert_generic_error_chain(responses, 'TestREPLICA.test_list_replicas')


class TestRULE:
    def test_examine_replication_rule(self, vo):
        cases = [
            ('root-owned rule alice', 'root-owned rule', 'alice'),
            ('root-owned rule bob', 'root-owned rule', 'bob'),
            ('nonexistent rule alice', 'nonexistent rule', 'alice'),
            ('nonexistent rule bob', 'nonexistent rule', 'bob'),
        ]
        responses = []
        for case_id, rule_case, account in cases:
            rule_id = _get_rule_id('file1.png', vo, 'root') if rule_case == 'root-owned rule' else 'non-existent-rule-id'
            responses.append((_get(f'/rules/{rule_id}/analysis', account), f'examine rule [{case_id}] as {account}'))
        _assert_generic_error_chain(responses, 'TestRULE.test_examine_replication_rule')

    def test_get_replication_rule(self, vo):
        cases = [
            ('root-owned rule alice', 'root-owned rule', 'alice'),
            ('root-owned rule bob', 'root-owned rule', 'bob'),
            ('nonexistent rule alice', 'nonexistent rule', 'alice'),
            ('nonexistent rule bob', 'nonexistent rule', 'bob'),
        ]
        responses = []
        for case_id, rule_case, account in cases:
            rule_id = _get_rule_id('file1.png', vo, 'root') if rule_case == 'root-owned rule' else 'non-existent-rule-id'
            responses.append((_get(f'/rules/{rule_id}', account), f'get rule [{case_id}] as {account}'))
        _assert_generic_error_chain(responses, 'TestRULE.test_get_replication_rule')

    def test_list_associated_replication_rules_for_file(self):
        cases = [
            ('other account', 'alice:file1.png', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = [
            (_get(_did_path(did, 'associated_rules'), account), f'associated rules [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestRULE.test_list_associated_replication_rules_for_file')

    def test_list_replication_rule_full_history(self):
        cases = [
            ('other account', 'alice:file1.png', 'bob'),
            ('bad scope', 'non_existing_scope:file1.png', 'alice'),
            ('bad scope other account', 'non_existing_scope:file1.png', 'bob'),
            ('missing DID other account', 'alice:non_existing_file.png', 'bob'),
        ]
        responses = [
            (_get(_scope_name_path('rules', did, 'history'), account), f'full history [{case_id}] for {did} as {account}')
            for case_id, did, account in cases
        ]
        _assert_generic_error_chain(responses, 'TestRULE.test_list_replication_rule_full_history')

    def test_list_replication_rule_history(self):
        pytest.skip("Permission Test: retrieve a rule's history by rule_id and verify access based on the rule's DID scope, including a rule visible only to root and an unknown rule.")

    def test_list_replication_rules(self):
        pytest.skip("Filtering Test: list replication rules by account, DID, or subscription and verify filtering of rules associated with unreadable scopes.")


class TestOPENDATA:
    def test_get_opendata_did(self):
        pytest.skip("Ambiguous: retrieve an open-data DID by scope and name, verifying authorized access, unauthorized-scope behavior, and unknown DID behavior.")

    def test_list_opendata_dids(self):
        pytest.skip("Ambiguous: list open-data DIDs and determine whether regular-account results are filtered to readable scopes or access is denied, while root can see all results.")


class TestREQUEST:
    def test_get_request_by_did(self):
        pytest.skip("Permission Test: retrieve a transfer request for a DID as root, the owning account, and an unauthorized account.")

    def test_get_request_history_by_did(self):
        pytest.skip("Permission Test: retrieve request history for a DID at an RSE as root, the owning account, and an unauthorized account.")

    def test_list_requests(self):
        pytest.skip("Ambiguous: list transfer requests and determine whether records for unreadable DID scopes are filtered or access is denied.")

    def test_list_requests_history(self):
        pytest.skip("Ambiguous: list transfer-request history and determine whether records for unreadable DID scopes are filtered or access is denied.")


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
