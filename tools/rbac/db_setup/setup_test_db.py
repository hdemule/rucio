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

"""
Check, and optionally rebuild from scratch, everything the RBAC tests rely on.

`tests/test_rbac_restapi.py` assumes a dev environment provisioned with a set of accounts, scopes,
files, rules, transfer requests and roles (see the assumptions at the top of that file). This
script runs inside the dev `rucio` container:

    python tools/rbac/db_setup/setup_test_db.py            # dry run: report what is present and what is missing
    python tools/rbac/db_setup/setup_test_db.py --reset    # DROP THE WHOLE DATABASE, then recreate everything

--reset first runs a preflight check of everything it needs (policy package, source files,
alembic head, ...) and stops before touching the database if any of it is missing. It then asks
for confirmation (skip it with --yes), purges the database schema, rebuilds it like
`tools/run_tests.sh -ir` does (reset_database.py -b, bootstrap_tests.py, sync_rses.py,
sync_meta.py) and provisions the RBAC test data on top. It ends by running the dry-run check
again, and exits with a non-zero status if anything is still missing.
"""

import argparse
import configparser
import filecmp
import importlib.util
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

# the root of the repository, this script being in tools/rbac/db_setup
BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.append(BASE_PATH)
os.chdir(BASE_PATH)

from sqlalchemy import Enum, select, text  # noqa: E402

from rucio.alembicrevision import ALEMBIC_REVISION  # noqa: E402
from rucio.common.config import config_get  # noqa: E402
from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.common.exception import RucioException  # noqa: E402
from rucio.common.types import InternalAccount, InternalScope  # noqa: E402
from rucio.db.sqla import models  # noqa: E402
from rucio.db.sqla.constants import AccountType, DatabaseOperationType, DIDType, IdentityType, ReplicaState, RequestState, RequestType, RolePermissionType, ScopeOperationType  # noqa: E402
from rucio.db.sqla.session import db_session, get_engine  # noqa: E402

POLICY_PACKAGE = 'rbac_rucio_policy_package'
POLICY_PACKAGE_SOURCE = os.path.join(BASE_PATH, 'policy-packages', POLICY_PACKAGE)

RSE = 'MOCK-POSIX'
PASSWORD = 'secret'

# account -> (type, email, userpass identity); the root account and its identity come from the bootstrap
ACCOUNTS = {
    'root': (AccountType.SERVICE, None, config_get('bootstrap', 'userpass_identity', raise_exception=False, default='ddmlab')),
    'alice': (AccountType.USER, 'alice@email.com', 'alice'),
    'bob': (AccountType.USER, 'bob@email.com', 'bob'),
}
# scope -> owner; bob owns no scope of its own
SCOPES = {'alice': 'alice', 'root': 'root', 'atlas': 'root'}
# (scope, name) -> local file uploaded to the RSE by root, which also creates a rule on the RSE
FILES = {
    ('alice', 'file1.png'): 'file1.png',
    ('alice', 'file2.png'): 'file2.png',
    ('alice', 'file3.png'): 'file3.png',
    ('root', 'file1.png'): 'file1.png',
}
# (scope, name) -> (owner, content)
DATASETS = {
    ('alice', 'alice_ds'): ('alice', [('alice', 'file1.png'), ('alice', 'file2.png'), ('alice', 'file3.png')]),
    ('alice', 'alice_ds2'): ('alice', [('alice', 'file2.png')]),
}
# the DIDs whose rule `_get_rule_id` looks up, the account name being used as the scope
RULE_DIDS = [('alice', 'file1.png'), ('root', 'file1.png')]
# the DID with a transfer request, and a past one in the history, towards the RSE
REQUEST_DID = ('alice', 'file1.png')
# role -> (operations granted on scope pattern, accounts holding the role)
ROLES = {
    'data-scientist': ({('read', 'atlas'), ('write', 'atlas')}, {'alice'}),
}
ACCOUNTS_WITHOUT_ROLES = ['bob']


# ------------------------------------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------------------------------------

@dataclass
class Result:
    ok: bool
    label: str
    detail: str = ''


class Report:
    def __init__(self) -> None:
        self.results: list[Result] = []

    def section(self, title: str) -> None:
        print('\n== %s' % title)

    def add(self, ok: bool, label: str, detail: str = '') -> bool:
        self.results.append(Result(ok, label, detail))
        print('  [%s] %s%s' % ('  OK  ' if ok else 'MISSING', label, (' -- %s' % detail) if detail else ''))
        return ok

    def run(self, label: str, check: Callable[[], Optional[str]]) -> bool:
        """Run `check`, which returns None when satisfied or the reason it is not, and record the outcome."""
        try:
            reason = check()
        except Exception as error:  # a broken database must not stop the remaining checks
            reason = '%s: %s' % (type(error).__name__, str(error).splitlines()[0] if str(error) else '')
        return self.add(reason is None, label, reason or '')

    @property
    def failures(self) -> list[Result]:
        return [result for result in self.results if not result.ok]


def _read(query: Any) -> list[Any]:
    with db_session(DatabaseOperationType.READ) as session:
        return list(session.execute(query).all())


def _scope(scope: str) -> InternalScope:
    return InternalScope(scope, vo=DEFAULT_VO)


def _account(account: str) -> InternalAccount:
    return InternalAccount(account, vo=DEFAULT_VO)


# ------------------------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------------------------

def _rucio_config() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(os.path.join(os.environ.get('RUCIO_HOME', '/opt/rucio'), 'etc', 'rucio.cfg'))
    return parser


def check_policy_package_configured() -> Optional[str]:
    package = _rucio_config().get('policy', 'package', fallback=None)
    if package != POLICY_PACKAGE:
        return "[policy] package is %r in rucio.cfg, expected %r" % (package, POLICY_PACKAGE)


def check_policy_package_installed() -> Optional[str]:
    spec = importlib.util.find_spec(POLICY_PACKAGE)
    if spec is None or not spec.origin:
        return "not importable, install it with: pip install --no-deps --force-reinstall %s" % os.path.dirname(POLICY_PACKAGE_SOURCE)
    installed = os.path.dirname(spec.origin)
    if os.path.isdir(POLICY_PACKAGE_SOURCE) and os.path.realpath(installed) != os.path.realpath(POLICY_PACKAGE_SOURCE):
        comparison = filecmp.dircmp(POLICY_PACKAGE_SOURCE, installed, ignore=['__pycache__'])
        stale = comparison.diff_files + comparison.left_only
        if stale:
            return ("the installed copy in %s differs from %s (%s): reinstall it with "
                    "`pip install --no-deps --force-reinstall %s` and restart httpd"
                    % (installed, POLICY_PACKAGE_SOURCE, ', '.join(sorted(stale)), os.path.dirname(POLICY_PACKAGE_SOURCE)))


def check_policy_package_roles() -> Optional[str]:
    from rucio.core import permission
    missing = set(ROLES) - set(permission.get_roles(vo=DEFAULT_VO))
    if missing:
        return 'the policy package does not define the role(s) %s' % ', '.join(sorted(missing))


def check_roles_endpoint() -> Optional[str]:
    endpoints = [endpoint.strip() for endpoint in _rucio_config().get('api', 'endpoints', fallback='').split(',')]
    if endpoints != [''] and 'roles' not in endpoints:
        return "'roles' is not listed in [api] endpoints of rucio.cfg"


def check_source_files(files_dir: str) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        missing = sorted({path for path in FILES.values() if not os.path.isfile(os.path.join(files_dir, path))})
        if missing:
            return 'not found in %s: %s' % (files_dir, ', '.join(missing))
    return check


def check_alembic_head() -> Optional[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    heads = ScriptDirectory.from_config(Config(config_get('alembic', 'cfg'))).get_heads()
    if heads != [ALEMBIC_REVISION]:
        return 'the migrations have head(s) %s, but rucio/alembicrevision.py expects %s' % (heads, ALEMBIC_REVISION)


def check_alembic_revision() -> Optional[str]:
    rows = _read(text('SELECT version_num FROM %salembic_version' % _schema_prefix()))
    revisions = [row[0] for row in rows]
    if revisions != [ALEMBIC_REVISION]:
        return 'the database is at %s, the code expects %s: the schema is stale, rebuild it with --reset' % (revisions, ALEMBIC_REVISION)


def _model_enums() -> dict[str, set[str]]:
    """The values of every enum type of the models, by type name."""
    enums = {}
    for table in models.BASE.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, Enum) and column.type.name:
                enums[column.type.name] = set(column.type.enums)
    return enums


def check_enums() -> Optional[str]:
    """Compare the enum type each column uses in the database with the models, e.g. a ScopeOperationType value added after the type was created."""
    if get_engine().dialect.name != 'postgresql':
        return None
    rows = _read(text(
        "SELECT c.udt_schema, c.udt_name, array_agg(e.enumlabel::text) FROM information_schema.columns c "
        "JOIN pg_namespace n ON n.nspname = c.udt_schema JOIN pg_type t ON t.typnamespace = n.oid AND t.typname = c.udt_name "
        "JOIN pg_enum e ON e.enumtypid = t.oid WHERE c.table_schema = :schema GROUP BY 1, 2"
    ).bindparams(schema=config_get('database', 'schema', raise_exception=False) or 'public'))
    expected = _model_enums()
    stale = ['%s.%s holds %s, the models expect %s' % (schema, name, sorted(values), sorted(expected[name]))
             for schema, name, values in rows if name in expected and set(values) != expected[name]]
    if stale:
        return '%s: rebuild it with --reset' % '; '.join(sorted(stale))


def _schema_prefix() -> str:
    schema = config_get('database', 'schema', raise_exception=False)
    return '%s.' % schema if schema else ''


def check_account(account: str) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.Account.status).where(models.Account.account == _account(account)))
        if not rows:
            return 'does not exist'
        if rows[0][0].name != 'ACTIVE':
            return 'is %s' % rows[0][0].name
    return check


def check_identity(account: str, identity: str) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        from rucio.core.identity import verify_identity
        rows = _read(select(models.IdentityAccountAssociation.account).where(
            models.IdentityAccountAssociation.identity == identity,
            models.IdentityAccountAssociation.identity_type == IdentityType.USERPASS,
            models.IdentityAccountAssociation.account == _account(account)))
        if not rows:
            return 'userpass identity %r is not mapped to the account' % identity
        with db_session(DatabaseOperationType.READ) as session:
            verify_identity(identity, IdentityType.USERPASS, PASSWORD, session=session)
    return check


def check_scope(scope: str, owner: str) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.Scope.account).where(models.Scope.scope == _scope(scope)))
        if not rows:
            return 'does not exist'
        if rows[0][0].external != owner:
            return 'is owned by %s' % rows[0][0].external
    return check


def check_rse() -> Optional[str]:
    rows = _read(select(models.RSE.id).where(models.RSE.rse == RSE, models.RSE.deleted == False))  # noqa: E712
    if not rows:
        return 'does not exist'
    protocols = _read(select(models.RSEProtocol.scheme).where(models.RSEProtocol.rse_id == rows[0][0]))
    if 'file' not in {row[0] for row in protocols}:
        return "has no 'file' protocol"


def check_file(scope: str, name: str) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.DataIdentifier.did_type, models.DataIdentifier.guid).where(
            models.DataIdentifier.scope == _scope(scope), models.DataIdentifier.name == name))
        if not rows:
            return 'does not exist'
        if rows[0][0] != DIDType.FILE:
            return 'is a %s, not a file' % rows[0][0].name
        if rows[0][1] is None:
            return 'has no GUID'
        replicas = _read(select(models.RSEFileAssociation.state).join(models.RSE, models.RSE.id == models.RSEFileAssociation.rse_id).where(
            models.RSEFileAssociation.scope == _scope(scope), models.RSEFileAssociation.name == name, models.RSE.rse == RSE))
        if not replicas or replicas[0][0] != ReplicaState.AVAILABLE:
            return 'has no AVAILABLE replica on %s' % RSE
    return check


def check_dataset(scope: str, name: str, content: list[tuple[str, str]]) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.DataIdentifier.did_type).where(
            models.DataIdentifier.scope == _scope(scope), models.DataIdentifier.name == name))
        if not rows:
            return 'does not exist'
        if rows[0][0] != DIDType.DATASET:
            return 'is a %s, not a dataset' % rows[0][0].name
        children = _read(select(models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.child_name).where(
            models.DataIdentifierAssociation.scope == _scope(scope), models.DataIdentifierAssociation.name == name))
        missing = set(content) - {(row[0].external, row[1]) for row in children}
        if missing:
            return 'does not contain %s' % ', '.join('%s:%s' % did for did in sorted(missing))
    return check


def check_rule(scope: str, name: str) -> Optional[str]:
    rows = _read(select(models.ReplicationRule.id).where(
        models.ReplicationRule.scope == _scope(scope), models.ReplicationRule.name == name))
    if not rows:
        return 'no replication rule'


def check_request(model: Any) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        scope, name = REQUEST_DID
        rows = _read(select(model.id).join(models.RSE, models.RSE.id == model.dest_rse_id).where(
            model.scope == _scope(scope), model.name == name, models.RSE.rse == RSE))
        if not rows:
            return 'none found'
    return check


def check_reserved_roles() -> Optional[str]:
    from rucio.core.role import RESERVED_ROLES
    present = {row[0] for row in _read(select(models.Roles.role))}
    missing = set(RESERVED_ROLES) - present
    if missing:
        return 'missing %s' % ', '.join(sorted(missing))


def check_role(role: str) -> Optional[str]:
    if not _read(select(models.Roles.role).where(models.Roles.role == role)):
        return 'does not exist'


def check_role_permissions(role: str, expected: set[tuple[str, str]]) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.RoleScopePermissionAssociation.operation, models.RoleScopePermissionAssociation.scope_pattern).where(
            models.RoleScopePermissionAssociation.role == role))
        missing = expected - {(row[0].value, row[1]) for row in rows}
        if missing:
            return 'missing %s' % ', '.join('%s on %s' % permission for permission in sorted(missing))
    return check


def check_account_roles(account: str, expected: set[str]) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        from rucio.core.role import has_account_valid_role, list_account_roles
        with db_session(DatabaseOperationType.READ) as session:
            # only an active assignment grants a role: activated already and not expired yet
            held = {
                role['role'] for role in list_account_roles(_account(account), session=session)
                if has_account_valid_role(_account(account), role['role'], session=session)
            }
        if expected and expected - held:
            return 'does not hold %s' % ', '.join(sorted(expected - held))
        if not expected and held:
            return 'holds %s, expected none' % ', '.join(sorted(held))
    return check


def run_environment_checks(report: Report, files_dir: str) -> None:
    """The checks that do not depend on the content of the database, and which --reset requires to pass first."""
    report.section('Environment')
    report.run('policy package configured in rucio.cfg', check_policy_package_configured)
    report.run('policy package installed and up to date', check_policy_package_installed)
    report.run('policy package defines the test roles', check_policy_package_roles)
    report.run("'roles' REST endpoint enabled", check_roles_endpoint)
    report.run('single alembic head matching rucio/alembicrevision.py', check_alembic_head)
    report.run('files to upload present', check_source_files(files_dir))


def run_database_checks(report: Report) -> None:
    report.section('Database schema')
    report.run('alembic revision is %s' % ALEMBIC_REVISION, check_alembic_revision)
    report.run('enum types match the models', check_enums)

    report.section('Accounts and identities')
    for account, (_, _, identity) in ACCOUNTS.items():
        report.run('account %s' % account, check_account(account))
        report.run('userpass identity %s/%s for %s' % (identity, PASSWORD, account), check_identity(account, identity))

    report.section('Scopes')
    for scope, owner in SCOPES.items():
        report.run('scope %s owned by %s' % (scope, owner), check_scope(scope, owner))

    report.section('RSE and data')
    report.run('RSE %s' % RSE, check_rse)
    for scope, name in FILES:
        report.run('file %s:%s' % (scope, name), check_file(scope, name))
    for (scope, name), (_, content) in DATASETS.items():
        report.run('dataset %s:%s' % (scope, name), check_dataset(scope, name, content))
    for scope, name in RULE_DIDS:
        report.run('replication rule on %s:%s' % (scope, name), lambda scope=scope, name=name: check_rule(scope, name))
    report.run('transfer request for %s:%s to %s' % (REQUEST_DID + (RSE,)), check_request(models.Request))
    report.run('transfer request history for %s:%s to %s' % (REQUEST_DID + (RSE,)), check_request(models.RequestHistory))

    report.section('Roles')
    report.run('reserved roles', check_reserved_roles)
    for role, (permissions, holders) in ROLES.items():
        report.run('role %s' % role, lambda role=role: check_role(role))
        report.run('role %s grants %s' % (role, ', '.join('%s on %s' % permission for permission in sorted(permissions))), check_role_permissions(role, permissions))
        for account in sorted(holders):
            report.run('account %s holds %s' % (account, role), check_account_roles(account, {role}))
    for account in ACCOUNTS_WITHOUT_ROLES:
        report.run('account %s holds no role' % account, check_account_roles(account, set()))


# ------------------------------------------------------------------------------------------------
# Reset
# ------------------------------------------------------------------------------------------------

def _step(message: str) -> None:
    print('\n>>> %s' % message, flush=True)


def _run_tool(*command: str) -> None:
    print('$ %s' % ' '.join(command), flush=True)
    subprocess.run([sys.executable, *command], check=True, cwd=BASE_PATH)


def _restart_server() -> None:
    """Restart httpd gracefully, so that the server drops its connections and caches of the purged schema, and wait for it."""
    import requests
    if shutil.which('httpd') is None:
        print('httpd not found, restart the server yourself if the following steps fail')
        return
    subprocess.run(['httpd', '-k', 'graceful'], check=True)
    url = '%s/ping' % config_get('client', 'rucio_host')
    ca_cert = config_get('client', 'ca_cert', raise_exception=False) or False
    for _ in range(60):
        try:
            if requests.get(url, verify=ca_cert, timeout=5).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError('the server did not answer on %s after the restart' % url)


def _drop_leftover_enums() -> None:
    """
    Drop the enum types of the models which survived the purge.

    On PostgreSQL the models create most of their enum types in the default schema of the
    connection (`public`) rather than in the configured one, so that purging the configured
    schema leaves them behind, and the rebuild would reuse them with their old values.
    """
    engine = get_engine()
    if engine.dialect.name != 'postgresql':
        return
    names = set(_model_enums())
    with engine.begin() as conn:
        leftovers = conn.execute(text(
            "SELECT n.nspname, t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
            "WHERE t.typtype = 'e' AND n.nspname = current_schema()")).all()
        for schema, name in leftovers:
            if name in names:
                print('Dropping enum type %s."%s"' % (schema, name))
                conn.execute(text('DROP TYPE "%s"."%s"' % (schema, name)))


def _rebuild_database() -> None:
    """The equivalent of `tools/reset_database.py -b`, which also drops the enum types left behind by the purge."""
    from rucio.db.sqla.util import build_database, create_base_vo, create_root_account, purge_db
    purge_db()
    _drop_leftover_enums()
    build_database()
    create_base_vo()
    create_root_account()


def _provision_accounts_and_scopes() -> None:
    from rucio.core.account import account_exists, add_account
    from rucio.core.identity import add_account_identity
    from rucio.core.scope import add_scope, check_scope
    with db_session(DatabaseOperationType.WRITE) as session:
        for account, (account_type, email, identity) in ACCOUNTS.items():
            if account == 'root':
                continue  # created by the bootstrap, along with its userpass identity
            if not account_exists(_account(account), session=session):
                add_account(_account(account), account_type, email, session=session)
            add_account_identity(identity, IdentityType.USERPASS, _account(account), email, password=PASSWORD, session=session)
        for scope, owner in SCOPES.items():
            if not check_scope(_scope(scope), session=session):
                add_scope(_scope(scope), _account(owner), session=session)


def _upload_files(files_dir: str) -> None:
    """Upload the files as root, which registers their replica and a rule on the RSE, like `rucio upload` does."""
    from rucio.client import Client
    from rucio.client.uploadclient import UploadClient
    from rucio.rse import rsemanager

    client = Client()
    rse_settings = rsemanager.get_rse_info(RSE, vo=DEFAULT_VO)
    for (scope, name), path in FILES.items():
        # the files of a previous reset are still on the storage, while the database no longer knows them
        pfn = list(rsemanager.lfns2pfns(rse_settings, [{'scope': scope, 'name': name}], operation='write').values())[0]
        if pfn.startswith('file://'):
            local = '/' + pfn.split('://', 1)[1].split('/', 1)[1]
            if os.path.isfile(local):
                print('Removing %s left on the storage by a previous run' % local)
                os.remove(local)

        UploadClient(_client=client).upload([{
            'path': os.path.join(files_dir, path),
            'rse': RSE,
            'did_scope': scope,
            'did_name': name,
        }])


def _provision_datasets() -> None:
    from rucio.core.did import add_did, attach_dids
    with db_session(DatabaseOperationType.WRITE) as session:
        for (scope, name), (owner, content) in DATASETS.items():
            add_did(_scope(scope), name, DIDType.DATASET, _account(owner), session=session)
            attach_dids(_scope(scope), name, [{'scope': _scope(child_scope), 'name': child_name} for child_scope, child_name in content],
                        _account(owner), session=session)


def _provision_requests() -> None:
    """Queue a transfer request for the DID, archive a first one to give it a history, and queue a second one which stays active."""
    from rucio.core.request import archive_request, queue_requests
    from rucio.core.rse import get_rse_id
    from rucio.core.rule import list_rules

    scope, name = REQUEST_DID
    with db_session(DatabaseOperationType.WRITE) as session:
        rule = next(iter(list_rules(filters={'scope': _scope(scope), 'name': name}, session=session)))
        file = session.execute(select(models.DataIdentifier).where(
            models.DataIdentifier.scope == _scope(scope), models.DataIdentifier.name == name)).scalar_one()

        def request(state: RequestState) -> dict[str, Any]:
            return {
                'request_type': RequestType.TRANSFER,
                'scope': _scope(scope),
                'name': name,
                'dest_rse_id': get_rse_id(RSE, vo=DEFAULT_VO, session=session),
                'rule_id': rule['id'],
                'account': _account('root'),
                'retry_count': 0,
                'state': state,
                'attributes': {'activity': 'User Subscriptions', 'bytes': file.bytes, 'md5': file.md5, 'adler32': file.adler32},
            }

        # despite its docstring, queue_requests returns the queued requests themselves, not their ids
        for queued in queue_requests([request(RequestState.DONE)], session=session):
            archive_request(queued['id'], session=session)
        queue_requests([request(RequestState.QUEUED)], session=session)


def _provision_roles() -> None:
    from rucio.core import role as role_core
    with db_session(DatabaseOperationType.WRITE) as session:
        role_core.setup_reserved_roles(session=session)
    with db_session(DatabaseOperationType.WRITE) as session:
        role_core.sync_roles_from_policy_package(vo=DEFAULT_VO, session=session)
    with db_session(DatabaseOperationType.WRITE) as session:
        for role, (permissions, holders) in ROLES.items():
            for operation, scope_pattern in sorted(permissions):
                role_core.add_role_permission(role, RolePermissionType.SCOPE, {'scope_pattern': scope_pattern, 'operation': ScopeOperationType(operation)}, session=session)
            for account in sorted(holders):
                role_core.add_account_role(_account(account), role, session=session)


def reset(files_dir: str) -> None:
    _step('Purging and rebuilding the database schema')
    _rebuild_database()

    _step('Restarting the server')
    _restart_server()

    _step('Bootstrapping the dev environment')
    _run_tool('tools/bootstrap_tests.py')
    _run_tool('tools/sync_rses.py')
    _run_tool('tools/sync_meta.py')

    _step('Creating the RBAC roles from the policy package')
    _provision_accounts_and_scopes()  # the role assignments need the accounts
    _provision_roles()

    _step('Uploading the files')
    _upload_files(files_dir)

    _step('Creating the datasets and the transfer requests')
    _provision_datasets()
    _provision_requests()


# ------------------------------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description='Check, and optionally rebuild from scratch, everything the RBAC tests rely on.')
    parser.add_argument('--reset', action='store_true', help='DROP THE WHOLE DATABASE and recreate everything from scratch (default: dry run, only check)')
    parser.add_argument('--yes', action='store_true', help='do not ask for confirmation before --reset')
    parser.add_argument('--files-dir', default=os.path.join(os.environ.get('RUCIO_HOME', '/opt/rucio')),
                        help='directory holding the files to upload (default: %(default)s)')
    args = parser.parse_args()

    report = Report()
    run_environment_checks(report, args.files_dir)

    if args.reset:
        if report.failures:
            print('\nThe environment is not ready for --reset, so the database was NOT touched. Fix the above first.')
            return 1
        if not args.yes:
            database = get_engine().url.render_as_string(hide_password=True)
            answer = input('\nThis DROPS EVERYTHING in %s (schema %s). Type "yes" to continue: '
                           % (database, config_get('database', 'schema', raise_exception=False)))
            if answer.strip() != 'yes':
                print('Aborted, nothing was changed.')
                return 1
        try:
            reset(args.files_dir)
        except (RucioException, subprocess.CalledProcessError, RuntimeError) as error:
            print('\nThe reset failed: %s' % error)
            return 1
        print('\n\nReset done, checking the result:')
        report = Report()
        run_environment_checks(report, args.files_dir)

    run_database_checks(report)

    print()
    if report.failures:
        print('%d requirement(s) missing.%s' % (len(report.failures), '' if args.reset else ' Run with --reset to rebuild everything from scratch.'))
        return 1
    print('Everything the RBAC tests rely on is present.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
