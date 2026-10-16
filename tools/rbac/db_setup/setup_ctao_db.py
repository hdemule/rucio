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
Check, and optionally rebuild from scratch, the CTAO RBAC demo environment.

The demo environment holds a CTAO-like set of accounts, scopes, roles and data: the raw data and
the analysis results of proposal 2026-042, a public data release and the
personal scope of each user, filled with the dummy files of `container_upload/ctao`. This script
runs inside the dev `rucio` container:

    python tools/rbac/db_setup/setup_ctao_db.py            # dry run: report what is present and what is missing
    python tools/rbac/db_setup/setup_ctao_db.py --reset    # DROP THE WHOLE DATABASE, then recreate everything

--reset first runs a preflight check of everything it needs (policy package, source files,
alembic head, ...) and stops before touching the database if any of it is missing. It then asks
for confirmation (skip it with --yes), purges the database schema and rebuilds it with nothing
but the root account, the reserved roles, the RSE the files are uploaded to and the CTAO demo
data on top: unlike `tools/run_tests.sh -ir`, it does not run the test bootstrap, so none of the
test accounts, scopes, RSEs or metadata keys are created. It ends by running the dry-run check
again, which also reports anything present beyond the demo environment, and exits with a
non-zero status if anything is missing or unexpected.
"""

import argparse
import configparser
import filecmp
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

# the Rucio root (/opt/rucio in the dev containers), three levels above tools/rbac/db_setup/; the relative paths of rucio.cfg,
# like the alembic script location, resolve against it
BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
sys.path.append(BASE_PATH)
os.chdir(BASE_PATH)

from sqlalchemy import Enum, select, text  # noqa: E402

from rucio.alembicrevision import ALEMBIC_REVISION  # noqa: E402
from rucio.common.config import config_get  # noqa: E402
from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.common.exception import RucioException  # noqa: E402
from rucio.common.types import InternalAccount, InternalScope  # noqa: E402
from rucio.db.sqla import models  # noqa: E402
from rucio.db.sqla.constants import AccountType, DatabaseOperationType, DIDType, IdentityType, ReplicaState, RoleOperationType  # noqa: E402
from rucio.db.sqla.session import db_session, get_engine  # noqa: E402

# the repository root, mounted in the dev containers at $RUCIO_SOURCE_DIR
SOURCE_PATH = os.environ.get('RUCIO_SOURCE_DIR') or BASE_PATH

POLICY_PACKAGE = 'rbac_rucio_policy_package'
POLICY_PACKAGE_SOURCE = os.path.join(BASE_PATH, 'policy-packages', POLICY_PACKAGE)

RSE = 'MOCK-POSIX'
RSE_REPOSITORY = os.path.join(SOURCE_PATH, 'etc', 'rse_repository.json')
PASSWORD = 'secret'

# account -> (type, email, userpass identity); the root account and its identity come from the bootstrap
ACCOUNTS = {
    'root': (AccountType.SERVICE, None, config_get('bootstrap', 'userpass_identity', raise_exception=False, default='ddmlab')),
    'zoro': (AccountType.USER, 'zoro@email.com', 'zoro'),
    'ana': (AccountType.USER, 'ana@email.com', 'ana'),
    'ben': (AccountType.USER, 'ben@email.com', 'ben'),
    'chen': (AccountType.USER, 'chen@email.com', 'chen'),
    'dara': (AccountType.USER, 'dara@email.com', 'dara'),
    'eli': (AccountType.USER, 'eli@email.com', 'eli'),
    'eve': (AccountType.USER, 'eve@email.com', 'eve'),
    'guest': (AccountType.USER, 'guest@email.com', 'guest'),
}
# scope -> owner; the personal scopes belong to their user, the others to zoro, guest owns no scope
SCOPES = {
    'prop_2026_042_raw': 'zoro',
    'prop_2026_042_res': 'zoro',
    'public': 'zoro',
    'user.ana': 'ana',
    'user.ben': 'ben',
    'user.chen': 'chen',
    'user.dara': 'dara',
    'user.eli': 'eli',
    'user.eve': 'eve',
}
# (scope, name) -> names of the files of the dataset, in the same scope; each dataset is owned by the owner of
# its scope, and each file is uploaded by root from <files dir>/<scope>/<name>, which also creates a rule on the RSE
DATASETS = {
    # raw data of proposal 2026-042: Crab Nebula observed by LST-1 on 2026-03-12, one dataset per run
    ('prop_2026_042_raw', 'obs_12001_r1'): [
        'CTAO.LST1.20260312.Run12001.0000.fits.fz',
        'CTAO.LST1.20260312.Run12001.0001.fits.fz',
        'CTAO.LST1.20260312.Run12001.0002.fits.fz',
    ],
    ('prop_2026_042_raw', 'obs_12002_r1'): [
        'CTAO.LST1.20260312.Run12002.0000.fits.fz',
        'CTAO.LST1.20260312.Run12002.0001.fits.fz',
        'CTAO.LST1.20260312.Run12002.0002.fits.fz',
    ],
    ('prop_2026_042_raw', 'night_20260312_aux'): [
        'CTAO.LST1.20260312.drive_log.ecsv',
    ],
    # analysis results of proposal 2026-042: PKS 2155-304 observed by CTAO-South
    ('prop_2026_042_res', 'pks2155_dl3'): [
        'CTAO.South.pks2155.dl3.obs-index.fits.gz',
        'CTAO.South.obs_23001.dl3.fits.gz',
        'CTAO.South.obs_23002.dl3.fits.gz',
        'CTAO.South.obs_23003.dl3.fits.gz',
    ],
    ('prop_2026_042_res', 'pks2155_dl5'): [
        'CTAO.South.pks2155.dl5.spectrum.ecsv',
        'CTAO.South.pks2155.dl5.lightcurve.ecsv',
        'CTAO.South.pks2155.dl5.skymap.fits',
    ],
    # public data release
    ('public', 'crab_dr1_dl3'): [
        'CTAO.DR1.crab.README.md',
        'CTAO.DR1.crab.obs-index.fits.gz',
        'CTAO.DR1.crab.hdu-index.fits.gz',
        'CTAO.DR1.crab.obs_1001.dl3.fits.gz',
        'CTAO.DR1.crab.obs_1002.dl3.fits.gz',
    ],
    # personal analyses
    ('user.ana', 'crab_spectral_fit'): ['crab_spectral_fit.yaml', 'crab_flux_points.ecsv'],
    ('user.ben', 'dl1_quality_checks'): ['run12001_dl1_qc.json', 'run12002_dl1_qc.json'],
    ('user.chen', 'background_model'): ['bkg_model_config.yaml', 'bkg_model_3d.ecsv'],
    ('user.dara', 'sensitivity_study'): ['sensitivity_config.yaml', 'sensitivity_curve.ecsv'],
    ('user.eli', 'source_detection'): ['ts_map_config.yaml', 'detected_sources.ecsv'],
    ('user.eve', 'crab_public_reanalysis'): ['crab_public_reanalysis.md', 'crab_public_lightcurve.ecsv'],
}
# (scope, name) -> local file, relative to the files directory
FILES = {(scope, name): os.path.join(scope, name) for (scope, _), names in DATASETS.items() for name in names}
# role -> (description, operations granted on scope pattern); every role is created unlocked and assignable
ROLES = {
    'cta-dmt': ('CTAO data management team.', {
        ('read', 'public'), ('write', 'public'), ('delete', 'public'),
        ('read', 'prop_2026_042*'), ('write', 'prop_2026_042*'), ('delete', 'prop_2026_042*'),
    }),
    'prop042-member': ('Member of the proposal CTAO-2026-042.', {
        ('read', 'prop_2026_042_raw'),
        ('read', 'prop_2026_042_res'), ('write', 'prop_2026_042_res'), ('delete', 'prop_2026_042_res'),
    }),
    'cta-public': ('Read access to the CTAO public data.', {
        ('read', 'public'),
    }),
}
# account -> the roles it holds, and no other
ACCOUNT_ROLES = {
    'root': set(),
    'zoro': {'cta-public', 'cta-dmt'},
    'ana': {'cta-public', 'prop042-member'},
    'ben': {'cta-public', 'prop042-member'},
    'chen': {'cta-public', 'prop042-member'},
    'dara': {'cta-public', 'prop042-member'},
    'eli': {'cta-public', 'prop042-member'},
    'eve': {'cta-public'},
    'guest': {'cta-public'},
}


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


def check_roles_endpoint() -> Optional[str]:
    endpoints = [endpoint.strip() for endpoint in _rucio_config().get('api', 'endpoints', fallback='').split(',')]
    if endpoints != [''] and 'roles' not in endpoints:
        return "'roles' is not listed in [api] endpoints of rucio.cfg"


def check_rse_repository() -> Optional[str]:
    if not os.path.isfile(RSE_REPOSITORY):
        return 'not found'
    with open(RSE_REPOSITORY) as handle:
        if RSE not in json.load(handle):
            return 'does not define %s' % RSE


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
    """Compare the enum type each column uses in the database with the models, e.g. a RoleOperationType value added after the type was created."""
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


def check_dataset(scope: str, name: str, owner: str, content: list[tuple[str, str]]) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.DataIdentifier.did_type, models.DataIdentifier.account).where(
            models.DataIdentifier.scope == _scope(scope), models.DataIdentifier.name == name))
        if not rows:
            return 'does not exist'
        if rows[0][0] != DIDType.DATASET:
            return 'is a %s, not a dataset' % rows[0][0].name
        if rows[0][1].external != owner:
            return 'is owned by %s' % rows[0][1].external
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


def check_reserved_roles() -> Optional[str]:
    from rucio.core.role import RESERVED_ROLES
    present = {row[0] for row in _read(select(models.Roles.role))}
    missing = set(RESERVED_ROLES) - present
    if missing:
        return 'missing %s' % ', '.join(sorted(missing))


def check_role(role: str) -> Optional[str]:
    rows = _read(select(models.Roles.assignable, models.Roles.locked).where(models.Roles.role == role))
    if not rows:
        return 'does not exist'
    assignable, locked = rows[0]
    if not assignable or locked:
        return 'is %s and %s' % ('assignable' if assignable else 'not assignable', 'locked' if locked else 'unlocked')


def check_role_permissions(role: str, expected: set[tuple[str, str]]) -> Callable[[], Optional[str]]:
    def check() -> Optional[str]:
        rows = _read(select(models.RolePermissionAssociation.operation, models.RolePermissionAssociation.scope_pattern).where(
            models.RolePermissionAssociation.role == role))
        granted = {(row[0].value, row[1]) for row in rows}
        problems = []
        if expected - granted:
            problems.append('missing %s' % ', '.join('%s on %s' % permission for permission in sorted(expected - granted)))
        if granted - expected:
            problems.append('also grants %s' % ', '.join('%s on %s' % permission for permission in sorted(granted - expected)))
        return '; '.join(problems) or None
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
        problems = []
        if expected - held:
            problems.append('does not hold %s' % ', '.join(sorted(expected - held)))
        if held - expected:
            problems.append('also holds %s' % ', '.join(sorted(held - expected)))
        return '; '.join(problems) or None
    return check


def check_nothing_else(query: Any, expected: set[str], to_name: Callable[[Any], str]) -> Callable[[], Optional[str]]:
    """Report the rows of `query` which are not part of the demo environment, each named by `to_name`."""
    def check() -> Optional[str]:
        unexpected = {to_name(row) for row in _read(query)} - expected
        if unexpected:
            return 'unexpected %s' % ', '.join(sorted(unexpected))
    return check


def run_environment_checks(report: Report, files_dir: str) -> None:
    """The checks that do not depend on the content of the database, and which --reset requires to pass first."""
    report.section('Environment')
    report.run('policy package configured in rucio.cfg', check_policy_package_configured)
    report.run('policy package installed and up to date', check_policy_package_installed)
    report.run("'roles' REST endpoint enabled", check_roles_endpoint)
    report.run('single alembic head matching rucio/alembicrevision.py', check_alembic_head)
    report.run('RSE repository %s defines %s' % (RSE_REPOSITORY, RSE), check_rse_repository)
    report.run('files to upload present', check_source_files(files_dir))


def run_database_checks(report: Report) -> None:
    from rucio.core.role import RESERVED_ROLES

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
    for (scope, name), _ in FILES.items():
        report.run('file %s:%s' % (scope, name), check_file(scope, name))
        report.run('replication rule on %s:%s' % (scope, name), lambda scope=scope, name=name: check_rule(scope, name))
    for (scope, name), names in DATASETS.items():
        report.run('dataset %s:%s owned by %s' % (scope, name, SCOPES[scope]),
                   check_dataset(scope, name, SCOPES[scope], [(scope, child) for child in names]))

    report.section('Roles')
    report.run('reserved roles', check_reserved_roles)
    for role, (_, permissions) in ROLES.items():
        report.run('role %s, unlocked and assignable' % role, lambda role=role: check_role(role))
        report.run('role %s grants exactly %s' % (role, ', '.join('%s on %s' % permission for permission in sorted(permissions))),
                   check_role_permissions(role, permissions))
    for account, roles in ACCOUNT_ROLES.items():
        report.run('account %s holds %s' % (account, ', '.join(sorted(roles)) if roles else 'no role'), check_account_roles(account, roles))

    report.section('Nothing else')
    report.run('no other account', check_nothing_else(select(models.Account.account), set(ACCOUNTS), lambda row: row[0].external))
    report.run('no other scope', check_nothing_else(select(models.Scope.scope), set(SCOPES), lambda row: row[0].external))
    report.run('no other RSE', check_nothing_else(
        select(models.RSE.rse).where(models.RSE.deleted == False), {RSE}, lambda row: row[0]))  # noqa: E712
    report.run('no other role', check_nothing_else(select(models.Roles.role), set(ROLES) | set(RESERVED_ROLES), lambda row: row[0]))
    report.run('no other DID', check_nothing_else(
        select(models.DataIdentifier.scope, models.DataIdentifier.name), {'%s:%s' % did for did in list(FILES) + list(DATASETS)},
        lambda row: '%s:%s' % (row[0].external, row[1])))


# ------------------------------------------------------------------------------------------------
# Reset
# ------------------------------------------------------------------------------------------------

def _step(message: str) -> None:
    print('\n>>> %s' % message, flush=True)


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


def _bootstrap() -> None:
    """
    The part of `tools/bootstrap_tests.py` and `tools/sync_rses.py` the demo needs, and nothing more.

    root is made an admin, which lets its upload rules ignore the account limits, and the RSE is
    created with its protocols as `etc/rse_repository.json` defines them.
    """
    from rucio.client import Client
    from rucio.core.account import add_account_attribute

    with db_session(DatabaseOperationType.WRITE) as session:
        add_account_attribute(account=_account('root'), key='admin', value=True, session=session)  # bypass client as schema validation fails at API level

    with open(RSE_REPOSITORY) as handle:
        definition = json.load(handle)[RSE]
    client = Client()
    client.add_rse(RSE, deterministic=definition.get('deterministic', True), volatile=definition.get('volatile', False))
    for scheme, protocol in definition['protocols']['supported'].items():
        client.add_protocol(RSE, dict(protocol, scheme=scheme))


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
        for (scope, name), names in DATASETS.items():
            owner = _account(SCOPES[scope])
            add_did(_scope(scope), name, DIDType.DATASET, owner, session=session)
            attach_dids(_scope(scope), name, [{'scope': _scope(scope), 'name': child} for child in names], owner, session=session)


def _provision_roles() -> None:
    """Create the reserved roles and the CTAO roles. The CTAO roles are created directly, not synced from the policy package."""
    from rucio.core import role as role_core
    with db_session(DatabaseOperationType.WRITE) as session:
        role_core.setup_reserved_roles(session=session)
    with db_session(DatabaseOperationType.WRITE) as session:
        for role, (description, permissions) in ROLES.items():
            role_core.add_role(role, description, assignable=True, locked=False, session=session)
            for operation, scope_pattern in sorted(permissions):
                role_core.add_role_permission(role, scope_pattern, RoleOperationType(operation), session=session)
        for account, roles in ACCOUNT_ROLES.items():
            for role in sorted(roles):
                role_core.add_account_role(_account(account), role, session=session)


def reset(files_dir: str) -> None:
    _step('Purging and rebuilding the database schema')
    _rebuild_database()

    _step('Restarting the server')
    _restart_server()

    _step('Bootstrapping the root account and the RSE')
    _bootstrap()

    _step('Creating the accounts, the scopes and the roles')
    _provision_accounts_and_scopes()  # the role assignments need the accounts
    _provision_roles()

    _step('Uploading the files')
    _upload_files(files_dir)

    _step('Creating the datasets')
    _provision_datasets()


# ------------------------------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description='Check, and optionally rebuild from scratch, the CTAO RBAC demo environment.')
    parser.add_argument('--reset', action='store_true', help='DROP THE WHOLE DATABASE and recreate everything from scratch (default: dry run, only check)')
    parser.add_argument('--yes', action='store_true', help='do not ask for confirmation before --reset')
    parser.add_argument('--files-dir', default=os.path.join(SOURCE_PATH, 'container_upload', 'ctao'),
                        help='directory holding the files to upload, one sub-directory per scope (default: %(default)s)')
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
    print('The CTAO RBAC demo environment is complete.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
