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
Test data shared by the RBAC REST API tests (`test_rbac_restapi.py` and `test_rbac_generic_errors.py`).

The response filtering of the RBAC can only be observed on data that crosses scopes, e.g. a dataset
in a scope an account can read which contains a file in a scope the account cannot read. The data
provisioned by the dev environment bootstrap does not cross scopes, so the layout below is created
once per test module, directly through the core, on an RSE of its own so that listings by RSE only
return what is created here:

    alice:<prefix>_ds           dataset, contains alice:<prefix>_file_a and root:<prefix>_file_r
                                rule `rule_a` (account alice, grouping DATASET) on the RSE
    root:<prefix>_ds_r          dataset, contains alice:<prefix>_file_a and root:<prefix>_file_r
                                rule `rule_r` (account root, grouping DATASET) on the RSE
    alice:<prefix>_hist_ds      dataset, alice:<prefix>_file_a and root:<prefix>_file_r were attached then detached
    alice:<prefix>.zip          archive, constituents alice:<prefix>_const_a and root:<prefix>_const_r

Both files are also declared suspicious on the RSE, both datasets have a collection replica on the
RSE and a lifetime exception. Each account thus finds, next to every alice item, a root item it may
or may not be allowed to see.

The names never contain an account name ('root', 'alice', 'bob'), since the generic error tests
normalise the account names out of the error messages.
"""

from dataclasses import dataclass
from uuid import uuid4

from rucio.common.types import InternalAccount, InternalScope
from rucio.core import did as did_core
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.db.sqla import models
from rucio.db.sqla.constants import BadFilesStatus, DatabaseOperationType, DIDType, LifetimeExceptionsState
from rucio.db.sqla.session import db_session

_BYTES = 1
_ADLER32 = '0cc737eb'


@dataclass(frozen=True)
class RBACTestData:
    """The DIDs are given as 'scope:name' strings, as the REST API tests use them."""
    rse: str
    rse_id: str
    file_a: str
    file_r: str
    dataset_a: str
    dataset_r: str
    history_dataset: str
    archive: str
    constituent_a: str
    constituent_r: str
    rule_a: str
    rule_r: str
    pfn_a: str
    pfn_r: str
    exception_a: str
    exception_r: str


def _did(scope: InternalScope, name: str) -> dict:
    return {'scope': scope, 'name': name}


def _file(scope: InternalScope, name: str) -> dict:
    return {'scope': scope, 'name': name, 'bytes': _BYTES, 'adler32': _ADLER32}


def _external(did: dict) -> str:
    return '%s:%s' % (did['scope'].external, did['name'])


def create_rbac_test_data(vo: str) -> RBACTestData:
    """Create the cross-scope layout described in the module docstring and return what the tests need to reach it."""
    prefix = 'rbac_%s' % uuid4().hex[:12]
    alice, root = InternalAccount('alice', vo=vo), InternalAccount('root', vo=vo)
    scope_a, scope_r = InternalScope('alice', vo=vo), InternalScope('root', vo=vo)

    file_a, file_r = _file(scope_a, '%s_file_a' % prefix), _file(scope_r, '%s_file_r' % prefix)
    constituent_a, constituent_r = _file(scope_a, '%s_const_a' % prefix), _file(scope_r, '%s_const_r' % prefix)
    archive = _file(scope_a, '%s.zip' % prefix)
    dataset_a, dataset_r = _did(scope_a, '%s_ds' % prefix), _did(scope_r, '%s_ds_r' % prefix)
    history_dataset = _did(scope_a, '%s_hist_ds' % prefix)
    files = [_did(file_a['scope'], file_a['name']), _did(file_r['scope'], file_r['name'])]

    rse = 'RBAC_%s' % uuid4().hex[:12].upper()

    with db_session(DatabaseOperationType.WRITE) as session:
        rse_id = rse_core.add_rse(rse, vo=vo, session=session)
        rse_core.add_protocol(rse_id=rse_id, parameter={
            'scheme': 'file',
            'hostname': 'localhost',
            'port': 0,
            'prefix': '/tmp/rucio_rse/%s/' % rse,
            'impl': 'rucio.rse.protocols.posix.Default',
            'domains': {
                'wan': {'read': 1, 'write': 1, 'delete': 1, 'third_party_copy_read': 1, 'third_party_copy_write': 1},
                'lan': {'read': 1, 'write': 1, 'delete': 1},
            },
        }, session=session)

        replica_core.add_replicas(rse_id=rse_id, files=[file_a, file_r, constituent_a, constituent_r, archive], account=root, session=session)

        # datasets whose content crosses scopes
        for dataset, account in ((dataset_a, alice), (dataset_r, root)):
            did_core.add_did(scope=dataset['scope'], name=dataset['name'], did_type=DIDType.DATASET, account=account, session=session)
            did_core.attach_dids(scope=dataset['scope'], name=dataset['name'], dids=files, account=account, session=session)

        # a dataset whose content history crosses scopes
        did_core.add_did(scope=history_dataset['scope'], name=history_dataset['name'], did_type=DIDType.DATASET, account=alice, session=session)
        did_core.attach_dids(scope=history_dataset['scope'], name=history_dataset['name'], dids=files, account=alice, session=session)
        did_core.detach_dids(scope=history_dataset['scope'], name=history_dataset['name'], dids=files, session=session)

        # an archive whose constituents cross scopes
        did_core.attach_dids(scope=archive['scope'], name=archive['name'], account=root, session=session,
                             dids=[_did(constituent_a['scope'], constituent_a['name']), _did(constituent_r['scope'], constituent_r['name'])])

        # rules on both datasets: each one locks a file of each scope, and creates a dataset lock on the RSE
        rule_ids = {}
        for dataset, account in ((dataset_a, alice), (dataset_r, root)):
            rule_ids[dataset['name']] = rule_core.add_rule(dids=[dataset], account=account, copies=1, rse_expression=rse, grouping='DATASET',
                                                          weight=None, lifetime=None, locked=False, subscription_id=None,
                                                          ignore_account_limit=True, session=session)[0]

        # both files are suspicious on the RSE
        replica_core.declare_bad_file_replicas([dict(did, rse_id=rse_id) for did in files], reason='RBAC test', issuer=root,
                                               status=BadFilesStatus.SUSPICIOUS, session=session)

        # lifetime exceptions of both datasets (their collection replicas on the RSE come with the rules above)
        exception_ids = {}
        for dataset, account in ((dataset_a, alice), (dataset_r, root)):
            exception = models.LifetimeException(scope=dataset['scope'], name=dataset['name'], did_type=DIDType.DATASET, account=account,
                                                 comments='RBAC test', state=LifetimeExceptionsState.WAITING)
            session.add(exception)
            session.flush()
            exception_ids[dataset['name']] = exception.id

    # the PFNs are resolved once everything is committed, since the RSE protocols are looked up in a session of their own
    pfns = {}
    for replica in replica_core.list_replicas(dids=files):
        # the files only have a replica on the RSE created above
        pfns[replica['name']] = next(iter(replica['rses'].values()))[0]

    return RBACTestData(
        rse=rse,
        rse_id=rse_id,
        file_a=_external(file_a),
        file_r=_external(file_r),
        dataset_a=_external(dataset_a),
        dataset_r=_external(dataset_r),
        history_dataset=_external(history_dataset),
        archive=_external(archive),
        constituent_a=_external(constituent_a),
        constituent_r=_external(constituent_r),
        rule_a=rule_ids[dataset_a['name']],
        rule_r=rule_ids[dataset_r['name']],
        pfn_a=pfns[file_a['name']],
        pfn_r=pfns[file_r['name']],
        exception_a=str(exception_ids[dataset_a['name']]),
        exception_r=str(exception_ids[dataset_r['name']]),
    )
