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

import logging
from typing import TYPE_CHECKING, Any

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccessDenied, RucioException, RuleNotFound
from rucio.common.types import InternalScope
from rucio.common.utils import gateway_update_return_dict
from rucio.core import lock
from rucio.core import rule as core_rule
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DatabaseOperationType, DIDType
from rucio.db.sqla.session import db_session
from rucio.gateway.permission import has_permission

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


LOGGER = logging.getLogger('lock')
LOGGER.setLevel(logging.DEBUG)


def get_dataset_locks(
    issuer: str,
    scope: str,
    name: str,
    vo: str = DEFAULT_VO,
) -> 'Iterator[dict[str, Any]]':
    """
    Get the dataset locks of a dataset.

    :param issuer:         The account issuing the request.
    :param scope:          Scope of the dataset.
    :param name:           Name of the dataset.
    :param vo:             The VO to act on.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """
    internal_scope = InternalScope(scope, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='get_dataset_locks', kwargs={'scope': scope}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s cannot retrieve dataset locks of data identifier %s:%s in scope %s. The requested DID either does not exist or is outside the account\'s authorized scope.' % (issuer, scope, name, scope))

        locks = lock.get_dataset_locks(scope=internal_scope, name=name, session=session)

        for lock_object in locks:
            yield gateway_update_return_dict(lock_object, session=session)


def get_dataset_locks_bulk(
    issuer: str,
    dids: 'Iterable[dict[str, Any]]',
    vo: str = DEFAULT_VO,
) -> 'Iterator[dict[str, Any]]':
    """
    Get the dataset locks for multiple datasets or containers.

    :param dids:            List of dataset or container DIDs as dictionaries {"scope":..., "name":..., "type":...}
                            "type" is optional. If present, will be either DIDType.DATASET or DIDType.CONTAINER,
                            or string "dataset" or "container"
    :param vo:              The VO to act on.
    :return:                Generator of dicts describing found locks {'rse_id': ..., 'state': ...}. Duplicates are removed
    """

    if vo is None:
        vo = DEFAULT_VO

    dids_converted = []
    for did_in in dids:
        did = did_in.copy()
        if isinstance(did.get("type"), str):
            # convert DID type
            try:
                did["type"] = {
                    "dataset": DIDType.DATASET,
                    "container": DIDType.CONTAINER
                }[did["type"]]
            except KeyError:
                raise ValueError("Unknown DID type %(type)s" % did)
        if isinstance(did["scope"], str):
            did["scope"] = InternalScope(did["scope"], vo=vo)
        dids_converted.append(did)

    seen = set()

    with db_session(DatabaseOperationType.READ) as session:
        for did in dids_converted:
            auth_result = has_permission(issuer=issuer, vo=vo, action='get_dataset_locks_bulk', kwargs={'scope': str(did["scope"])}, session=session)
            if not auth_result.allowed:
                raise AccessDenied('Account %s cannot retrieve dataset locks of data identifier %s:%s in scope %s. The requested DID either does not exist or is outside the account\'s authorized scope.' % (issuer, str(did['scope']), did['name'], str(did['scope'])))

        for lock_info in lock.get_dataset_locks_bulk(dids_converted, session=session):
            # filter duplicates - same scope, name, rse_id, rule_id
            scope_str = str(lock_info["scope"])

            key = (scope_str, lock_info["name"], lock_info["rse_id"], lock_info["rule_id"])
            if key not in seen:
                seen.add(key)
                yield lock_info


def get_dataset_locks_by_rse(
    rse: str,
    vo: str = DEFAULT_VO,
) -> 'Iterator[dict[str, Any]]':
    """
    Get the dataset locks of an RSE.

    :param rse:            RSE name.
    :param vo:             The VO to act on.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)
        locks = lock.get_dataset_locks_by_rse_id(rse_id=rse_id, session=session)

        for lock_object in locks:
            yield gateway_update_return_dict(lock_object, session=session)


def get_replica_locks_for_rule_id(
    issuer: str,
    rule_id: str,
    vo: str = DEFAULT_VO,
) -> 'Iterator[dict[str, Any]]':
    """
    Get the replica locks for a rule_id.

    :param rule_id:     Rule ID.
    :param vo:          The VO to act on.
    :return:            List of dicts.
    """
    def access_denied_message() -> str:
        return 'Account %s cannot retrieve replica locks for replication rule with id %s. The requested rule id either does not exist or is outside the account\'s authorized scope.' % (issuer, rule_id)

    with db_session(DatabaseOperationType.READ) as session:
        try:
            rule = core_rule.get_rule(rule_id, session=session)
        except (RuleNotFound, RucioException):  # TODO: RucioException comes from badly formatted rule_id, so we should probably handle that differently.
            session.rollback()
            if has_permission(issuer=issuer, vo=vo, action='know_if_rule_exists', kwargs={}, session=session).allowed:
                raise RuleNotFound('Rule %s not found' % rule_id)
            else:
                raise AccessDenied(access_denied_message())

        scope_str = str(rule['scope'])
        auth_result = has_permission(issuer=issuer, vo=vo, action='get_replica_locks_for_rule_id', kwargs={'scope': scope_str}, session=session)
        if not auth_result.allowed:
            raise AccessDenied(access_denied_message())

        locks = lock.get_replica_locks_for_rule_id(rule_id=rule_id, session=session)

        for lock_object in locks:
            if lock_object['scope'].vo != vo:  # rule is on a different VO, so don't return any locks
                LOGGER.debug('rule id %s is not present on VO %s' % (rule_id, vo))
                break

            yield gateway_update_return_dict(lock_object, session=session)
