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

from typing import TYPE_CHECKING, Any, Optional

import rucio.core.scope
from rucio.common.constants import RBAC_DELETE_METADATA_KEYS, RBAC_PROTECTED_METADATA_KEYS, RseAttr
from rucio.common.exception import DataIdentifierNotFound, ReplicaNotFound, RuleNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import role as role_core
from rucio.core.account import has_account_attribute, list_account_attributes
from rucio.core.did import get_did
from rucio.core.identity import exist_identity_account
from rucio.core.lifetime_exception import list_exceptions
from rucio.core.lock import get_replica_locks
from rucio.core.replica import get_replica
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rule
from rucio.db.sqla.constants import DidOperationType, IdentityType, ReplicaState

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from sqlalchemy.orm import Session


# Options of a replication rule that RBAC allows a non-admin account to update, provided it may alter the rule
# (owning it, or DELETE on its DID), see `_rbac_can_alter_rule`.
RBAC_UPDATABLE_RULE_OPTIONS = {'lifetime', 'comment', 'notify', 'purge_replicas'}

# Suffixes of the RSEs on which RBAC allows to update and delete replicas.
RBAC_REPLICA_RSE_SUFFIXES = ('SCRATCHDISK', 'USERDISK', 'MOCK', 'LOCALGROUPDISK')


def has_permission(issuer: "InternalAccount", action: str, kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer: Account identifier which issues the command..
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    perm = {'add_account': perm_add_account,
            'del_account': perm_del_account,
            'update_account': perm_update_account,
            'add_rule': perm_add_rule,
            'add_subscription': perm_add_subscription,
            'add_scope': perm_add_scope,
            'update_scope': perm_update_scope,
            'add_rse': perm_add_rse,
            'update_rse': perm_update_rse,
            'add_protocol': perm_add_protocol,
            'del_protocol': perm_del_protocol,
            'update_protocol': perm_update_protocol,
            'declare_bad_file_replicas': perm_declare_bad_file_replicas,
            'declare_suspicious_file_replicas': perm_declare_suspicious_file_replicas,
            'add_replicas': perm_add_replicas,
            'delete_replicas': perm_delete_replicas,
            'skip_availability_check': perm_skip_availability_check,
            'update_replicas_states': perm_update_replicas_states,
            'add_rse_attribute': perm_add_rse_attribute,
            'del_rse_attribute': perm_del_rse_attribute,
            'del_rse': perm_del_rse,
            'del_rule': perm_del_rule,
            'update_rule': perm_update_rule,
            'approve_rule': perm_approve_rule,
            'update_subscription': perm_update_subscription,
            'reduce_rule': perm_reduce_rule,
            'move_rule': perm_move_rule,
            'get_auth_token_user_pass': perm_get_auth_token_user_pass,
            'get_auth_token_gss': perm_get_auth_token_gss,
            'get_auth_token_x509': perm_get_auth_token_x509,
            'add_account_identity': perm_add_account_identity,
            'add_did': perm_add_did,
            'add_dids': perm_add_dids,
            'attach_dids': perm_attach_dids,
            'detach_dids': perm_detach_dids,
            'attach_dids_to_dids': perm_attach_dids_to_dids,
            'create_did_sample': perm_create_did_sample,
            'set_metadata': perm_set_metadata,
            'set_metadata_bulk': perm_set_metadata_bulk,
            'set_status': perm_set_status,
            'queue_requests': perm_queue_requests,
            'set_rse_usage': perm_set_rse_usage,
            'set_rse_limits': perm_set_rse_limits,
            'list_requests': perm_list_requests,
            'list_requests_history': perm_list_requests_history,
            'get_request_by_did': perm_get_request_by_did,
            'get_request_history_by_did': perm_get_request_history_by_did,
            'cancel_request': perm_cancel_request,
            'get_next': perm_get_next,
            'set_local_account_limit': perm_set_local_account_limit,
            'set_global_account_limit': perm_set_global_account_limit,
            'delete_local_account_limit': perm_delete_local_account_limit,
            'delete_global_account_limit': perm_delete_global_account_limit,
            'config_sections': perm_config,
            'config_add_section': perm_config,
            'config_has_section': perm_config,
            'config_options': perm_config,
            'config_has_option': perm_config,
            'config_get': perm_config,
            'config_items': perm_config,
            'config_set': perm_config,
            'config_remove_section': perm_config,
            'config_remove_option': perm_config,
            'get_local_account_usage': perm_get_local_account_usage,
            'get_global_account_usage': perm_get_global_account_usage,
            'add_attribute': perm_add_account_attribute,
            'del_attribute': perm_del_account_attribute,
            'list_heartbeats': perm_list_heartbeats,
            'resurrect': perm_resurrect,
            'update_lifetime_exceptions': perm_update_lifetime_exceptions,
            'get_auth_token_ssh': perm_get_auth_token_ssh,
            'get_signed_url': perm_get_signed_url,
            'add_bad_pfns': perm_add_bad_pfns,
            'del_account_identity': perm_del_account_identity,
            'del_identity': perm_del_identity,
            'remove_did_from_followed': perm_remove_did_from_followed,
            'remove_dids_from_followed': perm_remove_dids_from_followed,
            'export': perm_export,
            'list_transfer_limits': perm_list_transfer_limits,
            'set_transfer_limit': perm_set_transfer_limit,
            'delete_transfer_limit': perm_delete_transfer_limit,
            'add_opendata_did': perm_default,
            'update_opendata_did': perm_default,
            'delete_opendata_did': perm_default,
            'delete_metadata': perm_delete_metadata,
            'list_account_roles': perm_list_account_roles,
            'list_role_permissions': perm_list_role_permissions,
            'list_dids': perm_read_data,
            'list_parent_dids': perm_read_data,
            'get_did': perm_read_data,
            'get_metadata': perm_read_data,
            'get_metadata_bulk': perm_read_data,
            'list_content': perm_read_data,
            'list_content_history': perm_read_data,
            'list_files': perm_read_data,
            'scope_list': perm_read_data,
            'list_archive_content': perm_read_data,
            'get_users_following_did': perm_read_data,
            'add_did_to_followed': perm_read_data,
            'list_replication_rule_history': perm_read_data,
            'list_replication_rule_full_history': perm_read_data,
            'get_replication_rule': perm_read_data,
            'examine_replication_rule': perm_read_data,
            'get_dataset_locks': perm_read_data,
            'get_dataset_locks_bulk': perm_read_data,
            'list_associated_replication_rules_for_file': perm_read_data,
            'list_replicas': perm_read_data,
            'list_dataset_replicas': perm_read_data,
            'list_dataset_replicas_bulk': perm_read_data,
            'list_dataset_replicas_vp': perm_read_data,
            'get_replica_locks_for_rule_id': perm_read_data}

    return perm.get(action, perm_default)(issuer=issuer, kwargs=kwargs, session=session)


def _is_root(issuer) -> bool:
    return issuer.external == 'root'


def _use_roles() -> bool:
    """
    Checks if RBAC is enabled, see :func:`rucio.core.role.is_rbac_enabled`. Every role check of this policy
    is guarded by it, so that without RBAC this policy behaves as it does in standard Rucio.

    :returns: True if roles grant permissions, otherwise False
    """
    return role_core.is_rbac_enabled()


def _is_admin(issuer: "InternalAccount", session: "Session") -> bool:
    """
    Checks if an account is an admin: it holds the admin role if RBAC is enabled,
    otherwise it has the 'admin' account attribute.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is admin, otherwise False
    """
    if _use_roles():
        return role_core.has_admin_role(account=issuer, session=session)
    return has_account_attribute(account=issuer, key='admin', session=session)


def _did_exists(scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if a DID exists.

    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use
    :returns: True if the DID exists, otherwise False
    """
    try:
        get_did(scope=scope, name=name, session=session)
        return True
    except DataIdentifierNotFound:
        return False


def _internal_dids(issuer: "InternalAccount", dids: "Iterable[Mapping[str, Any]]") -> "list[tuple[InternalScope, str]]":
    """
    The distinct DIDs given as dictionaries with a 'scope' and a 'name', as (scope, name), external scopes being resolved in the VO of the issuer.

    :param issuer: Account identifier which issues the command.
    :param dids: The DIDs.
    :returns: The DIDs, in the order they are first given.
    """
    internal = {}
    for did in dids:
        scope = did['scope'] if isinstance(did['scope'], InternalScope) else InternalScope(did['scope'], vo=issuer.vo)
        internal.setdefault((scope, did['name']), None)
    return list(internal)


def _held_by_other_accounts(issuer: "InternalAccount", rse_id: str, scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if a replica is locked by a rule of another account. Deleting or invalidating such a replica would break
    the rules, and the data, of other accounts, so no role nor ownership grants it: only root and admins may.

    :param issuer: Account identifier which issues the command.
    :param rse_id: The id of the RSE of the replica.
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param session: The DB session to use
    :returns: True if a rule of another account locks the replica, otherwise False
    """
    return any(lock.account != issuer for lock in get_replica_locks(scope=scope, name=name, restrict_rses=[rse_id], session=session))


def _is_replica_being_copied(rse_id: str, scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if a replica is being copied ('C'), as while it is uploaded.

    :param rse_id: The id of the RSE of the replica.
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param session: The DB session to use
    :returns: True if the replica is being copied, otherwise False (also if it does not exist)
    """
    try:
        return get_replica(rse_id=rse_id, scope=scope, name=name, session=session)['state'] == ReplicaState.COPYING
    except ReplicaNotFound:
        return False


# ----- Ownership -----


def _owns_did(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Determines RBAC ownership of an existing DID. A DID is owned by its account only if a role grants that account READ
    on at least one DID of its scope, see :func:`rucio.core.role.has_any_scope_prefix_access`. The owner of a DID may
    then do anything on it, as if a role granted it every operation.

    The owner of the scope is not checked here: like in standard Rucio, the permission functions check it on their own,
    see :func:`rucio.core.scope.is_scope_owner`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use.
    :returns: True if the account owns the DID, otherwise False (also if it does not exist)
    """
    # Owning a DID in a scope requires to have at least one READ entry on that scope.
    if not role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session):
        return False
    try:
        return get_did(scope=scope, name=name, session=session)['account'] == issuer
    except DataIdentifierNotFound:
        return False


# ----- RBAC helpers -----


def _rbac_permission_access(issuer: "InternalAccount", scope: "InternalScope", name: Optional[str], operation: DidOperationType, session: "Session") -> bool:
    """
    Checks if a role grants an account an operation on a DID, or on a whole scope without `name`, see :func:`rucio.core.role.has_permission`.
    Like every `_rbac_*` helper, it does not check whether RBAC is enabled: the caller does, see :func:`_use_roles`.

    A DID is decided, within each role, by the most specific DID pattern matching it: e.g. 'rw' on 'data:*' and 'r' on
    'data:raw*' grant 'rw' on 'data:calib1' but only 'r' on 'data:raw1'. A whole scope is only granted by a pattern
    covering it ('data:*'), and only if no name pattern ('data:raw*') of the same role withdraws the operation from
    some of its DIDs, see :class:`rucio.core.role.DidAccess`.

    Only the roles are checked: owning the scope (see :func:`rucio.core.scope.is_scope_owner`) or the DID (see
    :func:`_owns_did`) grants every operation as well, which the permission functions check on their own.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope to check, or the scope of the DID.
    :param name: The name of the DID, None to check the whole scope.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param session: The DB session to use
    :returns: True if a role grants the operation, otherwise False
    """
    request = role_core.DidPermissionRequest(operation=operation, scope=scope, name=name)
    return role_core.has_permission(account=issuer, request=request, session=session)


def _rbac_can_alter_rule(issuer: "InternalAccount", rule_id: str, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to update, reduce, move or delete a replication rule: owning it, owning the scope
    of its DID, or DELETE on its DID. A rule is owned by its account only if a role grants that account READ on at
    least one DID of the scope of its DID, as a DID is, see :func:`_owns_did`.

    :param issuer: Account identifier which issues the command.
    :param rule_id: The id of the rule.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False (also if the rule does not exist)
    """
    try:
        rule = get_rule(rule_id=rule_id, session=session)
    except RuleNotFound:
        return False
    return (rule['account'] == issuer and role_core.has_any_scope_prefix_access(account=issuer, scope=rule['scope'], operation=DidOperationType.READ, session=session))\
        or rucio.core.scope.is_scope_owner(scope=rule['scope'], account=issuer, session=session)\
        or _rbac_permission_access(issuer, rule['scope'], rule['name'], DidOperationType.DELETE, session)


def _rbac_can_alter_metadata(issuer: "InternalAccount", scope: "InternalScope", name: str, keys: "Iterable[str]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to set metadata keys on an existing DID, the owner of its scope being checked
    before by the permission functions: it alters the DID, which requires owning it (see :func:`_owns_did`) or DELETE
    on it. The keys held by Rucio itself (see RBAC_PROTECTED_METADATA_KEYS) are never granted.
    A recursive update, which rewrites the metadata of the whole content, is granted by no role: the permission
    functions refuse it before calling this check.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param keys: The metadata keys to set.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    if set(keys) & RBAC_PROTECTED_METADATA_KEYS:
        return False
    return _owns_did(issuer, scope, name, session)\
        or _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session)


def _rbac_can_attach_dids(issuer: "InternalAccount", dids: "Iterable[Mapping[str, Any]]", registered: bool, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to attach DIDs to a collection, whoever may write on the collection itself:
    reading each of them, owning its scope or itself (see :func:`_owns_did`), or READ on it. When they are registered
    on an RSE along with the attachment (`registered`), a file which does not exist yet is created, which requires
    owning its scope or WRITE on it instead.

    :param issuer: Account identifier which issues the command.
    :param dids: The attached DIDs, each with its 'scope' and 'name'.
    :param registered: Whether the attached files are registered on an RSE.
    :param session: The DB session to use
    :returns: True if RBAC grants every DID, otherwise False
    """
    for scope, name in _internal_dids(issuer, dids):
        if rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session):
            continue
        if registered and not _did_exists(scope, name, session):
            if not _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session):
                return False
        elif not (_owns_did(issuer, scope, name, session) or _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)):
            return False
    return True


# ----- Permission functions -----


def perm_default(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Default permission.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_add_rse(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_update_rse(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_add_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if kwargs['account'] == issuer and not kwargs['locked']:
        # With RBAC, a rule copies data, so it requires to read every DID it is on: owning its scope or itself, or READ on it.
        return not _use_roles() or _is_root(issuer) or _is_admin(issuer, session)\
            or all(rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
                   or _owns_did(issuer, scope, name, session)
                   or _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)
                   for scope, name in _internal_dids(issuer, kwargs['dids']))
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return False


def perm_add_subscription(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add a subscription.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return False


def perm_add_rse_attribute(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add a RSE attribute.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return False


def perm_del_rse_attribute(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete a RSE attribute.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return False


def perm_del_rse(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete a RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_add_account(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_del_account(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can del an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_update_account(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_add_scope(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add a scop to a account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_update_scope(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update a scop to a account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) \
        or _is_admin(issuer, session) \
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_get_auth_token_user_pass(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['username'], type_=IdentityType.USERPASS, account=kwargs['account'], session=session):
        return True
    return False


def perm_get_auth_token_gss(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['gsscred'], type_=IdentityType.GSS, account=kwargs['account'], session=session):
        return True
    return False


def perm_get_auth_token_x509(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if a user can request a token with user_pass for an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if exist_identity_account(identity=kwargs['dn'], type_=IdentityType.X509, account=kwargs['account'], session=session):
        return True
    return False


def perm_add_account_identity(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """

    return _is_root(issuer) or _is_admin(issuer, session)


def perm_del_account_identity(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete an identity to an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """

    return _is_root(issuer) or _is_admin(issuer, session)


def perm_del_identity(issuer: "InternalAccount", kwargs, session: "Session") -> bool:
    """
    Checks if an account can delete an identity.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """

    return _is_root(issuer) or issuer.external in kwargs.get('accounts')


def perm_add_did(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add an data identifier to a scope.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    # Check the accounts of the issued rules
    if not _is_root(issuer) and not _is_admin(issuer, session):
        for rule in kwargs.get('rules', []):
            if rule['account'] != issuer:
                return False

    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    scope, name = kwargs['scope'], kwargs['name']
    owns_scope = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
    if not _use_roles():
        return owns_scope or scope.external == 'mock'

    # With RBAC, the new DID will be owned by its 'account', the issuer if none is given. The gateway turns the 'account'
    # of the permission arguments into an `InternalAccount` even when none is given (see
    # :func:`rucio.gateway.permission.has_permission`), so an account without external name stands for no account. The
    # 'account' of a DID created in bulk is left as given, an external name or nothing.
    owner = kwargs.get('account')
    if isinstance(owner, InternalAccount):
        owner = issuer if owner.external is None else owner
    else:
        owner = InternalAccount(owner, vo=issuer.vo) if owner else issuer

    if not owns_scope and scope.external != 'mock':
        # A role grants to create a DID with WRITE on it, which the account must own: creating DIDs for other accounts
        # is left to root, admins and the owner of the scope, as in standard Rucio.
        if owner != issuer or not _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session):
            return False
        # Its metadata ('meta', and a 'lifetime' given apart, which sets the same key) is checked as if set on it right
        # after the creation by its owner: the keys held by Rucio are refused, and those leading to its removal require
        # DELETE on it or owning it, which requires READ on at least one DID of its scope, as for an existing DID (see
        # :func:`_owns_did`).
        keys = set(kwargs.get('meta') or {}) | ({'lifetime'} if kwargs.get('lifetime') else set())
        if keys & RBAC_PROTECTED_METADATA_KEYS:
            return False
        if keys & RBAC_DELETE_METADATA_KEYS\
                and not _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session)\
                and not role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session):
            return False

    # What is attached to and ruled on the new DID is checked whatever lets the account create it: its rules require to
    # read it like any rule (see :func:`perm_add_rule`), and its content to be attachable (see :func:`_rbac_can_attach_dids`).
    if kwargs.get('rules')\
            and not owns_scope\
            and not _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)\
            and not (owner == issuer and role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session)):
        return False
    return _rbac_can_attach_dids(issuer, kwargs.get('dids') or [], bool(kwargs.get('rse_id')), session)


def perm_add_dids(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can bulk add data identifiers.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    # Check the accounts of the issued rules
    return all(perm_add_did(issuer, kwargs=did, session=session) for did in kwargs['dids'])


def perm_attach_dids(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can append an data identifier to the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    allowed = rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and (_owns_did(issuer, kwargs['scope'], kwargs['name'], session)
                              or _rbac_permission_access(issuer, kwargs['scope'], kwargs['name'], DidOperationType.WRITE, session)))
    # With RBAC, the attached DIDs are checked whatever lets the account write into the collection.
    attachment = kwargs['attachment']
    return allowed and (not _use_roles() or _rbac_can_attach_dids(issuer, attachment.get('dids', []), bool(attachment.get('rse_id')), session))


def perm_attach_dids_to_dids(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can append an data identifier to the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    for attachment in kwargs['attachments']:
        allowed = rucio.core.scope.is_scope_owner(attachment['scope'], issuer, session=session)\
            or (_use_roles() and (_owns_did(issuer, attachment['scope'], attachment['name'], session)
                                  or _rbac_permission_access(issuer, attachment['scope'], attachment['name'], DidOperationType.WRITE, session)))
        # With RBAC, the attached DIDs are checked whatever lets the account write into the collection.
        if not allowed or (_use_roles() and not _rbac_can_attach_dids(issuer, attachment.get('dids', []), bool(attachment.get('rse_id')), session)):
            return False
    return True


def perm_create_did_sample(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can create a sample of a data identifier collection.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and _rbac_permission_access(issuer, kwargs['scope'], kwargs.get('name'), DidOperationType.WRITE, session))


def perm_del_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an issuer can delete a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return _use_roles() and _rbac_can_alter_rule(issuer, kwargs['rule_id'], session)


def perm_update_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an issuer can update a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return _use_roles()\
        and set(kwargs['options']).issubset(RBAC_UPDATABLE_RULE_OPTIONS)\
        and _rbac_can_alter_rule(issuer, kwargs['rule_id'], session)


def perm_approve_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an issuer can approve a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return False


def perm_reduce_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an issuer can reduce a replication rule.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    return _use_roles() and _rbac_can_alter_rule(issuer, kwargs['rule_id'], session)


def perm_move_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an issuer can move a replication rule.

    :param issuer:   Account identifier which issues the command.
    :param kwargs:   List of arguments for the action.
    :param session: The DB session to use
    :returns:        True if account is allowed to call the API call, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    # As for adding a rule, RBAC does not allow to lock the new rule nor to give it to another account.
    return _use_roles()\
        and not kwargs['override'].get('locked')\
        and kwargs['override'].get('account', issuer) == issuer\
        and _rbac_can_alter_rule(issuer, kwargs['rule_id'], session)


def perm_update_subscription(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update a subscription.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True

    return False


def perm_detach_dids(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can detach an data identifier from the other data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    # With RBAC, unlike attaching, detaching removes content: owning the collection or DELETE on it removes any content,
    # WRITE on it only the DIDs the account owns.
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and (_owns_did(issuer, kwargs['scope'], kwargs['name'], session)
                              or _rbac_permission_access(issuer, kwargs['scope'], kwargs['name'], DidOperationType.DELETE, session)
                              or (_rbac_permission_access(issuer, kwargs['scope'], kwargs['name'], DidOperationType.WRITE, session)
                                  and all(_owns_did(issuer, scope, name, session) for scope, name in _internal_dids(issuer, kwargs['dids'])))))


def perm_set_metadata_bulk(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session) or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or (_use_roles() and not kwargs.get('recursive') and _rbac_can_alter_metadata(issuer, kwargs['scope'], kwargs['name'], kwargs['meta'], session))


def perm_set_metadata(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session) or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or (_use_roles() and not kwargs.get('recursive') and _rbac_can_alter_metadata(issuer, kwargs['scope'], kwargs['name'], [kwargs['key']], session))


def perm_set_status(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set status on an data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if kwargs.get('open', False):
        if not _is_root(issuer) and not _is_admin(issuer, session):
            return False

    # Closing a collection cannot be undone but by root/admin, freezes its content for every account and makes it
    # removable once empty, so no role grants it: it is left to root/admin and to the owner of the scope.
    return _is_root(issuer) or _is_admin(issuer, session) or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)


def perm_add_protocol(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add a protocol to an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_del_protocol(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete protocols from an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_update_protocol(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update protocols of an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_declare_bad_file_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can declare bad file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_declare_suspicious_file_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can declare suspicious file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_add_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    user_rse = str(kwargs.get('rse', '')).endswith('SCRATCHDISK')\
        or str(kwargs.get('rse', '')).endswith('USERDISK')\
        or str(kwargs.get('rse', '')).endswith('MOCK')\
        or str(kwargs.get('rse', '')).endswith('LOCALGROUPDISK')
    if not user_rse or not _use_roles():
        return user_rse
    # With RBAC, a replica of an existing file, given in 'dids', only copies data, which requires to read the file: owning
    # its scope or itself, or READ on it. A file which does not exist yet is created along with its replica, which the
    # gateway checks as the creation of a DID ('add_dids'). Without the DIDs, READ is required on the 'scopes' of the files.
    if not kwargs.get('dids'):
        scopes = {scope if isinstance(scope, InternalScope) else InternalScope(scope, vo=issuer.vo) for scope in kwargs.get('scopes') or []}
        return all(rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
                   or _rbac_permission_access(issuer, scope, None, DidOperationType.READ, session)
                   for scope in scopes)
    return all(not _did_exists(scope, name, session)
               or rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
               or _owns_did(issuer, scope, name, session)
               or _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)
               for scope, name in _internal_dids(issuer, kwargs['dids']))


def perm_skip_availability_check(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can skip the availabity check to add/delete file replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_delete_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    # With RBAC, on the RSEs listed in RBAC_REPLICA_RSE_SUFFIXES only: deleting a replica alters its file, given in 'dids',
    # which requires owning its scope or itself, or DELETE on it. No replica may be locked by a rule of another account,
    # since deleting replicas ignores the locks on them. Without the DIDs, the locks cannot be checked: it is left to root and admins.
    if not _use_roles() or not str(kwargs['rse']).endswith(RBAC_REPLICA_RSE_SUFFIXES) or not kwargs['scopes'] or not kwargs.get('dids'):
        return False
    return all((rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
                or _owns_did(issuer, scope, name, session)
                or _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session))
               and not _held_by_other_accounts(issuer, kwargs['rse_id'], scope, name, session)
               for scope, name in _internal_dids(issuer, kwargs['dids']))


def perm_update_replicas_states(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update the states of replicas.

    With RBAC, on the RSEs listed in RBAC_REPLICA_RSE_SUFFIXES only, for each file given in 'dids' with its requested
    'state' and optionally a new 'path': a replica locked by a rule of another account is left to root and admins, since
    its state completes or fails their locks. Otherwise, updating it alters the file, which requires owning its scope or
    itself, or DELETE on it. Finishing an upload is the only exception, since it completes a registration the account
    was allowed to make: marking available ('A') a replica being copied ('C'), without a new path, requires what
    registering it does (see :func:`perm_add_replicas`): WRITE on a file of its own (it uploads a new file, even
    without reading the scope), or reading the file (it uploads a copy of an existing file).

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    if not _use_roles() or not str(kwargs['rse']).endswith(RBAC_REPLICA_RSE_SUFFIXES) or not kwargs['scopes'] or not kwargs.get('dids'):
        return False
    for file in kwargs['dids']:
        (scope, name), = _internal_dids(issuer, [file])
        if _held_by_other_accounts(issuer, kwargs['rse_id'], scope, name, session):
            return False
        if rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)\
                or _owns_did(issuer, scope, name, session)\
                or _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session):
            continue
        try:
            finishes_upload = ReplicaState(file.get('state')) == ReplicaState.AVAILABLE and not file.get('path')
        except ValueError:
            finishes_upload = False
        if not finishes_upload or not _is_replica_being_copied(kwargs['rse_id'], scope, name, session):
            return False
        if not (get_did(scope=scope, name=name, session=session)['account'] == issuer and _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session))\
                and not _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session):
            return False
    return True


def perm_queue_requests(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can submit transfer or deletion requests on destination RSEs for data identifiers.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_list_requests(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list requests.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_list_requests_history(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list historical requests.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_get_request_by_did(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get a request by DID.

    Every account can, unless RBAC is enabled: a transfer request tells where the replica of the DID comes from and
    goes to, its source and destination URLs included, so it then requires to read the data of the DID like its
    replicas do, see :func:`perm_read_data`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_read_data(issuer, kwargs, session)


def perm_get_request_history_by_did(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get a historical request by DID.

    Only root and admins can, unless RBAC is enabled: a past transfer request is as sensitive as the current one, so
    whoever reads the data of the DID may then get it as well, see :func:`perm_get_request_by_did`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)\
        or (_use_roles() and perm_read_data(issuer, kwargs, session))


def perm_cancel_request(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can cancel a request.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_get_next(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can retrieve the next request matching the request type and state.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_set_rse_usage(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set RSE usage information.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer)


def perm_set_rse_limits(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set RSE limits.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_set_local_account_limit(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set an account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    # Check if user is a country admin
    admin_in_country = []
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])
    if admin_in_country and list_rse_attributes(rse_id=kwargs['rse_id'], session=session).get(RseAttr.COUNTRY) in admin_in_country:
        return True
    return False


def perm_set_global_account_limit(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set a global account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    # Check if user is a country admin
    admin_in_country = set()
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.add(kv['key'].partition('-')[2])
    resolved_rse_countries = {list_rse_attributes(rse_id=rse['rse_id'], session=session).get(RseAttr.COUNTRY)
                              for rse in parse_expression(kwargs['rse_expression'], filter_={'vo': issuer.vo}, session=session)}
    if resolved_rse_countries.issubset(admin_in_country):
        return True
    return False


def perm_delete_local_account_limit(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete an account limit.

    :param account: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    # Check if user is a country admin
    admin_in_country = []
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.append(kv['key'].partition('-')[2])
    if admin_in_country and list_rse_attributes(rse_id=kwargs['rse_id'], session=session).get(RseAttr.COUNTRY) in admin_in_country:
        return True
    return False


def perm_delete_global_account_limit(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete a global account limit.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    # Check if user is a country admin
    admin_in_country = set()
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            admin_in_country.add(kv['key'].partition('-')[2])
    if admin_in_country:
        resolved_rse_countries = {list_rse_attributes(rse_id=rse['rse_id'], session=session).get(RseAttr.COUNTRY)
                                  for rse in parse_expression(kwargs['rse_expression'], filter_={'vo': issuer.vo}, session=session)}
        if resolved_rse_countries.issubset(admin_in_country):
            return True
    return False


def perm_config(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can read/write the configuration.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_get_local_account_usage(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get the account usage of an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session) or kwargs.get('account') == issuer:
        return True
    # Check if user is a country admin
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            return True
    return False


def perm_get_global_account_usage(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get the account usage of an account.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session) or kwargs.get('account') == issuer:
        return True

    # Check if user is a country admin for all involved countries
    for kv in list_account_attributes(account=issuer, session=session):
        if kv['key'].startswith('country-') and kv['value'] == 'admin':
            return True
    return False


def perm_add_account_attribute(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add attributes to accounts.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_del_account_attribute(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add attributes to accounts.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return perm_add_account_attribute(issuer, kwargs, session=session)


def perm_list_heartbeats(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list heartbeats.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer)


def perm_resurrect(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can resurrect DIDS.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_update_lifetime_exceptions(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can approve/reject Lifetime Model exceptions.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    if kwargs['vo'] is not None:
        exceptions = next(list_exceptions(exception_id=kwargs['exception_id'], states=False, session=session))
        if exceptions['scope'].vo != kwargs['vo']:
            return False
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_get_auth_token_ssh(issuer: "InternalAccount", kwargs: dict, session: "Session") -> bool:
    """
    Checks if an account can request an ssh token.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return True


def perm_get_signed_url(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can request a signed URL.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is allowed to call the API call, otherwise False
    """
    return _is_root(issuer) or has_account_attribute(account=issuer, key='sign-url', session=session)


def perm_add_bad_pfns(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can declare bad PFNs.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_remove_did_from_followed(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can remove DID from followed table.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or kwargs['account'] == issuer\
        or kwargs['scope'].external == 'mock'


def perm_remove_dids_from_followed(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can bulk remove DIDs from followed table.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    if not kwargs['account'] == issuer:
        return False
    return True


def perm_export(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can export the RSE info.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer)


def perm_list_transfer_limits(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list transfer limits.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_set_transfer_limit(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set transfer limits.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_delete_transfer_limit(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete transfer limits.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_delete_metadata(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete a metadata key of a data identifier. With RBAC, it alters the DID: owning its scope
    or itself (see :func:`_owns_did`), or DELETE on it.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    if not _use_roles():
        return False
    scope, name = kwargs['scope'], kwargs['name']
    return rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)\
        or _owns_did(issuer, scope, name, session)\
        or _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session)


def perm_list_account_roles(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the roles assigned to an account. An account can list its own roles.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session) or kwargs['account'] == issuer


def perm_list_role_permissions(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the permissions of a role. An account can list the permissions of the roles it holds.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)\
        or role_core.has_account_valid_role(account=issuer, role=kwargs['role'], session=session)


def perm_read_data(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can read the data of a scope: the replicas of its DIDs, with their PFNs, which allow
    to download them. Every account can read every scope, unless RBAC is enabled: it then requires to read the DID
    the action names ('name'): owning its scope or itself (see :func:`_owns_did`), or READ on it. An action naming no
    DID (a listing of the scope) only requires to own the scope or READ on some DIDs of the scope, see
    :func:`rucio.core.role.has_any_scope_prefix_access`: the gateway then filters what it returns per DID, see
    :func:`rucio.core.role.filter_iterable_by_did_access`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if not _use_roles() or _is_root(issuer) or _is_admin(issuer, session):
        return True
    scope, name = kwargs['scope'], kwargs.get('name')
    if rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session):
        return True
    if name:
        return _owns_did(issuer, scope, name, session)\
            or _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)
    return role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session)
