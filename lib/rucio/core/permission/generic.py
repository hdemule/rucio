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
from rucio.common.constants import RseAttr
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


# Metadata keys whose update leads to the removal of the DID or of its replicas (e.g. `rucio did remove` sets the
# lifetime). Setting metadata on an existing DID already requires to alter it (owning it or DELETE on it), so these
# only matter when the DID is created: WRITE on the new DID is then not enough to set them, see `_rbac_can_create_did`.
RBAC_DELETE_METADATA_KEYS = {'lifetime', 'expired_at', 'eol_at', 'purge_replicas'}

# Metadata keys held by Rucio itself: the identity, size, checksums and state of a DID, and its bookkeeping. Setting
# them would rename a DID, falsify its size (and the account usage computed from it) or its checksums, or change
# how Rucio handles it, so no role grants it: only root, admins and the owner of the scope may.
RBAC_PROTECTED_METADATA_KEYS = {
    'name', 'scope', 'account', 'did_type', 'bytes', 'length', 'events', 'adler32', 'md5', 'guid',
    'availability', 'complete', 'is_open', 'monotonic', 'obsolete', 'suppressed', 'hidden', 'transient',
    'is_archive', 'constituent', 'is_new', 'closed_at', 'deleted_at', 'accessed_at', 'access_cnt',
    'created_at', 'updated_at',
}

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
            'add_qos_policy': perm_add_qos_policy,
            'delete_qos_policy': perm_delete_qos_policy,
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
            'delete_metadata': perm_delete_metadata,
            'list_account_roles': perm_list_account_roles,
            'list_role_permissions': perm_list_role_permissions,
            'list_dids': perm_read_scope,
            'list_parent_dids': perm_read_scope,
            'get_did': perm_read_scope,
            'get_metadata': perm_read_scope,
            'get_metadata_bulk': perm_read_scope,
            'list_content': perm_read_scope,
            'list_content_history': perm_read_scope,
            'list_files': perm_read_scope,
            'scope_list': perm_read_scope,
            'list_archive_content': perm_read_scope,
            'get_users_following_did': perm_read_scope,
            'add_did_to_followed': perm_read_scope,
            'list_replication_rule_history': perm_read_scope,
            'list_replication_rule_full_history': perm_read_scope,
            'get_replication_rule': perm_read_scope,
            'examine_replication_rule': perm_read_scope,
            'get_dataset_locks': perm_read_scope,
            'get_dataset_locks_bulk': perm_read_scope,
            'list_associated_replication_rules_for_file': perm_read_scope,
            'list_replicas': perm_read_scope,
            'list_dataset_replicas': perm_read_scope,
            'list_dataset_replicas_bulk': perm_read_scope,
            'list_dataset_replicas_vp': perm_read_scope,
            'get_replica_locks_for_rule_id': perm_read_scope}

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


def _rbac_permission_access(issuer: "InternalAccount", scope: "InternalScope", name: Optional[str], operation: DidOperationType, session: "Session") -> bool:
    """
    Checks if a role grants an account an operation on a DID, or on a whole scope without `name`, see :func:`rucio.core.role.has_permission`.
    Like every `_rbac_*` helper, it does not check whether RBAC is enabled: the caller does, see :func:`_use_roles`.

    Giving the name only extends what is granted: a DID pattern covering the whole scope ('data:*') grants
    the DIDs of the scope as well as the scope, while a name pattern ('data:raw*') only grants the DIDs it matches.
    The owner of the scope is granted everything in it.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope to check, or the scope of the DID.
    :param name: The name of the DID, None to check the whole scope.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param session: The DB session to use
    :returns: True if RBAC grants the operation, otherwise False
    """
    request = role_core.DidPermissionRequest(operation=operation, scope=scope, name=name)
    return role_core.has_permission(account=issuer, request=request, session=session)


def _rbac_did_ownership_access(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Determines RBAC ownership of an existing DID. A DID is owned by its account only if a role grants that account READ on at least one DID of its scope, see :func:`rucio.core.role.has_any_scope_prefix_access`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use.
    :returns: True if the account owns the DID, otherwise False (also if it does not exist)
    """
    # Owning a DID in a scope requires to have at least one READ entry on that scope.
    # The READ then transforms to READ,WRITE,DELETE for the owner.
    if not role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session):
        return False
    try:
        return get_did(scope=scope, name=name, session=session)['account'] == issuer
    except DataIdentifierNotFound:
        return False


def _rbac_new_did_ownership_access(issuer: "InternalAccount", new_did: "Mapping[str, Any]", session: "Session") -> bool:
    """
    Determines RBAC ownership of a DID being created, which does not exist yet: it will be owned by its 'account', the issuer by default.
    As for an existing DID, it is owned only if a role grants that account READ on at least one DID of its scope, see :func:`_rbac_did_ownership_access`.

    :param issuer: Account identifier which issues the command.
    :param new_did: The DID being created, with its 'scope' and optionally its 'account' (internal or external).
    :param session: The DB session to use.
    :returns: True if the account will own the DID, otherwise False
    """
    owner = new_did.get('account') or issuer
    if not isinstance(owner, InternalAccount):
        owner = InternalAccount(owner, vo=issuer.vo)
    return owner == issuer\
        and role_core.has_any_scope_prefix_access(account=issuer, scope=new_did['scope'], operation=DidOperationType.READ, session=session)


def _rbac_rule_ownership_access(issuer: "InternalAccount", rule: "Mapping[str, Any]", session: "Session") -> bool:
    """
    Determines RBAC ownership of an existing replication rule. A rule is owned by its account only if a role grants that account READ on at least one DID of the scope of its DID, see :func:`rucio.core.role.has_any_scope_prefix_access`.

    :param issuer: Account identifier which issues the command.
    :param rule: The rule, with its 'account' and 'scope'.
    :param session: The DB session to use.
    :returns: True if the account owns the rule, otherwise False (also if it does not exist)
    """
    return rule['account'] == issuer and role_core.has_any_scope_prefix_access(account=issuer, scope=rule['scope'], operation=DidOperationType.READ, session=session)


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


def _rbac_can_read_did(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to read a DID: READ on it, or owning it.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    return _rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)\
        or _rbac_did_ownership_access(issuer, scope, name, session)


def _rbac_can_read_dids(issuer: "InternalAccount", dids: "Iterable[Mapping[str, Any]]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to read all the given DIDs, see :func:`_rbac_can_read_did`.

    :param issuer: Account identifier which issues the command.
    :param dids: The DIDs, each with its 'scope' and 'name'.
    :param session: The DB session to use
    :returns: True if every DID is readable (or if there is none), otherwise False
    """
    return all(_rbac_can_read_did(issuer, scope, name, session) for scope, name in _internal_dids(issuer, dids))


def _rbac_can_alter_did(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to write on, overwrite or delete an existing DID: owning it, or DELETE on it.
    WRITE alone only creates DIDs, and adds content into collections, see :func:`_rbac_can_create_did` and
    :func:`_rbac_can_attach_into`: the existing DIDs of other accounts are altered with DELETE only.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    return _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session)\
        or _rbac_did_ownership_access(issuer, scope, name, session)


def _rbac_can_alter_rule(issuer: "InternalAccount", rule_id: str, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to update, reduce, move or delete a replication rule: owning it (see
    :func:`_rbac_rule_ownership_access`), or DELETE on its DID.

    :param issuer: Account identifier which issues the command.
    :param rule_id: The id of the rule.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False (also if the rule does not exist)
    """
    try:
        rule = get_rule(rule_id=rule_id, session=session)
    except RuleNotFound:
        return False
    # owning a rule counts as owning a DID: it requires READ on at least one DID of the scope of the ruled DID
    return _rbac_rule_ownership_access(issuer, rule, session)\
        or _rbac_permission_access(issuer, rule['scope'], rule['name'], DidOperationType.DELETE, session)


def _rbac_can_alter_metadata(issuer: "InternalAccount", scope: "InternalScope", name: str, keys: "Iterable[str]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to set metadata keys on an existing DID: it alters the DID, see
    :func:`_rbac_can_alter_did`, and the keys held by Rucio itself (see RBAC_PROTECTED_METADATA_KEYS) are never granted.
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
    return _rbac_can_alter_did(issuer, scope, name, session)


def _rbac_can_attach_dids(issuer: "InternalAccount", dids: "Iterable[Mapping[str, Any]]", registered: bool, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to attach DIDs to a collection, whoever may write on the collection itself:
    READ on each of them (see :func:`_rbac_can_read_did`). When they are registered on an RSE along with the attachment
    (`registered`), a file which does not exist yet is created, which requires WRITE on it instead.

    :param issuer: Account identifier which issues the command.
    :param dids: The attached DIDs, each with its 'scope' and 'name'.
    :param registered: Whether the attached files are registered on an RSE.
    :param session: The DB session to use
    :returns: True if RBAC grants every DID, otherwise False
    """
    for scope, name in _internal_dids(issuer, dids):
        if registered and not _did_exists(scope, name, session):
            if not _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session):
                return False
        elif not _rbac_can_read_did(issuer, scope, name, session):
            return False
    return True


def _rbac_can_attach_into(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to add content into a collection: WRITE on it, or owning it. The attached DIDs
    are checked by :func:`_rbac_can_attach_dids`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the collection.
    :param name: The name of the collection.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    return _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session)\
        or _rbac_did_ownership_access(issuer, scope, name, session)


def _rbac_can_detach_from(issuer: "InternalAccount", scope: "InternalScope", name: str, dids: "Iterable[Mapping[str, Any]]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to remove content from a collection: altering the collection (see
    :func:`_rbac_can_alter_did`) removes any content, WRITE on it only the DIDs the account owns (see :func:`_rbac_did_ownership_access`).

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the collection.
    :param name: The name of the collection.
    :param dids: The detached DIDs, each with its 'scope' and 'name'.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    if _rbac_can_alter_did(issuer, scope, name, session):
        return True
    return _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session)\
        and all(_rbac_did_ownership_access(issuer, did_scope, did_name, session) for did_scope, did_name in _internal_dids(issuer, dids))


def _rbac_can_create_did(issuer: "InternalAccount", did: "Mapping[str, Any]", session: "Session") -> bool:
    """
    Checks if a role grants an account to create a DID: WRITE on the new DID, which it must own (no 'account' but
    itself), creating DIDs for other accounts being left to root, admins and the owner of the scope. Its metadata ('meta') is checked as if
    set on it right after the creation by its owner: the keys held by Rucio are refused, and those leading to its
    removal require owning it (see :func:`_rbac_new_did_ownership_access`) or DELETE on it. What is attached or ruled along
    with it is checked for every account by :func:`_rbac_can_create_did_with`.

    :param issuer: Account identifier which issues the command.
    :param did: The DID to create, with its 'scope', 'name' and optionally its 'account' and 'meta'.
    :param session: The DB session to use
    :returns: True if RBAC grants the creation, otherwise False
    """
    scope, name = did['scope'], did['name']
    # creating a DID owned by another account is left to root, admins and the owner of the scope, as in standard Rucio
    owner = did.get('account') or issuer
    if (owner if isinstance(owner, InternalAccount) else InternalAccount(owner, vo=issuer.vo)) != issuer:
        return False
    if not _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session):
        return False
    keys = set(did.get('meta') or {})
    if keys & RBAC_PROTECTED_METADATA_KEYS:
        return False
    return not keys & RBAC_DELETE_METADATA_KEYS\
        or _rbac_permission_access(issuer, scope, name, DidOperationType.DELETE, session)\
        or _rbac_new_did_ownership_access(issuer, did, session)


def _rbac_can_create_did_with(issuer: "InternalAccount", did: "Mapping[str, Any]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account what it attaches to and rules on a DID it creates, whatever lets it create the
    DID: its content ('dids'), see :func:`_rbac_can_attach_dids`, and its rules ('rules'), which require to read the
    new DID like any rule (READ on it, or owning it once created), see :func:`perm_add_rule`.

    :param issuer: Account identifier which issues the command.
    :param did: The DID to create, with its 'scope', 'name' and optionally its 'dids', 'rse_id', 'rules' and 'account'.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    scope, name = did['scope'], did['name']
    if did.get('rules') and not (_rbac_permission_access(issuer, scope, name, DidOperationType.READ, session)
                                 or _rbac_new_did_ownership_access(issuer, did, session)):
        return False
    return _rbac_can_attach_dids(issuer, did.get('dids') or [], bool(did.get('rse_id')), session)


def _rbac_held_by_other_accounts(issuer: "InternalAccount", rse_id: str, scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Checks if a replica is locked by a rule of another account. Deleting or invalidating such a replica would break
    the rules, and the data, of other accounts, so no role grants it: only root and admins may.

    :param issuer: Account identifier which issues the command.
    :param rse_id: The id of the RSE of the replica.
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param session: The DB session to use
    :returns: True if a rule of another account locks the replica, otherwise False
    """
    return any(lock.account != issuer for lock in get_replica_locks(scope=scope, name=name, restrict_rses=[rse_id], session=session))


def _rbac_can_register_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if RBAC grants an account to register replicas of files, given in 'dids': a replica of an existing file
    only copies data, which requires to read the file, see :func:`_rbac_can_read_did`. A file which does not exist yet is
    created along with its replica, which the gateway checks as the creation of a DID ('add_dids'). Without the DIDs,
    READ is required on the 'scopes' of the files.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action, holding the 'scopes' of the files and, optionally, their 'dids'.
    :param session: The DB session to use
    :returns: True if RBAC grants every registration, otherwise False
    """
    if not kwargs.get('dids'):
        scopes = {scope if isinstance(scope, InternalScope) else InternalScope(scope, vo=issuer.vo) for scope in kwargs.get('scopes') or []}
        return all(_rbac_permission_access(issuer, scope, None, DidOperationType.READ, session) for scope in scopes)
    return all(not _did_exists(scope, name, session) or _rbac_can_read_did(issuer, scope, name, session)
               for scope, name in _internal_dids(issuer, kwargs['dids']))


def _rbac_can_delete_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if RBAC grants an account to delete replicas, on the RSEs listed in RBAC_REPLICA_RSE_SUFFIXES only: it alters
    each file, given in 'dids' (see :func:`_rbac_can_alter_did`), and no replica may be locked by a rule of another account
    (see :func:`_rbac_held_by_other_accounts`), since deleting replicas ignores the locks on them. Without the DIDs,
    DELETE is required on the 'scopes' of the files, and the locks are left to root and admins.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action, holding the 'rse', its 'rse_id', the 'scopes' of the files and, optionally, their 'dids'.
    :param session: The DB session to use
    :returns: True if RBAC grants every deletion, otherwise False
    """
    if not str(kwargs['rse']).endswith(RBAC_REPLICA_RSE_SUFFIXES) or not kwargs['scopes'] or not kwargs.get('dids'):
        return False
    return all(_rbac_can_alter_did(issuer, scope, name, session)
               and not _rbac_held_by_other_accounts(issuer, kwargs['rse_id'], scope, name, session)
               for scope, name in _internal_dids(issuer, kwargs['dids']))


def _rbac_can_update_replica_states(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if RBAC grants an account to update the states of replicas, on the RSEs listed in RBAC_REPLICA_RSE_SUFFIXES
    only, each file given in 'dids' with its requested 'state' and optionally a new 'path', see :func:`_rbac_can_update_replica_state`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action, holding the 'rse', its 'rse_id', the 'scopes' of the files and their 'dids'.
    :param session: The DB session to use
    :returns: True if RBAC grants every update, otherwise False
    """
    if not str(kwargs['rse']).endswith(RBAC_REPLICA_RSE_SUFFIXES) or not kwargs['scopes'] or not kwargs.get('dids'):
        return False
    return all(_rbac_can_update_replica_state(issuer, kwargs['rse_id'], file, session) for file in kwargs['dids'])


def _rbac_can_update_replica_state(issuer: "InternalAccount", rse_id: str, file: "Mapping[str, Any]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to update the state of one replica.

    A replica locked by a rule of another account is left to root and admins, see :func:`_rbac_held_by_other_accounts`:
    its state completes or fails their locks. Otherwise, updating it alters the file, see :func:`_rbac_can_alter_did`.
    Finishing an upload is the only exception, since it completes a registration the account was allowed to make:
    marking available ('A') a replica being copied ('C'), without a new path, requires what registering it does, see
    :func:`_rbac_can_register_replicas`: WRITE on a file the account owns (it uploads a new file, even without
    reading the scope), or READ on the file (it uploads a copy of an existing file).

    :param issuer: Account identifier which issues the command.
    :param rse_id: The id of the RSE of the replica.
    :param file: The file, with its 'scope', 'name', requested 'state' and optionally its new 'path'.
    :param session: The DB session to use
    :returns: True if RBAC grants the update, otherwise False
    """
    (scope, name), = _internal_dids(issuer, [file])
    if _rbac_held_by_other_accounts(issuer, rse_id, scope, name, session):
        return False
    if _rbac_can_alter_did(issuer, scope, name, session):
        return True
    try:
        finishes_upload = ReplicaState(file.get('state')) == ReplicaState.AVAILABLE and not file.get('path')
    except ValueError:
        finishes_upload = False
    if not finishes_upload or not _is_replica_being_copied(rse_id, scope, name, session):
        return False
    return (get_did(scope=scope, name=name, session=session)['account'] == issuer and _rbac_permission_access(issuer, scope, name, DidOperationType.WRITE, session))\
        or _rbac_can_read_did(issuer, scope, name, session)


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
        # With RBAC, a rule copies data, so it requires to read every DID it is on, see :func:`_rbac_can_read_did`.
        return not _use_roles() or _is_root(issuer) or _is_admin(issuer, session)\
            or _rbac_can_read_dids(issuer, kwargs['dids'], session)
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
    allowed = rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and _rbac_can_create_did(issuer, kwargs, session))
    # With RBAC, what is attached to and ruled on the new DID is checked whatever lets the account create it.
    return allowed and (not _use_roles() or _rbac_can_create_did_with(issuer, kwargs, session))


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
        or (_use_roles() and _rbac_can_attach_into(issuer, kwargs['scope'], kwargs['name'], session))
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
            or (_use_roles() and _rbac_can_attach_into(issuer, attachment['scope'], attachment['name'], session))
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
    # Unlike attaching, detaching removes content: WRITE on the collection only removes owned DIDs, see :func:`_rbac_can_detach_from`.
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and _rbac_can_detach_from(issuer, kwargs['scope'], kwargs['name'], kwargs['dids'], session))


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


def perm_add_qos_policy(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can add QoS policies to an RSE.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


def perm_delete_qos_policy(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete QoS policies from an RSE.

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
    # With RBAC, a replica of an existing file copies its data, so it requires to read the file.
    return user_rse and (not _use_roles() or _rbac_can_register_replicas(issuer, kwargs, session))


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
    return _use_roles() and _rbac_can_delete_replicas(issuer, kwargs, session)


def perm_update_replicas_states(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can update the states of replicas, see :func:`_rbac_can_update_replica_states` for RBAC.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)\
        or (_use_roles() and _rbac_can_update_replica_states(issuer, kwargs, session))


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

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return True


def perm_get_request_history_by_did(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get a historical request by DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


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
    Checks if an account can delete a metadata key of a data identifier. RBAC requires to alter the DID, see :func:`_rbac_can_alter_did`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)\
        or (_use_roles() and _rbac_can_alter_did(issuer, kwargs['scope'], kwargs['name'], session))


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


def perm_read_scope(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can read the content of a scope (its DIDs, their metadata, rules, locks and replicas).
    Every account can read every scope, unless RBAC is enabled: it then requires to read the DID the action names
    ('name'), see :func:`_rbac_can_read_did`. An action naming no DID (a listing of the scope) only requires READ on
    some DIDs of the scope, see :func:`rucio.core.role.has_any_scope_prefix_access`: the gateway then filters what it returns per DID,
    see :func:`rucio.core.role.filter_iterable_by_did_access`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if not _use_roles() or _is_root(issuer) or _is_admin(issuer, session):
        return True
    if kwargs.get('name'):
        return _rbac_can_read_did(issuer, kwargs['scope'], kwargs['name'], session)
    return role_core.has_any_scope_prefix_access(account=issuer, scope=kwargs['scope'], operation=DidOperationType.READ, session=session)
