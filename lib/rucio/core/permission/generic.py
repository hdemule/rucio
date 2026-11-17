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
from rucio.common.constants import RBAC_DELETE_METADATA_KEYS, RESERVED_KEYS, RseAttr
from rucio.common.exception import DataIdentifierNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import role as role_core
from rucio.core.account import has_account_attribute, list_account_attributes
from rucio.core.did import get_did
from rucio.core.identity import exist_identity_account
from rucio.core.lifetime_exception import list_exceptions
from rucio.core.replica import get_did_from_pfns, get_pfn_to_rse
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla.constants import DidOperationType, IdentityType

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from sqlalchemy.orm import Session


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
            'list_replicas': perm_list_replicas,
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
    Checks if an account is an admin: it has the 'admin' account attribute, as in standard Rucio, or, if RBAC is
    enabled, it holds the admin role. The attribute keeps counting with RBAC, so that enabling RBAC demotes no admin.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is admin, otherwise False
    """
    return has_account_attribute(account=issuer, key='admin', session=session)\
        or (_use_roles() and role_core.has_admin_role(account=issuer, session=session))


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


# ----- Ownership -----


def _owns_did(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session", did_access: "Optional[role_core.DidAccess]" = None) -> bool:
    """
    Determines RBAC ownership of an existing DID. A DID is owned by its account only while a role grants that account
    WRITE on the DID itself, see :func:`rucio.core.role.has_did_permission`. The owner of a DID may then do anything on it, as if
    a role granted it every operation: WRITE lets an account create DIDs, and alter or remove the ones it owns, so
    withdrawing WRITE on a DID also withdraws what owning it grants.

    The owner of the scope is not checked here: like in standard Rucio, the permission functions check it on their own,
    see :func:`rucio.core.scope.is_scope_owner`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use.
    :param did_access: The DID permissions of the roles of the account, if read already, e.g. to filter a listing.
    :returns: True if the account owns the DID, otherwise False (also if it does not exist)
    """
    writes = did_access.grants(scope, name, DidOperationType.WRITE) if did_access is not None\
        else role_core.has_did_permission(issuer, scope, name, DidOperationType.WRITE, session=session)
    if not writes:
        return False
    try:
        return get_did(scope=scope, name=name, session=session)['account'] == issuer
    except DataIdentifierNotFound:
        return False


def _new_did_owner(issuer: "InternalAccount", kwargs: dict[str, Any]) -> "InternalAccount":
    """
    The account a DID created with the permission arguments of `add_did` or of a DID of `add_dids` will belong to: its
    'account', the issuer if none is given.

    The gateway turns the 'account' of `add_did` into an InternalAccount even when none is given (see
    :func:`rucio.gateway.permission.has_permission`): an account without external name then stands for no account. The
    'account' of a DID of `add_dids` is left as given, an external name or nothing.

    :param issuer: Account identifier which issues the command.
    :param kwargs: The permission arguments of the new DID.
    :returns: The future owner of the DID.
    """
    owner = kwargs.get('account')
    if isinstance(owner, InternalAccount):
        return issuer if owner.external is None else owner
    return InternalAccount(owner, vo=issuer.vo) if owner else issuer


# ----- RBAC helpers -----

# The roles alone are checked with `rucio.core.role.has_did_permission`: the callers check whether RBAC is enabled
# (see `_use_roles`), and owning the scope or the DID, on their own.


def _rbac_can_alter_metadata(issuer: "InternalAccount", scope: "InternalScope", name: str, keys: "Iterable[str]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to set metadata keys on an existing DID, the owner of its scope being checked
    before by the permission functions. Owning the DID (see :func:`_owns_did`) grants every key. Those leading to the
    removal of the DID (see RBAC_DELETE_METADATA_KEYS), and a call setting no other key, require DELETE on it. The other keys are
    decided per key by the metadata permissions, falling back to DELETE on the DID as without metadata permissions,
    see :func:`rucio.core.role.can_write_metadata_keys`.
    A recursive update, which rewrites the metadata of the whole content, is granted by no role: the permission
    functions refuse it before calling this check.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param keys: The metadata keys to set.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    keys = set(keys)
    if _owns_did(issuer, scope, name, session):
        return True
    other_keys = keys - RBAC_DELETE_METADATA_KEYS
    if (not other_keys or keys & RBAC_DELETE_METADATA_KEYS) and not role_core.has_did_permission(issuer, scope, name, DidOperationType.DELETE, session=session):
        return False
    return not other_keys or role_core.can_write_metadata_keys(account=issuer, scope=scope, name=name, keys=other_keys, session=session)


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
            if not role_core.has_did_permission(issuer, scope, name, DidOperationType.WRITE, session=session):
                return False
        elif not (_owns_did(issuer, scope, name, session) or role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session)):
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
                   or role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session)
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
    if _is_root(issuer) or _is_admin(issuer, session):
        return True
    # Check the accounts of the issued rules
    for rule in kwargs.get('rules', []):
        if rule['account'] != issuer:
            return False

    scope = kwargs['scope']
    owns_scope = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
    if not _use_roles():
        return owns_scope or scope.external == 'mock'

    name = kwargs.get('name')
    if not owns_scope:
        # With RBAC, the account will own the new DID, as an existing one (see :func:`_owns_did`), if it is its own and a
        # role grants it WRITE on it. Creating DIDs for other accounts is left to root, admins and the owner of the scope,
        # as in standard Rucio.
        will_own = _new_did_owner(issuer, kwargs) == issuer and role_core.has_did_permission(issuer, scope, name, DidOperationType.WRITE, session=session)
        if scope.external != 'mock':
            # Outside the scope 'mock', which every account may create DIDs in, a role grants to create a DID it will own.
            if not will_own:
                return False
            # Its metadata is set by its future owner, which may set the keys it could set on it once created: not those
            # Rucio reserves, which the gateway refuses on an existing DID but not on creation. A role grants WRITE on DID
            # patterns, which e.g. 'name' would let the new DID leave.
            if set(kwargs.get('meta') or {}) & set(RESERVED_KEYS):
                return False
        # Its rules require to read it, or to own it, like any rule, see :func:`perm_add_rule`.
        if kwargs.get('rules') and not will_own and not role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session):
            return False

    # Its content must be attachable, whatever lets the account create it, see :func:`_rbac_can_attach_dids`.
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
        or (_use_roles() and role_core.has_did_permission(issuer, kwargs['scope'], kwargs['name'], DidOperationType.WRITE, session=session))
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
            or (_use_roles() and role_core.has_did_permission(issuer, attachment['scope'], attachment['name'], DidOperationType.WRITE, session=session))
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
        or (_use_roles() and role_core.has_did_permission(issuer, kwargs['scope'], kwargs.get('name'), DidOperationType.WRITE, session=session))


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
    return False


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
    return False


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
    return False


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
    return False


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
                              or role_core.has_did_permission(issuer, kwargs['scope'], kwargs['name'], DidOperationType.DELETE, session=session)
                              or (role_core.has_did_permission(issuer, kwargs['scope'], kwargs['name'], DidOperationType.WRITE, session=session)
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

    Every account can, unless RBAC is enabled: the declaration acts on the replicas, and its result tells whether each
    of them exists, so it then requires to read the data of the DID of each replica ('pfns'): owning its scope or itself
    (see :func:`_owns_did`), or READ on it. A PFN which does not resolve to a DID is refused the same way, so that a
    hidden DID cannot be told from a missing one. A PFN which matches no RSE tells nothing about a DID, and is left to
    the declaration to report.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if not _use_roles() or _is_root(issuer) or _is_admin(issuer, session):
        return True
    did_access = role_core.DidAccess(issuer, session=session)
    owned_scopes: dict[InternalScope, bool] = {}
    for did in _suspicious_replica_dids(issuer, kwargs.get('pfns') or [], session):
        if did is None:
            return False
        scope, name = did
        if scope not in owned_scopes:
            owned_scopes[scope] = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
        if not (owned_scopes[scope] or did_access.grants(scope, name, DidOperationType.READ)
                or _owns_did(issuer, scope, name, session, did_access=did_access)):
            return False
    return True


def _suspicious_replica_dids(issuer: "InternalAccount", pfns: "list[Any]", session: "Session") -> "list[Optional[tuple[InternalScope, str]]]":
    """
    The DIDs of the replicas declared suspicious, see :func:`perm_declare_suspicious_file_replicas`.

    :param issuer: Account identifier which issues the command.
    :param pfns: The PFNs, or the replicas as dictionaries with a 'scope', a 'name' and an 'rse_id'.
    :param session: The DB session to use
    :returns: The DID of each replica, None for a PFN which matches an RSE but resolves to no DID. A PFN which matches
              no RSE is left out.
    """
    if not pfns:
        return []
    if not isinstance(pfns[0], str):
        return [(r['scope'] if isinstance(r['scope'], InternalScope) else InternalScope(r['scope'], vo=issuer.vo), r['name']) for r in pfns]

    _, pfns_by_rse, _ = get_pfn_to_rse(pfns, vo=issuer.vo, session=session)
    located = [pfn for rse_pfns in pfns_by_rse.values() for pfn in rse_pfns]
    resolved: dict[str, dict[str, Any]] = {}
    if located:
        for item in get_did_from_pfns(pfns=located, vo=issuer.vo, session=session):
            resolved.update(item)
    return [(resolved[pfn]['scope'], resolved[pfn]['name']) if pfn in resolved else None for pfn in located]


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
                   or role_core.has_did_permission(issuer, scope, None, DidOperationType.READ, session=session)
                   for scope in scopes)
    return all(not _did_exists(scope, name, session)
               or rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
               or _owns_did(issuer, scope, name, session)
               or role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session)
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
    return False


def perm_update_replicas_states(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)


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
    replicas do, see :func:`perm_list_replicas`. A metadata permission making the DID visible does not grant it.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return perm_list_replicas(issuer, kwargs, session)


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
    Checks if an account can delete a metadata key of a data identifier.

    Every account can, unless RBAC is enabled.

    Only the custom metadata plugins (e.g. JSON) delete keys: the core refuses to delete a key of the DID columns,
    which hold every deletion key and most reserved ones. A reserved key it deletes, e.g. 'is_open', is therefore a
    custom key of that name, not the state of the DID.

    With RBAC, owning the scope or the DID (see :func:`_owns_did`) grants every key. Otherwise, the metadata
    permissions decide the key, falling back to DELETE on the DID as without metadata permissions, see
    :func:`rucio.core.role.can_write_metadata_keys`. No metadata permission decides the keys of
    `rucio.core.role.METADATA_KEYS_NOT_WRITABLE`, so DELETE on the DID decides them directly.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if not _use_roles() or _is_root(issuer) or _is_admin(issuer, session):
        return True
    scope, name, key = kwargs['scope'], kwargs['name'], kwargs['key']
    if rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session) or _owns_did(issuer, scope, name, session):
        return True
    if key in role_core.METADATA_KEYS_NOT_WRITABLE:
        # `can_write_metadata_keys` refuses them outright, without falling back to the DID permissions
        return role_core.has_did_permission(issuer, scope, name, DidOperationType.DELETE, session=session)
    return role_core.can_write_metadata_keys(account=issuer, scope=scope, name=name, keys=[key], session=session)


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
    Checks if an account can read the content of a scope (its DIDs, their metadata, rules, locks and dataset replicas).
    Every account can read every scope, unless RBAC is enabled: it then requires to read the DID the action names
    ('name'): owning its scope or itself (see :func:`_owns_did`), READ on it, or a metadata permission making it
    visible, see :func:`rucio.core.role.has_metadata_visibility`. An action naming no DID (a listing of the scope) only requires to
    own the scope, or READ or metadata visibility on some DIDs of the scope, see
    :func:`rucio.core.role.has_any_scope_prefix_access`: the gateway then filters what it returns per DID, see
    :func:`did_filter`, and hides the metadata keys the account may not read, see :func:`metadata_key_filter`.

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
            or role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session)\
            or role_core.has_metadata_visibility(account=issuer, scope=scope, name=name, session=session)
    return role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session)\
        or role_core.has_any_scope_prefix_metadata_visibility(account=issuer, scope=scope, session=session)


def perm_list_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the replicas of a DID, with their PFNs, which allow to download it. Every account
    can, unless RBAC is enabled: it then requires to read the DID, owning its scope or itself (see :func:`_owns_did`), or
    READ on it. Unlike :func:`perm_read_data`, a metadata permission making the DID visible does not grant it.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return not _use_roles() or _is_root(issuer) or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or _owns_did(issuer, kwargs['scope'], kwargs['name'], session)\
        or role_core.has_did_permission(issuer, kwargs['scope'], kwargs['name'], DidOperationType.READ, session=session)


# ----- Listing filters -----
#
# The gateway filters a listing item by item, with a callable built once for the listing, see
# `rucio.core.permission.did_filter`: deciding every item through `has_permission` would query the database for each
# of them. A callable decides an item as the permission functions decide it for a single DID or scope (root, admins,
# the owner of the scope, the owner of the DID, the roles, see :func:`perm_read_data`), from the roles of the account
# read once, see :class:`rucio.core.role.DidAccess` and :class:`rucio.core.role.MetadataAccess`.


def is_listing_filtered(issuer: "InternalAccount", action: str, session: "Session") -> bool:
    """
    Checks if a listing is filtered for an account: only with RBAC, unless the policy package disables the filter of
    the listing for the account, see :func:`rucio.core.role.is_filter_disabled`.

    :param issuer: Account identifier which issues the command.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The DB session to use
    :returns: True if the listing is filtered, otherwise False
    """
    return _use_roles() and not role_core.is_filter_disabled(issuer, action, session=session)


def scope_filter(issuer: "InternalAccount", action: str, session: "Session", operation: DidOperationType = DidOperationType.READ,
                 any_did: bool = False) -> "Callable[[Optional[InternalScope]], bool]":
    """
    Builds a callable telling whether an account may perform an operation on a scope, to filter a listing.

    Root, admins and the owner of the scope may. Otherwise a role must grant the operation on the whole scope, by a
    pattern with the '*' name part which no name pattern of the role withdraws from some of its DIDs, see
    :meth:`rucio.core.role.DidAccess.role_grants`: this is meant for the items standing for the whole content of a
    scope, e.g. counts. With `any_did`, meant for listing the scopes themselves, a grant on some DIDs of the scope is
    enough, and for READ a metadata permission making some of its DIDs visible, as :func:`perm_read_data` decides it
    for a scope.

    :param issuer: Account identifier which issues the command.
    :param action: The filter of the listing, see :func:`is_listing_filtered`.
    :param session: The DB session to use
    :param operation: The operation to check.
    :param any_did: Grant a scope if the operation is granted on some of its DIDs.
    :returns: A callable taking a scope and returning True if the account may access it: every scope if the listing is
              not filtered, otherwise never a scope that is None or not an InternalScope.
    """
    if not is_listing_filtered(issuer, action, session):
        return lambda scope: True

    privileged = _is_root(issuer) or _is_admin(issuer, session)
    did_access = role_core.DidAccess(issuer, session=session)
    metadata = role_core.MetadataAccess(issuer, session=session, did_access=did_access) if any_did and operation == DidOperationType.READ else None
    owned_scopes: dict[InternalScope, bool] = {}

    def _can_access(scope: "Optional[InternalScope]") -> bool:
        if not isinstance(scope, InternalScope):
            return False
        if privileged or did_access.grants(scope, None, operation):
            return True
        if scope not in owned_scopes:
            owned_scopes[scope] = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
        if owned_scopes[scope]:
            return True
        return any_did and (did_access.grants_some_did(scope, operation) or (metadata is not None and metadata.is_visible_in_scope(scope)))

    return _can_access


def did_filter(issuer: "InternalAccount", action: str, session: "Session", operation: DidOperationType = DidOperationType.READ,
               reads_data: bool = False) -> "Callable[[Optional[InternalScope], Optional[str]], bool]":
    """
    Builds a callable telling whether an account may perform an operation on a DID, to filter a listing.

    Root, admins and the owner of the scope may, and so may an account a role grants the operation on the whole scope
    (see :func:`scope_filter`), on the DID itself (see :func:`rucio.core.role.has_did_permission`), or which owns the DID (see
    :func:`_owns_did`). For READ, a DID a metadata permission makes visible is granted too, as by :func:`perm_read_data`,
    unless `reads_data` tells that its data are read, e.g. the PFNs of its replicas, as by :func:`perm_list_replicas`.
    The DIDs are decided one by one, so that a long listing is not kept in memory.

    :param issuer: Account identifier which issues the command.
    :param action: The filter of the listing, see :func:`is_listing_filtered`.
    :param session: The DB session to use
    :param operation: The operation to check.
    :param reads_data: Whether the data of the DIDs are read, which a metadata permission making them visible does not grant.
    :returns: A callable taking a scope and a name, returning True if the account may access the DID: every DID if the
              listing is not filtered, otherwise never one whose scope is None or not an InternalScope, nor whose name
              is None unless the whole scope is granted.
    """
    if not is_listing_filtered(issuer, action, session):
        return lambda scope, name: True

    privileged = _is_root(issuer) or _is_admin(issuer, session)
    did_access = role_core.DidAccess(issuer, session=session)
    metadata = role_core.MetadataAccess(issuer, session=session, did_access=did_access) if operation == DidOperationType.READ and not reads_data else None
    owned_scopes: dict[InternalScope, bool] = {}

    def _can_access(scope: "Optional[InternalScope]", name: Optional[str]) -> bool:
        if not isinstance(scope, InternalScope):
            return False
        if privileged or did_access.grants(scope, None, operation):
            return True
        if scope not in owned_scopes:
            owned_scopes[scope] = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
        if owned_scopes[scope]:
            return True
        if name is None:
            return False
        return did_access.grants(scope, name, operation)\
            or (metadata is not None and metadata.is_visible(scope, name))\
            or _owns_did(issuer, scope, name, session, did_access=did_access)

    return _can_access


# The keys some DID listings use for a metadata key, e.g. `rucio.core.did.get_did` gives 'is_open' as 'open'.
_METADATA_KEY_ALIASES = {'open': 'is_open'}


class MetadataKeyFilter:
    """
    Tells which metadata keys of the DIDs it is given an account may read, and hides the others, see :func:`metadata_key_filter`.

    Root, admins, the owner of the scope and the owner of a DID (see :func:`_owns_did`) read every key. So does an
    account whose roles have no metadata permission matching the DID: its keys are read like the DID itself, which the
    caller checked already. Otherwise each key is decided by :meth:`rucio.core.role.MetadataAccess.can_read_key`. The
    keys naming the DID (`rucio.core.role.METADATA_IDENTITY_KEYS`) are always kept, since the DID itself is visible.
    """

    def __init__(self, issuer: "InternalAccount", session: "Session", filtered: bool) -> None:
        self._issuer = issuer
        self._session = session
        self._did_access = None if not filtered or _is_root(issuer) or _is_admin(issuer, session) else role_core.DidAccess(issuer, session=session)
        access = None if self._did_access is None else role_core.MetadataAccess(issuer, session=session, did_access=self._did_access)
        # without metadata permissions, every key is read like the DID itself
        self._access = access if access is not None and access.has_metadata_permissions else None
        self._owned_scopes: dict[InternalScope, bool] = {}
        self._reads_every_key: dict[tuple[InternalScope, str], bool] = {}

    def _every_key(self, scope: "InternalScope", name: str) -> bool:
        """Tells whether the account reads every key of a DID."""
        if self._access is None:
            return True
        if (scope, name) not in self._reads_every_key:
            if scope not in self._owned_scopes:
                self._owned_scopes[scope] = rucio.core.scope.is_scope_owner(scope=scope, account=self._issuer, session=self._session)
            self._reads_every_key[(scope, name)] = not self._access.decides_keys(scope, name)\
                or self._owned_scopes[scope]\
                or _owns_did(self._issuer, scope, name, self._session, did_access=self._did_access)
        return self._reads_every_key[(scope, name)]

    def is_readable(self, scope: "InternalScope", name: str, key: str) -> bool:
        """Tells whether the account may read a metadata key of a DID it may see."""
        key = _METADATA_KEY_ALIASES.get(key, key)
        if key in role_core.METADATA_IDENTITY_KEYS or self._every_key(scope, name):
            return True
        return self._access.can_read_key(scope, name, key)  # type: ignore[union-attr]  # set, since not every key is read

    def are_readable(self, scope: "InternalScope", name: str, keys: "Iterable[str]") -> bool:
        """Tells whether the account may read every given metadata key of a DID it may see."""
        return all(self.is_readable(scope, name, key) for key in keys)

    def project(self, scope: "InternalScope", name: str, item: "Mapping[str, Any]") -> dict[str, Any]:
        """Returns the keys of a DID the account may read, dropping the others."""
        if self._every_key(scope, name):
            return dict(item)
        return {key: value for key, value in item.items() if self.is_readable(scope, name, key)}

    def project_item(self, item: "Mapping[str, Any]", scope_keyword: str = "scope", name_keyword: str = "name") -> dict[str, Any]:
        """Returns the keys of a DID given as an item of a listing, with its scope and name, the account may read."""
        scope, name = item.get(scope_keyword), item.get(name_keyword)
        if not isinstance(scope, InternalScope) or name is None:
            return dict(item)
        return self.project(scope, name, item)


def metadata_key_filter(issuer: "InternalAccount", session: "Session") -> MetadataKeyFilter:
    """
    Builds the filter hiding from the DIDs an account sees the metadata keys it may not read, see :class:`MetadataKeyFilter`.

    The DIDs themselves are filtered beforehand, see :func:`did_filter`: this only hides keys, and only with RBAC. The
    roles of the account are read once, the owners of the scopes and DIDs once each, so that a listing is filtered
    without querying the database for every key.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    """
    return MetadataKeyFilter(issuer, session, filtered=_use_roles())
