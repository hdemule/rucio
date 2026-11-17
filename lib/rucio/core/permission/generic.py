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
from rucio.common.constants import RESERVED_KEYS, RseAttr
from rucio.common.exception import DataIdentifierNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import role as role_core
from rucio.core.account import has_account_attribute, list_account_attributes
from rucio.core.did import get_did, list_content
from rucio.core.identity import exist_identity_account
from rucio.core.lifetime_exception import list_exceptions
from rucio.core.replica import get_did_from_pfns, get_pfn_to_rse
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla.constants import DidOperationType, DIDType, IdentityType

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
    Checks if an account is an admin: it has the 'admin' account attribute, as in standard Rucio, or, if RBAC is
    enabled, it holds the admin role. The attribute keeps counting with RBAC, so that enabling RBAC demotes no admin.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is admin, otherwise False
    """
    return has_account_attribute(account=issuer, key='admin', session=session)\
        or (_use_roles() and role_core.has_account_admin_role(account=issuer, session=session))


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
    The DIDs given as dictionaries with a 'scope' and a 'name', as (scope, name), with an internal scope.

    The gateway turns the scopes of the top-level DIDs of the permission arguments ('dids', 'attachments') into
    internal scopes, but not those nested in them: the DIDs of an attachment, the content of each DID of `add_dids`
    and the replicas declared suspicious keep their external scope, which is resolved here in the VO of the issuer.

    :param issuer: Account identifier which issues the command.
    :param dids: The DIDs, each with an internal or an external scope.
    :returns: The DIDs, in the order they are given.
    """
    return [(did['scope'] if isinstance(did['scope'], InternalScope) else InternalScope(did['scope'], vo=issuer.vo), did['name'])
            for did in dids]


# ----- Ownership -----


def _is_did_owner(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session") -> bool:
    """
    Tells whether an account owns an existing DID: it is the account of the DID. Owning a DID grants nothing by itself,
    see :func:`_rbac_can_alter_did`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use.
    :returns: True if the account owns the DID, otherwise False (also if it does not exist)
    """
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

# The callers check whether RBAC is enabled, see `_use_roles`.


def _rbac_can_alter_did(issuer: "InternalAccount", scope: "InternalScope", name: str, session: "Session",
                        did_access: "Optional[role_core.DidAccess]" = None) -> bool:
    """
    Checks if RBAC grants an account to alter an existing DID: to overwrite it, remove content from it or delete
    it. It requires DELETE on the DID, or WRITE on it for its owner (see :func:`_is_did_owner`), see
    :func:`rucio.core.role.has_did_permission`. WRITE alone only adds DIDs and content, so that an account may still
    alter and remove the DIDs it created. Withdrawing WRITE on a DID from its owner also withdraws this. WRITE includes
    READ, so ownership adds nothing to reading a DID.

    The owner of the scope is not checked here: like in standard Rucio, the permission functions check it on their own,
    see :func:`rucio.core.scope.is_scope_owner`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The DB session to use.
    :param did_access: The DID permissions of the roles of the account, if read already, e.g. to filter a listing.
    :returns: True if RBAC grants it, otherwise False
    """
    def grants(operation: DidOperationType) -> bool:
        return did_access.grants(scope, name, operation) if did_access is not None\
            else role_core.has_did_permission(issuer, scope, name, operation, session=session)

    return grants(DidOperationType.DELETE) or (grants(DidOperationType.WRITE) and _is_did_owner(issuer, scope, name, session))


def _rbac_can_alter_metadata(issuer: "InternalAccount", scope: "InternalScope", name: str, keys: "Iterable[str]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to set metadata keys on an existing DID, the owner of its scope being checked
    before by the permission functions: it alters the DID, see :func:`_rbac_can_alter_did`.
    A recursive update, which rewrites the metadata of the whole content, is granted by no role: the permission
    functions refuse it before calling this check.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param keys: The metadata keys to set.
    :param session: The DB session to use
    :returns: True if RBAC grants it, otherwise False
    """
    return _rbac_can_alter_did(issuer, scope, name, session)


def _rbac_can_attach_dids(issuer: "InternalAccount", dids: "Iterable[Mapping[str, Any]]", registered: bool, session: "Session") -> bool:
    """
    Checks if RBAC grants an account to attach DIDs to a collection, whoever may write on the collection itself:
    reading each of them, owning its scope or READ on it. When they are registered
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
        elif not role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session):
            return False
    return True


def _rbac_can_replicate_dids(issuer: "InternalAccount", dids: "Iterable[Mapping[str, Any]]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to replicate DIDs with a rule: a rule copies the whole content of a collection,
    recursively, so the account must read every DID it copies: each DID given and, if it exists, all its content,
    containers, datasets and files. A DID is read by owning its scope or with READ on it: owning the DID adds nothing,
    see :func:`_rbac_can_alter_did`.

    The content is the one the DIDs have when this is checked: what is attached later to a collection the rule is on
    is replicated by the rule without being checked.

    :param issuer: Account identifier which issues the command.
    :param dids: The DIDs, each with its 'scope' and 'name'.
    :param session: The DB session to use
    :returns: True if RBAC grants every DID and all their content, otherwise False
    """
    # The DID permissions of the roles are read once, not once per DID of the content.
    did_access = role_core.DidAccess(issuer, session=session)
    owned_scopes: dict["InternalScope", bool] = {}

    def reads(scope: "InternalScope", name: str) -> bool:
        if scope not in owned_scopes:
            owned_scopes[scope] = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
        return owned_scopes[scope] or did_access.grants(scope, name, DidOperationType.READ)

    # The type of the DIDs given is not known: each is listed, a file having no content.
    seen = set(_internal_dids(issuer, dids))
    if not all(reads(scope, name) for scope, name in seen):
        return False
    to_list = list(seen)
    while to_list:
        scope, name = to_list.pop()
        try:
            children = list(list_content(scope=scope, name=name, session=session))
        except DataIdentifierNotFound:
            # A DID which does not exist yet has no content; the rule itself fails on it later.
            continue
        for child in children:
            did = (child['scope'], child['name'])
            if did in seen:
                continue
            seen.add(did)
            if not reads(*did):
                return False
            # Only the collections have content: listing a file would only query the database for nothing.
            if child['type'] in (DIDType.CONTAINER, DIDType.DATASET):
                to_list.append(did)
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
        # With RBAC, a rule copies data, so it requires to read every DID it is on and all their content, see :func:`_rbac_can_replicate_dids`.
        return not _use_roles() or _is_root(issuer) or _is_admin(issuer, session)\
            or _rbac_can_replicate_dids(issuer, kwargs['dids'], session)
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
        if scope.external != 'mock':
            # Outside the scope 'mock', which every account may create DIDs in, WRITE on a DID grants to create it for
            # the account itself, which will then alter it as its owner (see :func:`_rbac_can_alter_did`). Creating
            # DIDs for other accounts is left to root, admins and the owner of the scope, as in standard Rucio.
            if _new_did_owner(issuer, kwargs) != issuer or not role_core.has_did_permission(issuer, scope, name, DidOperationType.WRITE, session=session):
                return False
            # Its metadata is set by its future owner, which may set the keys it could set on it once created: not those
            # Rucio reserves, which the gateway refuses on an existing DID but not on creation. A role grants WRITE on DID
            # patterns, which e.g. 'name' would let the new DID leave.
            if set(kwargs.get('meta') or {}) & set(RESERVED_KEYS):
                return False
        # Its rules require to read it, like any rule, see :func:`perm_add_rule`: WRITE on it includes READ.
        if kwargs.get('rules') and not role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session):
            return False

    # Its content must be attachable, whatever lets the account create it, see :func:`_rbac_can_attach_dids`. Its rules
    # copy that content, recursively, which must then be readable too, see :func:`_rbac_can_replicate_dids`.
    content = kwargs.get('dids') or []
    return _rbac_can_attach_dids(issuer, content, bool(kwargs.get('rse_id')), session)\
        and (not kwargs.get('rules') or _rbac_can_replicate_dids(issuer, content, session))


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
    # With RBAC, unlike attaching, detaching removes content, which alters the collection (see :func:`_rbac_can_alter_did`):
    # this removes any content, WRITE on the collection only the DIDs the account may alter themselves.
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and (_rbac_can_alter_did(issuer, kwargs['scope'], kwargs['name'], session)
                              or (role_core.has_did_permission(issuer, kwargs['scope'], kwargs['name'], DidOperationType.WRITE, session=session)
                                  and all(_rbac_can_alter_did(issuer, scope, name, session) for scope, name in _internal_dids(issuer, kwargs['dids'])))))


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
    of them exists, so it then requires to read the data of the DID of each replica ('pfns'): owning its scope, or READ
    on it. A PFN which does not resolve to a DID is refused the same way, so that a
    hidden DID cannot be told from a missing one. A PFN which matches no RSE tells nothing about a DID, and is left to
    the declaration to report.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if not _use_roles() or _is_root(issuer) or _is_admin(issuer, session):
        return True
    # The replicas are given either as PFNs, or as dictionaries with a 'scope', a 'name' and an 'rse_id'.
    pfns = kwargs.get('pfns') or []
    if pfns and isinstance(pfns[0], str):
        _, pfns_by_rse, _ = get_pfn_to_rse(pfns, vo=issuer.vo, session=session)
        located = [pfn for rse_pfns in pfns_by_rse.values() for pfn in rse_pfns]
        resolved: dict[str, dict[str, Any]] = {}
        if located:
            for item in get_did_from_pfns(pfns=located, vo=issuer.vo, session=session):
                resolved.update(item)
        if not all(pfn in resolved for pfn in located):
            return False
        dids = [(resolved[pfn]['scope'], resolved[pfn]['name']) for pfn in located]
    else:
        dids = _internal_dids(issuer, pfns)

    did_access = role_core.DidAccess(issuer, session=session)
    owned_scopes: dict[InternalScope, bool] = {}
    for scope, name in dids:
        if scope not in owned_scopes:
            owned_scopes[scope] = rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
        if not (owned_scopes[scope] or did_access.grants(scope, name, DidOperationType.READ)):
            return False
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
    # its scope, or READ on it. A file which does not exist yet is created along with its replica, which the
    # gateway checks as the creation of a DID ('add_dids'). Without the DIDs, READ is required on the 'scopes' of the files.
    if not kwargs.get('dids'):
        scopes = {scope if isinstance(scope, InternalScope) else InternalScope(scope, vo=issuer.vo) for scope in kwargs.get('scopes') or []}
        return all(rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
                   or role_core.has_did_permission(issuer, scope, None, DidOperationType.READ, session=session)
                   for scope in scopes)
    return all(not _did_exists(scope, name, session)
               or rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)
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

    With RBAC, it alters the DID: owning its scope, or altering the DID through the roles, see :func:`_rbac_can_alter_did`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if not _use_roles() or _is_root(issuer) or _is_admin(issuer, session):
        return True
    scope, name = kwargs['scope'], kwargs['name']
    return rucio.core.scope.is_scope_owner(scope=scope, account=issuer, session=session)\
        or _rbac_can_alter_did(issuer, scope, name, session)


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
        or role_core.has_account_active_role(account=issuer, role=kwargs['role'], session=session)


def perm_read_data(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can read the data of a scope: the replicas of its DIDs, with their PFNs, which allow
    to download them. Every account can read every scope, unless RBAC is enabled: it then requires to read the DID
    the action names ('name'): owning its scope, or READ on it. An action naming no
    DID (a listing of the scope) only requires to own the scope or READ on some DIDs of the scope, see
    :func:`rucio.core.role.has_any_scope_prefix_access`: the gateway then filters what it returns per DID, see
    :func:`did_filter`.

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
        return role_core.has_did_permission(issuer, scope, name, DidOperationType.READ, session=session)
    return role_core.has_any_scope_prefix_access(account=issuer, scope=scope, operation=DidOperationType.READ, session=session)


# ----- Listing filters -----
#
# The gateway filters a listing item by item, with a callable built once for the listing, see
# `rucio.core.permission.did_filter`: deciding every item through `has_permission` would query the database for each
# of them. A callable decides an item as the permission functions decide it for a single DID or scope (root, admins,
# the owner of the scope, the roles, see :func:`perm_read_data`), from the roles of the account
# read once, see :class:`rucio.core.role.DidAccess`.


def is_listing_filtered(issuer: "InternalAccount", action: str, session: "Session") -> bool:
    """
    Checks if a listing is filtered for an account: only with RBAC. A policy package overriding the listing filters
    may decide it per listing, from its filter.

    :param issuer: Account identifier which issues the command.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The DB session to use
    :returns: True if the listing is filtered, otherwise False
    """
    return _use_roles()


def scope_filter(issuer: "InternalAccount", action: str, session: "Session", operation: DidOperationType = DidOperationType.READ,
                 any_did: bool = False) -> "Callable[[Optional[InternalScope]], bool]":
    """
    Builds a callable telling whether an account may perform an operation on a scope, to filter a listing.

    Root, admins and the owner of the scope may. Otherwise a role must grant the operation on the whole scope, by a
    pattern with the '*' name part which no name pattern of the role withdraws from some of its DIDs, see
    :meth:`rucio.core.role.DidAccess.role_grants`: this is meant for the items standing for the whole content of a
    scope, e.g. counts. With `any_did`, meant for listing the scopes themselves, a grant on some DIDs of the scope is
    enough, as :func:`perm_read_data` decides it for a scope.

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
        return any_did and did_access.grants_some_did(scope, operation)

    return _can_access


def did_filter(issuer: "InternalAccount", action: str, session: "Session",
               operation: DidOperationType = DidOperationType.READ) -> "Callable[[Optional[InternalScope], Optional[str]], bool]":
    """
    Builds a callable telling whether an account may perform an operation on a DID, to filter a listing.

    Root, admins and the owner of the scope may, and so may an account a role grants the operation on the whole scope
    (see :func:`scope_filter`), or on the DID itself (see :func:`rucio.core.role.has_did_permission`), and, for DELETE, an
    account altering the DID as its owner (see :func:`_rbac_can_alter_did`). The DIDs are decided one by one, so that a
    long listing is not kept in memory.

    :param issuer: Account identifier which issues the command.
    :param action: The filter of the listing, see :func:`is_listing_filtered`.
    :param session: The DB session to use
    :param operation: The operation to check.
    :returns: A callable taking a scope and a name, returning True if the account may access the DID: every DID if the
              listing is not filtered, otherwise never one whose scope is None or not an InternalScope, nor whose name
              is None unless the whole scope is granted.
    """
    if not is_listing_filtered(issuer, action, session):
        return lambda scope, name: True

    privileged = _is_root(issuer) or _is_admin(issuer, session)
    did_access = role_core.DidAccess(issuer, session=session)
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
            or (operation == DidOperationType.DELETE and _rbac_can_alter_did(issuer, scope, name, session, did_access=did_access))

    return _can_access
