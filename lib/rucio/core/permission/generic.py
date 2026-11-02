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

from typing import TYPE_CHECKING, Any

import rucio.core.scope
from rucio.common.constants import RseAttr
from rucio.common.exception import RuleNotFound
from rucio.common.types import InternalScope
from rucio.core import role as role_core
from rucio.core.account import has_account_attribute, list_account_attributes
from rucio.core.did import get_did
from rucio.core.identity import exist_identity_account
from rucio.core.lifetime_exception import list_exceptions
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rule
from rucio.db.sqla.constants import IdentityType, ScopeOperationType

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount

# Metadata keys whose update leads to the removal of the DID (e.g. `rucio did remove` sets the lifetime),
# so a role must grant DELETE instead of WRITE to set them.
RBAC_DELETE_METADATA_KEYS = {'lifetime'}

# Options of a replication rule that RBAC allows a non-admin account to update, provided it may DELETE the rule.
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


def _rbac_grants_on_scope(issuer: "InternalAccount", scope: "InternalScope", operation: ScopeOperationType, session: "Session") -> bool:
    """
    Checks if RBAC grants an account an operation on a scope, see :func:`rucio.core.role.has_permission`.
    Like every `_rbac_grants_*` helper, it does not check whether RBAC is enabled: the caller does, see :func:`_use_roles`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope to check.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param session: The DB session to use
    :returns: True if RBAC grants the operation, otherwise False
    """
    request = role_core.ScopePermissionRequest(operation=operation, scope=scope)
    return role_core.has_permission(account=issuer, request=request, session=session)


def _rbac_grants_on_scopes(issuer: "InternalAccount", scopes: "Iterable[InternalScope | str]", operation: ScopeOperationType, session: "Session") -> bool:
    """
    Checks if RBAC grants an account an operation on all the given scopes, see :func:`_rbac_grants_on_scope`.

    :param issuer: Account identifier which issues the command.
    :param scopes: The scopes to check. External scope names are resolved in the VO of the issuer.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param session: The DB session to use
    :returns: True if RBAC grants the operation on every scope (or if there is none), otherwise False
    """
    internal_scopes = {scope if isinstance(scope, InternalScope) else InternalScope(scope, vo=issuer.vo) for scope in scopes}
    return all(_rbac_grants_on_scope(issuer, scope, operation, session) for scope in internal_scopes)


def _rbac_grants_on_owned(issuer: "InternalAccount", scope: "InternalScope", operation: ScopeOperationType, is_owner: "Callable[[], bool]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account an operation on an object of a scope that it may own (a DID, a rule), see :func:`_rbac_grants_on_scope`.
    Owning the object lowers DELETE to WRITE: an account allowed to add content to a scope can also update and remove
    its own content, while DELETE on the scope allows to manage any content of the scope.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the object.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param is_owner: Returns whether the issuer owns the object, only called when the ownership matters.
    :param session: The DB session to use
    :returns: True if RBAC grants the operation, otherwise False
    """
    if _rbac_grants_on_scope(issuer, scope, operation, session):
        return True
    return operation == ScopeOperationType.DELETE\
        and _rbac_grants_on_scope(issuer, scope, ScopeOperationType.WRITE, session)\
        and is_owner()


def _rbac_grants_on_did(issuer: "InternalAccount", scope: "InternalScope", name: str, operation: ScopeOperationType, session: "Session") -> bool:
    """
    Checks if RBAC grants an account an operation on a DID, see :func:`_rbac_grants_on_owned`.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param session: The DB session to use
    :returns: True if RBAC grants the operation, otherwise False
    :raises DataIdentifierNotFound: If the ownership matters and the DID does not exist.
    """
    return _rbac_grants_on_owned(issuer, scope, operation, lambda: get_did(scope=scope, name=name, session=session)['account'] == issuer, session)


def _rbac_grants_on_rule(issuer: "InternalAccount", rule_id: str, operations: "Iterable[ScopeOperationType]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account operations on a replication rule, given the scope of its DID, see :func:`_rbac_grants_on_owned`.

    :param issuer: Account identifier which issues the command.
    :param rule_id: The id of the rule.
    :param operations: The operations needed on the scope of the rule.
    :param session: The DB session to use
    :returns: True if RBAC grants all the operations, otherwise False (also if the rule does not exist)
    """
    try:
        rule = get_rule(rule_id=rule_id, session=session)
    except RuleNotFound:
        return False
    return all(_rbac_grants_on_owned(issuer, rule['scope'], operation, lambda: rule['account'] == issuer, session) for operation in operations)


def _rbac_grants_metadata(issuer: "InternalAccount", scope: "InternalScope", name: str, keys: "Iterable[str]", session: "Session") -> bool:
    """
    Checks if RBAC grants an account to set metadata keys on a DID: DELETE for the keys leading to
    the removal of the DID (see RBAC_DELETE_METADATA_KEYS), WRITE for the others.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param keys: The metadata keys to set.
    :param session: The DB session to use
    :returns: True if RBAC grants the operations, otherwise False
    """
    operations = {ScopeOperationType.DELETE if key in RBAC_DELETE_METADATA_KEYS else ScopeOperationType.WRITE for key in keys} or {ScopeOperationType.WRITE}
    return all(_rbac_grants_on_did(issuer, scope, name, operation, session) for operation in operations)


def _rbac_grants_attach(issuer: "InternalAccount", scope: "InternalScope", attachment: dict[str, Any], session: "Session") -> bool:
    """
    Checks if RBAC grants an account to attach DIDs to a collection: attaching adds content to the collection,
    so it requires WRITE on the scope of the collection, and READ on the scopes of the attached DIDs.
    When an RSE is given, the attached files are registered as replicas (and created if missing),
    so WRITE is required on their scopes instead.

    :param issuer: Account identifier which issues the command.
    :param scope: The scope of the collection.
    :param attachment: The attachment, holding the attached 'dids' and optionally the 'rse_id'.
    :param session: The DB session to use
    :returns: True if RBAC grants the attachment, otherwise False
    """
    if not _rbac_grants_on_scope(issuer, scope, ScopeOperationType.WRITE, session):
        return False
    child_operation = ScopeOperationType.WRITE if attachment.get('rse_id') else ScopeOperationType.READ
    return _rbac_grants_on_scopes(issuer, [did['scope'] for did in attachment.get('dids', [])], child_operation, session)


def _rbac_grants_on_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], operation: ScopeOperationType, session: "Session") -> bool:
    """
    Checks if RBAC grants an account an operation on replicas: only on the RSEs listed in RBAC_REPLICA_RSE_SUFFIXES,
    and it requires the operation on the scopes of the files.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action, holding the 'rse' and the 'scopes' of the files.
    :param operation: The operation to check (READ, WRITE, DELETE).
    :param session: The DB session to use
    :returns: True if RBAC grants the operation, otherwise False
    """
    return str(kwargs['rse']).endswith(RBAC_REPLICA_RSE_SUFFIXES)\
        and bool(kwargs['scopes'])\
        and _rbac_grants_on_scopes(issuer, kwargs['scopes'], operation, session)


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
        return True
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

    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and _rbac_grants_on_scope(issuer, kwargs['scope'], ScopeOperationType.WRITE, session))


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
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and _rbac_grants_attach(issuer, kwargs['scope'], kwargs['attachment'], session))


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
    else:
        attachments = kwargs['attachments']
        scopes = [did['scope'] for did in attachments]
        scopes = list(set(scopes))
        for scope in scopes:
            if not rucio.core.scope.is_scope_owner(scope, issuer, session=session):
                return _use_roles() and all(_rbac_grants_attach(issuer, attachment['scope'], attachment, session) for attachment in attachments)
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
        or (_use_roles() and _rbac_grants_on_scope(issuer, kwargs['scope'], ScopeOperationType.WRITE, session))


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
    return _use_roles() and _rbac_grants_on_rule(issuer, kwargs['rule_id'], [ScopeOperationType.DELETE], session)


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
        and _rbac_grants_on_rule(issuer, kwargs['rule_id'], [ScopeOperationType.DELETE], session)


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
    return _use_roles() and _rbac_grants_on_rule(issuer, kwargs['rule_id'], [ScopeOperationType.DELETE], session)


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
        and _rbac_grants_on_rule(issuer, kwargs['rule_id'], [ScopeOperationType.WRITE, ScopeOperationType.DELETE], session)


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
    # Unlike attaching, RBAC requires DELETE on the collection to detach from it, so the role check of perm_attach_dids does not apply.
    return _is_root(issuer)\
        or _is_admin(issuer, session)\
        or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or kwargs['scope'].external == 'mock'\
        or (_use_roles() and _rbac_grants_on_did(issuer, kwargs['scope'], kwargs['name'], ScopeOperationType.DELETE, session))


def perm_set_metadata_bulk(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session) or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or (_use_roles() and _rbac_grants_metadata(issuer, kwargs['scope'], kwargs['name'], kwargs['meta'], session))


def perm_set_metadata(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can set a metadata on a data identifier.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session) or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or (_use_roles() and _rbac_grants_metadata(issuer, kwargs['scope'], kwargs['name'], [kwargs['key']], session))


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

    # Closing a collection prevents any further change of its content, so RBAC requires DELETE on it.
    return _is_root(issuer) or _is_admin(issuer, session) or rucio.core.scope.is_scope_owner(scope=kwargs['scope'], account=issuer, session=session)\
        or (_use_roles() and _rbac_grants_on_did(issuer, kwargs['scope'], kwargs['name'], ScopeOperationType.DELETE, session))


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
    return str(kwargs.get('rse', '')).endswith('SCRATCHDISK')\
        or str(kwargs.get('rse', '')).endswith('USERDISK')\
        or str(kwargs.get('rse', '')).endswith('MOCK')\
        or str(kwargs.get('rse', '')).endswith('LOCALGROUPDISK')\
        or _is_root(issuer)\
        or _is_admin(issuer, session)


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
    return _use_roles() and _rbac_grants_on_replicas(issuer, kwargs, ScopeOperationType.DELETE, session)


def perm_update_replicas_states(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can delete replicas.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)\
        or (_use_roles() and _rbac_grants_on_replicas(issuer, kwargs, ScopeOperationType.DELETE, session))


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
    Checks if an account can delete a metadata key of a data identifier. RBAC requires DELETE on the DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or _is_admin(issuer, session)\
        or (_use_roles() and _rbac_grants_on_did(issuer, kwargs['scope'], kwargs['name'], ScopeOperationType.DELETE, session))


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
    Every account can read every scope, unless RBAC is enabled: it then requires READ on the scope, see :func:`_rbac_grants_on_scope`.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return not _use_roles()\
        or _is_root(issuer)\
        or _is_admin(issuer, session)\
        or _rbac_grants_on_scope(issuer, kwargs['scope'], ScopeOperationType.READ, session)
