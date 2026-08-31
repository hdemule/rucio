import logging
from typing import TYPE_CHECKING, Any

from rucio.core.account import has_account_attribute
from rucio.core.roles import list_account_scopes
from rucio.db.sqla.constants import DatabaseOperationType

if TYPE_CHECKING:
    from typing import Optional

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, InternalScope


def has_permission(issuer: "InternalAccount", action: str, kwargs: dict[str, Any], session: "Session") -> "Optional[bool]":
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer: Account identifier which issues the command..
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True/False if this package handles the action, None to defer to the generic policy
    """
    perm = {
        'list_dids': perm_list_dids,
        'list_parent_dids': perm_list_parent_dids,
        'get_did': perm_get_did,
        'get_metadata': perm_get_metadata,
        'get_metadata_bulk': perm_get_metadata,  # Bulk metadata retrieval uses the same permission check as single metadata retrieval
        'list_content': perm_list_content,
        'list_content_history': perm_list_content_history,
        'list_files': perm_list_files,
        'list_replication_rule_full_history': perm_list_replication_rule_full_history,
        'get_replication_rule': perm_get_replication_rule,
        'examine_replication_rule': perm_examine_replication_rule,
        'get_dataset_locks': perm_get_dataset_locks,
        'get_dataset_locks_bulk': perm_get_dataset_locks,  # Bulk dataset locks retrieval uses the same permission check as single dataset locks retrieval
        'list_associated_replication_rules_for_file': perm_list_associated_replication_rules_for_file,
        'list_replicas': perm_list_replicas,
        'list_dataset_replicas': perm_list_dataset_replicas,
        'list_dataset_replicas_bulk': perm_list_dataset_replicas,  # Bulk dataset replicas retrieval uses the same permission check as single dataset replicas retrieval
        'list_dataset_replicas_vp': perm_list_dataset_replicas_vp,
        'get_replica_locks_for_rule_id': perm_replica_locks_for_rule_id,
        'know_if_rule_exists': perm_default,  # Considered an admin privilege.
        }

    handler = perm.get(action)
    if handler is None:
        return None

    logging.log(logging.ERROR, "[HUGO] HAS_PERMISSION, issuer: %s, action: %s, kwargs: %s, handler: %s", issuer, action, kwargs, handler.__name__)

    return handler(issuer=issuer, kwargs=kwargs, session=session)


def _is_root(issuer) -> bool:
    return issuer.external == 'root'


def _is_admin(issuer: "InternalAccount", session: "Session") -> bool:
    """
    Checks if an account is an admin.

    :param issuer: Account identifier which issues the command.
    :param session: The DB session to use
    :returns: True if account is admin, otherwise False
    """
    return has_account_attribute(account=issuer, key='admin', session=session)


def _can_read_scope(issuer: "InternalAccount", scope_str: str, session: "Session") -> bool:
    """
    Checks if an account can read a scope. Admins and root can read all scopes by default, other accounts can read scopes that are listed in the 'read_scopes' account attribute.


    :param issuer: Account identifier which issues the command.
    :param scope_str: The scope to check.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    if _is_root(issuer) or _is_admin(issuer, session):
        return True

    read_scopes: list[InternalScope] = list_account_scopes(account=issuer, session=session, permission_type=DatabaseOperationType.READ)

    return scope_str in [scope.external for scope in read_scopes if scope.external is not None]


def perm_default(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Default permission.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _is_root(issuer) or has_account_attribute(account=issuer, key='admin', session=session)


def perm_list_dids(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list DIDs in a scope.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_parent_dids(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list parent DIDs of a DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_get_did(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get a DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_get_metadata(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get metadata of a DID.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_content(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the content of a DID.
    ! Note: Check that a user cannot read anything if the parent scope is not readable. Otherwise, consider filter data instead.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_content_history(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the content history of a DID.
    ! Note: Check that a user cannot read anything if the parent scope is not readable. Otherwise, consider filter data instead.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_files(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the files of a DID.
    ! Note: Check that a user cannot read anything if the parent scope is not readable. Otherwise, consider filter data instead.

    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_replication_rule_full_history(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the full replication rule history of a DID.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_get_replication_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get a replication rule.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_examine_replication_rule(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can examine a replication rule.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_get_dataset_locks(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get the locks of a dataset.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_associated_replication_rules_for_file(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the associated replication rules for a file.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_dataset_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the replicas of a dataset.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_replicas(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the replicas of a DID.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_list_dataset_replicas_vp(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can list the replicas of a dataset (VP).
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)


def perm_replica_locks_for_rule_id(issuer: "InternalAccount", kwargs: dict[str, Any], session: "Session") -> bool:
    """
    Checks if an account can get the replica locks for a rule_id.
    :param issuer: Account identifier which issues the command.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True if account is allowed, otherwise False
    """
    return _can_read_scope(issuer=issuer, scope_str=str(kwargs.get('scope')), session=session)
