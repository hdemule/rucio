from typing import TYPE_CHECKING, Any

import rucio.core.did
import rucio.core.scope
from rucio.common.constants import RseAttr
from rucio.core.account import has_account_attribute, list_account_attributes
from rucio.core.identity import exist_identity_account
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rule
from rucio.db.sqla.constants import BadPFNStatus, IdentityType

if TYPE_CHECKING:
    from typing import Optional

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount


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
        }

    handler = perm.get(action)
    if handler is None:
        return None

    return handler(issuer=issuer, kwargs=kwargs, session=session)


def _is_root(issuer) -> bool:
    return issuer.external == 'root'


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
    if _is_root(issuer) or has_account_attribute(account=issuer, key='admin', session=session):
        return True

    scope_queried = str(kwargs.get('scope'))
    account_attributes = list_account_attributes(account=issuer, session=session)

    allowed_scopes_pattern = ""

    for kv in account_attributes:
        if kv["key"] == "read_scopes":
            allowed_scopes_pattern = kv["value"]
            if type(allowed_scopes_pattern) is not str:
                raise ValueError(f"Account attribute are misconfigured, 'read_scopes' must be a string, got {type(allowed_scopes_pattern)}")
            break

    # "scope1,scope2,scope3" => ["scope1", "scope2", "scope3"]
    allowed_scopes = [s.strip() for s in allowed_scopes_pattern.split(",") if s.strip()]

    return scope_queried in allowed_scopes
