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

import importlib
import logging
from configparser import NoOptionError, NoSectionError
from os import environ
from typing import TYPE_CHECKING, Any, Optional

import rucio.core.permission.generic
from rucio.common import config, exception
from rucio.common.constants import DEFAULT_VO
from rucio.common.plugins import check_policy_module_version
from rucio.common.policy import get_policy
from rucio.db.sqla.constants import DatabaseOperationType, DidOperationType
from rucio.db.sqla.session import db_session

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, InternalScope

LOGGER = logging.getLogger('policy')

# dictionary of permission modules for each VO
permission_modules = {}

try:
    multivo = config.config_get_bool('common', 'multi_vo')
except (NoOptionError, NoSectionError):
    multivo = False

# in multi-vo mode packages are loaded on demand when needed
if not multivo:
    generic_fallback = 'generic'

    fallback_policy = get_policy()
    if fallback_policy == 'def':
        fallback_policy = generic_fallback

    try:
        if 'RUCIO_POLICY_PACKAGE' in environ:
            policy = environ['RUCIO_POLICY_PACKAGE']
        else:
            policy = config.config_get('policy', 'package', check_config_table=False, raise_exception=True)
        package_module = importlib.import_module(policy)
        check_policy_module_version(package_module)
        policy = policy + ".permission"
    except (NoOptionError, NoSectionError):
        policy = 'rucio.core.permission.' + fallback_policy.lower()
    except ModuleNotFoundError:
        raise exception.PolicyPackageNotFound(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain permission module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load permission module %s from policy package, falling back to %s'
                           % (policy, fallback_policy))
            policy = 'rucio.core.permission.' + fallback_policy.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    permission_modules[DEFAULT_VO] = module


def load_permission_for_vo(vo: str) -> None:
    generic_fallback = 'generic_multi_vo'
    try:
        env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper()
        if env_name in environ:
            policy = environ[env_name]
        else:
            policy = config.config_get('policy', 'package-' + vo, raise_exception=True)
        package_module = importlib.import_module(policy)
        check_policy_module_version(package_module)
        policy = policy + ".permission"
    except (NoOptionError, NoSectionError):
        policy = 'rucio.core.permission.' + generic_fallback.lower()
    except ModuleNotFoundError:
        raise exception.PolicyPackageNotFound(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain permission module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load permission module %s from policy package, falling back to %s'
                           % (policy, generic_fallback))
            policy = 'rucio.core.permission.' + generic_fallback.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
        raise exception.PolicyPackageNotFound(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    permission_modules[vo] = module


def _get_policy_function(vo: str, name: str) -> "Callable[..., Any]":
    """
    Get a function of the permission module of a VO, loading the module if needed, see :func:`load_permission_for_vo`.

    :param vo: The VO.
    :param name: The name of the function.
    :returns: The function of the permission module of the VO, or the generic one if that module does not define it.
    """
    if vo not in permission_modules:
        load_permission_for_vo(vo)
    return getattr(permission_modules[vo], name, None) or getattr(rucio.core.permission.generic, name)


class PermissionResult:
    """
    Represents the result of a permission check, allowing an optional message to be
    included to give the user more information.
    """
    def __init__(self, allowed: bool, message: "Optional[str]" = "") -> None:
        self.allowed = allowed
        self.message = message

    # allow this to be tested as a bool for backwards compatibility
    def __bool__(self) -> bool:
        return self.allowed


def has_permission(
        issuer: "InternalAccount",
        action: str,
        kwargs: dict[str, Any],
        session: Optional["Session"] = None  # TODO - make it a required parameter in v40: https://github.com/rucio/rucio/issues/8175
) -> PermissionResult:
    if issuer.vo not in permission_modules:
        load_permission_for_vo(issuer.vo)

    # TODO - remove this if statement: https://github.com/rucio/rucio/issues/8175,
    # and only keep the path where session is passed
    if not session:
        LOGGER.warning("`session` argument nor provided to has_permission. "
                       "`session` will become a required parameter from Rucio v40 onwards. "
                       "For more information, see https://github.com/rucio/rucio/issues/8175")

        with db_session(DatabaseOperationType.READ) as session:
            try:
                result = permission_modules[issuer.vo].has_permission(issuer, action, kwargs, session=session)
            except TypeError:
                # will be thrown if policy package is missing the action in its perm dictionary
                result = None
            # if this permission is missing from the policy package, fallback to generic
            if result is None:
                result = rucio.core.permission.generic.has_permission(issuer, action, kwargs, session=session)
    else:
        try:
            result = permission_modules[issuer.vo].has_permission(issuer, action, kwargs, session=session)
        except TypeError:
            # will be thrown if policy package is missing the action in its perm dictionary
            result = None
        # if this permission is missing from the policy package, fallback to generic
        if result is None:
            result = rucio.core.permission.generic.has_permission(issuer, action, kwargs, session=session)

    # continue to support policy packages that just return a boolean and no message
    if isinstance(result, bool):
        result = PermissionResult(result)
    return result


# ----------------------------------------------------------------------------------------------
# Listing filters
#
# A listing is filtered item by item with a callable built once for the listing, rather than with `has_permission`
# for each item. Like the permissions, the filters are those of the policy package of the VO of the issuer, falling
# back to the generic ones, see :mod:`rucio.core.permission.generic`, for each filter the policy package does not define.
# ----------------------------------------------------------------------------------------------

def is_listing_filtered(issuer: "InternalAccount", action: str, *, session: "Session") -> bool:
    """
    Tell whether a listing is filtered for an account, see :func:`rucio.core.permission.generic.is_listing_filtered`.

    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The database session.
    """
    return _get_policy_function(issuer.vo, 'is_listing_filtered')(issuer, action, session=session)


def scope_filter(issuer: "InternalAccount", action: str, *, session: "Session", operation: DidOperationType = DidOperationType.READ,
                 any_did: bool = False) -> "Callable[[Optional[InternalScope]], bool]":
    """
    Build a callable telling whether an account may perform an operation on a scope, see :func:`rucio.core.permission.generic.scope_filter`.

    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_scopes'.
    :param session: The database session.
    :param operation: The operation to check.
    :param any_did: Grant a scope if the operation is granted on some of its DIDs.
    """
    return _get_policy_function(issuer.vo, 'scope_filter')(issuer, action, session=session, operation=operation, any_did=any_did)


def did_filter(issuer: "InternalAccount", action: str, *, session: "Session",
               operation: DidOperationType = DidOperationType.READ) -> "Callable[[Optional[InternalScope], Optional[str]], bool]":
    """
    Build a callable telling whether an account may perform an operation on a DID, see :func:`rucio.core.permission.generic.did_filter`.

    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The database session.
    :param operation: The operation to check.
    """
    return _get_policy_function(issuer.vo, 'did_filter')(issuer, action, session=session, operation=operation)


def filter_scopes(items: "Iterable[dict[str, Any]]", issuer: "InternalAccount", action: str, *, session: "Session",
                  operation: DidOperationType = DidOperationType.READ, any_did: bool = False, scope_keyword: str = "scope") -> "Iterator[dict[str, Any]]":
    """
    Yield the items whose scope the account may perform an operation on, see :func:`scope_filter`.
    Items standing for DIDs are filtered with :func:`filter_dids` instead.

    :param items: The items, each with its scope under `scope_keyword`.
    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_scopes'.
    :param session: The database session.
    :param operation: The operation to check.
    :param any_did: Yield an item if the operation is granted on some DIDs of its scope.
    :param scope_keyword: The key of the scope in the items.
    """
    can_access = scope_filter(issuer, action, session=session, operation=operation, any_did=any_did)
    for item in items:
        if can_access(item.get(scope_keyword)):
            yield item


def filter_dids(items: "Iterable[dict[str, Any]]", issuer: "InternalAccount", action: str, *, session: "Session",
                operation: DidOperationType = DidOperationType.READ, scope_keyword: str = "scope",
                name_keyword: str = "name") -> "Iterator[dict[str, Any]]":
    """
    Yield the items whose DID the account may perform an operation on, see :func:`did_filter`.

    :param items: The items, each with the scope and the name of its DID under `scope_keyword` and `name_keyword`.
    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The database session.
    :param operation: The operation to check.
    :param scope_keyword: The key of the scope in the items.
    :param name_keyword: The key of the name in the items.
    """
    can_access = did_filter(issuer, action, session=session, operation=operation)
    for item in items:
        if can_access(item.get(scope_keyword), item.get(name_keyword)):
            yield item
