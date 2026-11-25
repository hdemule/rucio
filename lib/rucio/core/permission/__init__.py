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
from collections.abc import Mapping, Sequence
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
    from rucio.core.permission.generic import MetadataKeyFilter

LOGGER = logging.getLogger('policy')

# dictionary of permission modules for each VO
permission_modules = {}

# role definitions of the instance, loaded on demand from the policy package, None until loaded
role_definitions: Optional[dict[str, dict[str, Any]]] = None

# attributes of a policy package role module disabling filters for more than a single role,
# see `get_disabled_filters_for_all_roles` and `get_disabled_filters_for_all_accounts`
DISABLE_FILTERS_FOR_ALL_ROLES = 'disable_filters_for_all_roles'
DISABLE_FILTERS_FOR_ALL_ACCOUNTS = 'disable_filters_for_all_accounts'

# filters disabled for all roles and for all accounts of the instance, keyed by the attribute defining them,
# loaded on demand from the policy package together with the role definitions, None until loaded
disabled_filters: Optional[dict[str, frozenset[str]]] = None

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


def _get_policy_package_name() -> Optional[str]:
    """
    Return the name of the policy package defining the roles of the instance.

    Roles apply to the whole instance, regardless of its VOs, so they are always defined by the main
    policy package of the instance (`RUCIO_POLICY_PACKAGE` or the `package` option of the `policy`
    section), never by the policy package of a VO.

    :returns: The name of the policy package, or None if the instance has no policy package configured.
    """
    if 'RUCIO_POLICY_PACKAGE' in environ:
        return environ['RUCIO_POLICY_PACKAGE']
    try:
        return config.config_get('policy', 'package', check_config_table=False, raise_exception=True)
    except (NoOptionError, NoSectionError):
        return None


def _parse_roles(roles: Any, module_name: str) -> dict[str, dict[str, Any]]:
    """
    Normalise the role definitions of a policy package into a dictionary keyed by role name.

    The `roles` attribute of a policy package role module may either be a mapping of
    role name to role definition, or a sequence of role definitions carrying their own
    'name' key. Both are normalised into a mapping of role name to a definition holding
    a 'description' and the 'disable_filters' of the role, see :func:`_parse_disable_filters`.
    The policy package only defines the role, its description and its disabled filters; its
    permissions and account assignments are managed from within Rucio, see
    :func:`rucio.core.role.sync_roles_from_policy_package`.

    :param roles: The `roles` attribute as defined by the policy package.
    :param module_name: The name of the role module, used for error messages.
    :returns: The role definitions keyed by role name.
    :raises ErrorLoadingPolicyPackage: If the role definitions are malformed.
    """
    if isinstance(roles, Mapping):
        definitions = [dict(definition, name=name) for name, definition in roles.items()]
    elif isinstance(roles, Sequence) and not isinstance(roles, (str, bytes)):
        definitions = list(roles)
    else:
        raise exception.ErrorLoadingPolicyPackage(
            "%s: 'roles' must be a mapping or a sequence of role definitions, got '%s'" % (module_name, type(roles).__name__))

    parsed: dict[str, dict[str, Any]] = {}
    for definition in definitions:
        if not isinstance(definition, Mapping):
            raise exception.ErrorLoadingPolicyPackage(
                "%s: each role definition must be a mapping, got '%s'" % (module_name, type(definition).__name__))

        name = definition.get('name')
        if not isinstance(name, str) or not name.strip():
            raise exception.ErrorLoadingPolicyPackage("%s: every role definition must have a non-empty 'name'" % module_name)
        name = name.strip()
        if name in parsed:
            raise exception.ErrorLoadingPolicyPackage("%s: role '%s' is defined more than once" % (module_name, name))

        parsed[name] = {
            'description': definition.get('description'),
            'disable_filters': _parse_disable_filters(definition.get('disable_filters'), "'disable_filters' of role '%s'" % name, module_name),
        }

    return parsed


def _parse_disable_filters(disable_filters: Any, source: str, module_name: str) -> frozenset[str]:
    """
    Normalise the filters a policy package disables.

    Filtering is the default: each listing drops the items in scopes the account may not read.
    A policy package disables filters for the accounts holding a role, through the optional
    'disable_filters' of the role definition, for every account holding at least one role, through
    the optional `disable_filters_for_all_roles` attribute of its role module, or for every account
    of the instance, through the optional `disable_filters_for_all_accounts` attribute of its role module,
    see :func:`rucio.core.role.is_filter_disabled`.

    :param disable_filters: The filter names as defined by the policy package, or None if it defines none.
    :param source: Where the filter names are defined, used for error messages.
    :param module_name: The name of the role module, used for error messages.
    :returns: The names of the disabled filters, empty if none is disabled.
    :raises ErrorLoadingPolicyPackage: If the filter names are not a sequence of non-empty strings.
    """
    if disable_filters is None:
        return frozenset()

    if isinstance(disable_filters, (str, bytes)) or not isinstance(disable_filters, Sequence):
        raise exception.ErrorLoadingPolicyPackage(
            "%s: %s must be a sequence of filter names, got '%s'" % (module_name, source, type(disable_filters).__name__))

    if not all(isinstance(name, str) and name.strip() for name in disable_filters):
        raise exception.ErrorLoadingPolicyPackage("%s: %s must only hold non-empty filter names" % (module_name, source))

    return frozenset(name.strip() for name in disable_filters)


def load_roles() -> None:
    """
    Load the role definitions of the instance from its policy package and cache them.

    A policy package defines the roles of an installation through a `role` module which
    exposes a `roles` attribute, and may disable filters for every account holding a role, or
    for every account of the instance, through the optional `disable_filters_for_all_roles` and
    `disable_filters_for_all_accounts` attributes. Unlike permissions there is no generic
    fallback: an instance without a policy package, or with a policy package that does not provide
    a role module, simply has no policy-defined roles and disables no filter.
    """
    global role_definitions, disabled_filters

    no_filters = dict.fromkeys((DISABLE_FILTERS_FOR_ALL_ROLES, DISABLE_FILTERS_FOR_ALL_ACCOUNTS), frozenset())

    package = _get_policy_package_name()
    if package is None:
        role_definitions, disabled_filters = {}, no_filters
        return

    try:
        package_module = importlib.import_module(package)
        check_policy_module_version(package_module)
    except ModuleNotFoundError:
        raise exception.PolicyPackageNotFound(package)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(package)

    module_name = package + '.role'
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        # a policy package may omit modules that do not need customisation
        LOGGER.debug('Policy package %s does not provide a role module, no roles defined' % package)
        role_definitions, disabled_filters = {}, no_filters
        return
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(module_name)

    filters = {
        attribute: _parse_disable_filters(getattr(module, attribute, None), "'%s'" % attribute, module_name)
        for attribute in (DISABLE_FILTERS_FOR_ALL_ROLES, DISABLE_FILTERS_FOR_ALL_ACCOUNTS)
    }

    roles = getattr(module, 'roles', None)
    if roles is None:
        LOGGER.warning("Role module %s does not define 'roles', no roles defined" % module_name)
        role_definitions = {}
    else:
        role_definitions = _parse_roles(roles, module_name)
    disabled_filters = filters


def get_roles() -> dict[str, dict[str, Any]]:
    """
    Get the role definitions provided by the policy package of the instance.

    The definitions are loaded from the policy package on first use and cached afterwards.

    :returns: A dictionary mapping role name to its definition, each holding a 'description' and its 'disable_filters'.
              Empty if the instance has no policy-defined roles.
    """
    if role_definitions is None:
        load_roles()
    assert role_definitions is not None
    return role_definitions


def get_disabled_filters_for_all_roles() -> frozenset[str]:
    """
    Get the filters the policy package of the instance disables for every account holding at least one role.

    These filters are disabled by any role the account holds through an assignment which has not
    expired yet, except a reserved role, whether or not the policy package defines that role.
    They are loaded from the policy package on first use and cached afterwards, together with the
    role definitions.

    :returns: The names of the filters disabled for every role, empty if none is disabled.
    """
    if disabled_filters is None:
        load_roles()
    assert disabled_filters is not None
    return disabled_filters[DISABLE_FILTERS_FOR_ALL_ROLES]


def get_disabled_filters_for_all_accounts() -> frozenset[str]:
    """
    Get the filters the policy package of the instance disables for every account.

    These filters are disabled regardless of the roles of the account, including for an account
    which holds no role at all. They are loaded from the policy package on first use and cached
    afterwards, together with the role definitions.

    :returns: The names of the filters disabled for every account, empty if none is disabled.
    """
    if disabled_filters is None:
        load_roles()
    assert disabled_filters is not None
    return disabled_filters[DISABLE_FILTERS_FOR_ALL_ACCOUNTS]


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

def _policy_function(issuer: "InternalAccount", name: str) -> "Callable[..., Any]":
    """The function of the policy package of the VO of the issuer, or the generic one if the policy package does not define it."""
    if issuer.vo not in permission_modules:
        load_permission_for_vo(issuer.vo)
    return getattr(permission_modules[issuer.vo], name, None) or getattr(rucio.core.permission.generic, name)


def is_listing_filtered(issuer: "InternalAccount", action: str, *, session: "Session") -> bool:
    """
    Tell whether a listing is filtered for an account, see :func:`rucio.core.permission.generic.is_listing_filtered`.

    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The database session.
    """
    return _policy_function(issuer, 'is_listing_filtered')(issuer, action, session=session)


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
    return _policy_function(issuer, 'scope_filter')(issuer, action, session=session, operation=operation, any_did=any_did)


def did_filter(issuer: "InternalAccount", action: str, *, session: "Session", operation: DidOperationType = DidOperationType.READ,
               reads_data: bool = False) -> "Callable[[Optional[InternalScope], Optional[str]], bool]":
    """
    Build a callable telling whether an account may perform an operation on a DID, see :func:`rucio.core.permission.generic.did_filter`.

    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The database session.
    :param operation: The operation to check.
    :param reads_data: Whether the data of the DIDs are read, e.g. the PFNs of their replicas.
    """
    return _policy_function(issuer, 'did_filter')(issuer, action, session=session, operation=operation, reads_data=reads_data)


def metadata_key_filter(issuer: "InternalAccount", *, session: "Session") -> "MetadataKeyFilter":
    """
    Build the filter hiding from the DIDs an account sees the metadata keys it may not read, see
    :func:`rucio.core.permission.generic.metadata_key_filter`.

    :param issuer: The account the listing is made for.
    :param session: The database session.
    """
    return _policy_function(issuer, 'metadata_key_filter')(issuer, session=session)


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
                operation: DidOperationType = DidOperationType.READ, reads_data: bool = False, scope_keyword: str = "scope",
                name_keyword: str = "name") -> "Iterator[dict[str, Any]]":
    """
    Yield the items whose DID the account may perform an operation on, see :func:`did_filter`.

    :param items: The items, each with the scope and the name of its DID under `scope_keyword` and `name_keyword`.
    :param issuer: The account the listing is made for.
    :param action: The filter of the listing, e.g. 'list_dids'.
    :param session: The database session.
    :param operation: The operation to check.
    :param reads_data: Whether the data of the DIDs are read, e.g. the PFNs of their replicas.
    :param scope_keyword: The key of the scope in the items.
    :param name_keyword: The key of the name in the items.
    """
    can_access = did_filter(issuer, action, session=session, operation=operation, reads_data=reads_data)
    for item in items:
        if can_access(item.get(scope_keyword), item.get(name_keyword)):
            yield item


def filter_metadata_keys(items: "Iterable[dict[str, Any]]", issuer: "InternalAccount", *, session: "Session", scope_keyword: str = "scope",
                         name_keyword: str = "name") -> "Iterator[dict[str, Any]]":
    """
    Yield the items standing for DIDs, each with only the metadata keys the account may read, see :func:`metadata_key_filter`.
    The DIDs themselves are filtered beforehand, with :func:`filter_dids`.

    :param items: The items, each with the scope and the name of its DID under `scope_keyword` and `name_keyword`.
    :param issuer: The account the listing is made for.
    :param session: The database session.
    :param scope_keyword: The key of the scope in the items.
    :param name_keyword: The key of the name in the items.
    """
    key_filter = metadata_key_filter(issuer, session=session)
    for item in items:
        yield key_filter.project_item(item, scope_keyword=scope_keyword, name_keyword=name_keyword)
