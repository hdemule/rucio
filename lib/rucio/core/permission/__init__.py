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
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount

LOGGER = logging.getLogger('policy')

# dictionary of permission modules for each VO
permission_modules = {}

# dictionary of role definitions for each VO, loaded on demand from the policy package
role_definitions: dict[str, dict[str, dict[str, Any]]] = {}

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


def _get_policy_package_name(vo: str) -> Optional[str]:
    """
    Return the name of the policy package configured for a VO.

    :param vo: The VO to look the policy package up for.
    :returns: The name of the policy package, or None if the VO has no policy package configured.
    """
    if vo == DEFAULT_VO:
        env_name, config_option = 'RUCIO_POLICY_PACKAGE', 'package'
    else:
        env_name, config_option = 'RUCIO_POLICY_PACKAGE_' + vo.upper(), 'package-' + vo

    if env_name in environ:
        return environ[env_name]
    try:
        return config.config_get('policy', config_option, check_config_table=False, raise_exception=True)
    except (NoOptionError, NoSectionError):
        return None


def _parse_roles(roles: Any, module_name: str) -> dict[str, dict[str, Any]]:
    """
    Normalise the role definitions of a policy package into a dictionary keyed by role name.

    The `roles` attribute of a policy package role module may either be a mapping of
    role name to role definition, or a sequence of role definitions carrying their own
    'name' key. Both are normalised into a mapping of role name to a definition holding
    a 'description'. The policy package only defines the role and its description; its
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
        }

    return parsed


def load_roles_for_vo(vo: str) -> None:
    """
    Load the role definitions of a VO from its policy package and cache them.

    A policy package defines the roles of an installation through a `role` module which
    exposes a `roles` attribute. Unlike permissions there is no generic fallback: a VO
    without a policy package, or with a policy package that does not provide a role
    module, simply has no policy-defined roles.

    :param vo: The VO to load the role definitions for.
    """
    package = _get_policy_package_name(vo)
    if package is None:
        role_definitions[vo] = {}
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
        LOGGER.debug('Policy package %s does not provide a role module, no roles defined for VO %s' % (package, vo))
        role_definitions[vo] = {}
        return
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(module_name)

    roles = getattr(module, 'roles', None)
    if roles is None:
        LOGGER.warning("Role module %s does not define 'roles', no roles defined for VO %s" % (module_name, vo))
        role_definitions[vo] = {}
        return

    role_definitions[vo] = _parse_roles(roles, module_name)


def get_roles(vo: str = DEFAULT_VO) -> dict[str, dict[str, Any]]:
    """
    Get the role definitions provided by the policy package of a VO.

    The definitions are loaded from the policy package on first use and cached afterwards.

    :param vo: The VO to get the role definitions for.
    :returns: A dictionary mapping role name to its definition, each holding a 'description'.
              Empty if the VO has no policy-defined roles.
    """
    if vo not in role_definitions:
        load_roles_for_vo(vo)
    return role_definitions[vo]


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
