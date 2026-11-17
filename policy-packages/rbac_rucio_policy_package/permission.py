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

if TYPE_CHECKING:
    from typing import Optional

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount


def has_permission(issuer: "InternalAccount", action: str, kwargs: dict[str, Any], session: "Session") -> "Optional[bool]":
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    This policy package does not customise any permission: every action is left to the generic
    permission policy, see :mod:`rucio.core.permission.generic`, which handles RBAC itself.
    To customise an action, return True or False for it here.

    :param issuer: Account identifier which issues the command.
    :param action:  The action(API call) called by the account.
    :param kwargs: List of arguments for the action.
    :param session: The DB session to use
    :returns: True/False if this package handles the action, None to defer to the generic policy
    """
    return None
