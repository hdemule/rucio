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

from typing import TYPE_CHECKING, Optional, cast

from sqlalchemy import and_, select

from rucio.db.sqla import models

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, InternalScope, PermissionDict
    from rucio.db.sqla.constants import DatabaseOperationType


def list_roles(account: "InternalAccount", session: "Session"):
    pass


def list_role_permissions(account: "InternalAccount", session: "Session", permission_type: Optional["DatabaseOperationType"] = None) -> list["PermissionDict"]:
    """
    List all permissions (scope + operation) granted to an account via its roles.

    :param account: The account to list permissions for.
    :param session: The database session in which to perform the query.
    :param permission_type: Optional filter to only return permissions of a specific type (e.g., READ, WRITE).
    :return: A list of permissions granted to the account.
    """
    # Join instead of an IN-subquery so the planner can use the PKs on both mapping tables directly,
    # and dedupe since two different roles can grant the same (scope, operation) pair.
    permissions_query = (
        select(models.RolePermissionAssociation.scope, models.RolePermissionAssociation.operation)
        .join(models.AccountRoleAssociation, models.AccountRoleAssociation.role == models.RolePermissionAssociation.role)
        .where(models.AccountRoleAssociation.account == account)
        .distinct()
    )

    # If a specific permission type is provided, filter the permissions query
    if permission_type:
        permissions_query = permissions_query.where(models.RolePermissionAssociation.operation == permission_type)

    # Execute the query and return the results
    return [cast("PermissionDict", row._asdict()) for row in session.execute(permissions_query).all()]


def list_role_scopes(account: "InternalAccount", session: "Session", permission_type: "DatabaseOperationType") -> list["InternalScope"]:
    """
    List all scopes that the account is allowed to access based on its roles and the specified permission type.

    :param account: The account to list scopes for.
    :param session: The database session in which to perform the query.
    :param permission_type: The type of permission (e.g., READ, WRITE) to filter the scopes.
    :return: A list of scopes that the account is allowed to access.
    """
    query = (
        select(models.RolePermissionAssociation.scope)
        .join(models.AccountRoleAssociation, models.AccountRoleAssociation.role == models.RolePermissionAssociation.role)
        .where(
            and_(
                models.AccountRoleAssociation.account == account,
                models.RolePermissionAssociation.operation == permission_type,
            )
        )
        .distinct()
    )
    res = session.execute(query).fetchall()

    return [row.scope for row in res]
