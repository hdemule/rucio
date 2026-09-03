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

from sqlalchemy import exists, or_, select

from rucio.db.sqla import models

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from sqlalchemy.sql.elements import ColumnElement
    from sqlalchemy.sql.selectable import Select

    from rucio.common.types import InternalAccount, InternalScope
    from rucio.db.sqla.constants import DatabaseOperationType


def _scope_access_condition(
    account: "InternalAccount",
    operation: "DatabaseOperationType",
    scope_column: Any,
) -> "ColumnElement":
    """
    Return a SQLAlchemy boolean expression that is true iff `account`
    has `operation` permission on the scope represented by `scope_column`.

    This can be used inside a .where(...) clause to restrict rows to
    those whose scope the account is allowed to access.

    :param account: The account performing the operation.
    :param operation: READ, WRITE, etc.
    :param scope_column: The column in the query that represents the scope
                         (e.g. models.DataIdentifierAssociation.scope).
    """
    return exists(
        select(1)
        .select_from(models.AccountRoleAssociation)
        .join(
            models.RolePermissionAssociation,
            models.RolePermissionAssociation.role
            == models.AccountRoleAssociation.role,
        )
        .where(
            models.AccountRoleAssociation.account == account,
            models.RolePermissionAssociation.scope == scope_column,
            models.RolePermissionAssociation.operation == operation,
        )
    )


def filter_query_by_scope_access(
    stmt: "Select",
    *,
    account: "InternalAccount",
    operation: "DatabaseOperationType",
    scope_column: Any,
    owner_column: Any,
) -> "Select":
    """
    Add an RBAC + ownership predicate to a SQLAlchemy SELECT statement.

    The returned statement will only return rows where the account either:
      - owns the row (owner_column == account), OR
      - has the specified operation permission on the row's scope via RBAC.

    This is intended for tables like `scopes` where there is an explicit
    owner column (e.g. Scope.account).

    :param stmt: The original SQLAlchemy SELECT statement.
    :param account: The account performing the operation.
    :param operation: The operation (READ, WRITE, etc.).
    :param scope_column: The column in the query that represents the scope.
    :param owner_column: The column in the query that represents the owner account.
    :return: A new SELECT statement with the RBAC+ownership condition added.
    """

    if account.external == 'root':
        return stmt

    ownership_condition = owner_column == account

    rbac_condition = _scope_access_condition(
        account=account,
        operation=operation,
        scope_column=scope_column,
    )

    return stmt.where(
        or_(ownership_condition, rbac_condition)
    )


def has_scope_permission(
    account: "InternalAccount",
    scope: "InternalScope",
    operation: "DatabaseOperationType",
    session: "Session",
) -> bool:
    """
    Return True if the account has the specified operation permission
    on the given scope, according to the RBAC tables.
    """
    exists_stmt = (
        select(1)
        .select_from(models.AccountRoleAssociation)
        .join(
            models.RolePermissionAssociation,
            models.RolePermissionAssociation.role
            == models.AccountRoleAssociation.role,
        )
        .where(
            models.AccountRoleAssociation.account == account,
            models.RolePermissionAssociation.scope == scope,
            models.RolePermissionAssociation.operation == operation,
        )
    )

    stmt = select(exists(exists_stmt))
    return bool(session.execute(stmt).scalar())
