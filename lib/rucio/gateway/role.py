from typing import Union

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccessDenied
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import role as core_role
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway.permission import has_permission


def list_roles(issuer: str, vo: str = DEFAULT_VO) -> list[str]:
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='list_roles', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to list roles.' % issuer)

        return core_role.list_roles(session=session)


def add_role(role: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='add_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to add role.' % issuer)

        core_role.add_role(role=role, session=session)


def delete_role(role: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='delete_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to delete role.' % issuer)

        core_role.delete_role(role=role, session=session)


def list_account_roles(account: str, issuer: str, detail: bool = False, vo: str = DEFAULT_VO) -> dict[str, Union[list[str], list[dict[str, str]]]]:
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='list_account_roles', kwargs={'account': account}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s cannot list roles for account %s. Either the requested account does not exist or additional permissions are required.' % (issuer, account))

        internal_account = InternalAccount(account, vo=vo)
        roles = core_role.list_account_roles(account=internal_account, session=session)
        result: dict[str, Union[list[str], list[dict[str, str]]]] = {'roles': roles}
        if detail:
            result['permissions'] = [
                {'role': role, **permission}
                for role in roles
                for permission in core_role.list_role_permissions(role=role, session=session)
            ]
        return result


def add_account_role(account: str, role: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='add_account_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to add role %s to account %s.' % (issuer, role, account))

        core_role.add_account_role(account=InternalAccount(account, vo=vo), role=role, session=session)


def delete_account_role(account: str, role: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='delete_account_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to delete role %s from account %s.' % (issuer, role, account))
        core_role.delete_account_role(account=InternalAccount(account, vo=vo), role=role, session=session)


def list_role_permissions(role: str, issuer: str, vo: str = DEFAULT_VO) -> list[dict[str, str]]:
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='list_role_permissions', kwargs={'role': role}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s cannot list permissions for role %s. Either the role does not exist or additional permissions are required.' % (issuer, role))
        return core_role.list_role_permissions(role=role, session=session)


def add_role_permission(role: str, operation: str, scope: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='add_role_permission', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to add role permission for role %s.' % (issuer, role))

        core_role.add_role_permission(
            role=role,
            operation=DatabaseOperationType(operation),
            scope=InternalScope(scope, vo=vo),
            session=session,
        )


def delete_role_permission(role: str, operation: str, scope: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='delete_role_permission', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to delete role permission for role %s.' % (issuer, role))

        core_role.delete_role_permission(
            role=role,
            operation=DatabaseOperationType(operation),
            scope=InternalScope(scope, vo=vo),
            session=session,
        )
