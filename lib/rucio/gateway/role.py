from typing import TYPE_CHECKING, Any, Optional, Union

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccessDenied
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import role as core_role
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway.permission import has_permission

if TYPE_CHECKING:
    from datetime import datetime


def list_roles(issuer: str, vo: str = DEFAULT_VO) -> list[dict[str, Any]]:
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='list_roles', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to list roles.' % issuer)

        return core_role.list_roles(session=session)


def add_role(role: str, issuer: str, description: Optional[str] = None, vo: str = DEFAULT_VO) -> None:
    """
    Add a new role.

    :param role: The name of the role to add.
    :param issuer: The account issuing the command.
    :param description: An optional description of the role. An empty description is stored as NULL.
    :param vo: The VO of the issuing account.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='add_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to add role.' % issuer)

        core_role.add_role(role=role, description=description, session=session)


def set_role_description(role: str, description: Optional[str], issuer: str, vo: str = DEFAULT_VO) -> Optional[str]:
    """
    Overwrite the description of an existing role.

    :param role: The role to update.
    :param description: The new description. An empty description clears the field (stored as NULL).
    :param issuer: The account issuing the command.
    :param vo: The VO of the issuing account.
    :returns: The description as it was stored, or None if it was cleared.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='set_role_description', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to set the description of role %s.' % (issuer, role))

        return core_role.set_role_description(role=role, description=description, session=session)


def lock_role(role: str, issuer: str, vo: str = DEFAULT_VO) -> bool:
    """
    Lock a role, so that it cannot be altered by any external entity (e.g. an identity provider).

    :param role: The role to lock.
    :param issuer: The account issuing the command.
    :param vo: The VO of the issuing account.
    :returns: True if the role was locked, False if it already was locked.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='lock_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to lock role %s.' % (issuer, role))

        return core_role.set_role_locked(role=role, locked=True, session=session)


def unlock_role(role: str, issuer: str, vo: str = DEFAULT_VO) -> bool:
    """
    Unlock a role, so that it can be altered by external entities (e.g. an identity provider) again.

    :param role: The role to unlock.
    :param issuer: The account issuing the command.
    :param vo: The VO of the issuing account.
    :returns: True if the role was unlocked, False if it already was unlocked.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='unlock_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to unlock role %s.' % (issuer, role))

        return core_role.set_role_locked(role=role, locked=False, session=session)


def delete_role(role: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='delete_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to delete role.' % issuer)

        core_role.delete_role(role=role, session=session)


def list_account_roles(account: str, issuer: str, detail: bool = False, vo: str = DEFAULT_VO) -> dict[str, Union[list[dict[str, Any]], list[dict[str, str]]]]:
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='list_account_roles', kwargs={'account': account}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s cannot list roles for account %s. Additional permissions are required.' % (issuer, account))

        internal_account = InternalAccount(account, vo=vo)
        roles = core_role.list_account_roles(account=internal_account, session=session)
        result: dict[str, Union[list[dict[str, Any]], list[dict[str, str]]]] = {'roles': roles}
        if detail:
            result['permissions'] = [
                {'role': role['role'], **permission}
                for role in roles
                for permission in core_role.list_role_permissions(role=role['role'], session=session)
            ]
        return result


def add_account_role(account: str, role: str, issuer: str, expires_at: Optional[Union[str, "datetime"]] = None, vo: str = DEFAULT_VO) -> None:
    """
    Assign a role to an account.

    :param account: The account to assign the role to.
    :param role: The role to assign.
    :param issuer: The account issuing the command.
    :param expires_at: An optional date at which the assignment expires. None means that it does not expire.
    :param vo: The VO of the issuing account.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='add_account_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to add role %s to account %s.' % (issuer, role, account))

        core_role.add_account_role(account=InternalAccount(account, vo=vo), role=role, expires_at=expires_at, session=session)


def delete_account_role(account: str, role: str, issuer: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='delete_account_role', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to delete role %s from account %s.' % (issuer, role, account))
        core_role.delete_account_role(account=InternalAccount(account, vo=vo), role=role, session=session)


def set_account_role_expires_at(account: str, role: str, expires_at: Optional[Union[str, "datetime"]], issuer: str, vo: str = DEFAULT_VO) -> Optional["datetime"]:
    """
    Overwrite the expiry date of a role assigned to an account.

    :param account: The account the role is assigned to.
    :param role: The role to set the `expires_at` of.
    :param expires_at: The new date. None clears it, so that the assignment does not expire.
    :param issuer: The account issuing the command.
    :param vo: The VO of the issuing account.
    :returns: The date as it was stored, or None if it was cleared.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='set_account_role_expires_at', kwargs={}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s does not have permission to set the expires_at of role %s for account %s.' % (issuer, role, account))

        return core_role.set_account_role_expires_at(account=InternalAccount(account, vo=vo), role=role, expires_at=expires_at, session=session)


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
