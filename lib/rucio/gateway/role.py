from rucio.common.constants import DEFAULT_VO
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import role as core_role
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session


def list_roles() -> list[str]:
    with db_session(DatabaseOperationType.READ) as session:
        return core_role.list_roles(session=session)


def add_role(role: str) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        core_role.add_role(role=role, session=session)


def delete_role(role: str) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        core_role.delete_role(role=role, session=session)


def list_account_roles(account: str, detail: bool = False, vo: str = DEFAULT_VO) -> dict[str, list]:
    with db_session(DatabaseOperationType.READ) as session:
        internal_account = InternalAccount(account, vo=vo)
        roles = core_role.list_account_roles(account=internal_account, session=session)
        result = {'roles': roles}
        if detail:
            result['permissions'] = [
                {'role': role, **permission}
                for role in roles
                for permission in core_role.list_role_permissions(role=role, session=session)
            ]
        return result


def add_account_role(account: str, role: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        core_role.add_account_role(account=InternalAccount(account, vo=vo), role=role, session=session)


def delete_account_role(account: str, role: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        core_role.delete_account_role(account=InternalAccount(account, vo=vo), role=role, session=session)


def list_role_permissions(role: str) -> list[dict[str, str]]:
    with db_session(DatabaseOperationType.READ) as session:
        return core_role.list_role_permissions(role=role, session=session)


def add_role_permission(role: str, operation: str, scope: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        core_role.add_role_permission(
            role=role,
            operation=DatabaseOperationType(operation),
            scope=InternalScope(scope, vo=vo),
            session=session,
        )


def delete_role_permission(role: str, operation: str, scope: str, vo: str = DEFAULT_VO) -> None:
    with db_session(DatabaseOperationType.WRITE) as session:
        core_role.delete_role_permission(
            role=role,
            operation=DatabaseOperationType(operation),
            scope=InternalScope(scope, vo=vo),
            session=session,
        )
