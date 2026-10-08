from json import loads
from typing import TYPE_CHECKING, Any, Optional, Union
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import ISSUER_ACCOUNT_ALIAS, HTTPMethod
from rucio.common.utils import build_url, render_json

if TYPE_CHECKING:
    from datetime import datetime


class RoleClient(BaseClient):
    ROLES_BASEURL = "roles"

    def list_roles(self) -> list[dict[str, Any]]:
        """
        List all roles.

        Returns
        -------
            A list of dictionaries, one per role, with the keys `role`, `description`,
            `assignable`, `locked` and `reserved`. `description` is None for roles
            without a description.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/")
        response = self._send_request(url, method=HTTPMethod.GET)

        if response.status_code == codes.ok:
            return loads(response.text)

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def add_role(
            self,
            role: str,
            description: Optional[str] = None,
            assignable: bool = True,
            locked: bool = False) -> None:
        """
        Add a new role.

        Parameters
        ----------
        role :
            The name of the role to add.
        description :
            An optional description of the role. An empty description is stored as NULL.
        assignable :
            Whether an identity provider may assign this role to, or take it away from, an account.
        locked :
            Whether the role is locked, which prevents a policy package from altering or deleting it.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description, assignable=assignable, locked=locked)
        response = self._send_request(url, method=HTTPMethod.POST, data=data)

        if response.status_code == codes.created:
            return

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def update_role(
            self,
            role: str,
            description: Optional[str] = None,
            assignable: Optional[bool] = None,
            locked: Optional[bool] = None,
            force: bool = False) -> None:
        """
        Update an existing role. Only the parameters explicitly given are changed.

        Parameters
        ----------
        role :
            The role to update.
        description :
            The new description, or None to leave it untouched. An empty string clears it.
        assignable :
            The new assignable state, or None to leave it untouched.
        locked :
            The new locked state, or None to leave it untouched.
        force :
            Change the description or the assignable state even if the role is locked.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description, assignable=assignable, locked=locked, force=force)
        response = self._send_request(url, method=HTTPMethod.PUT, data=data)

        if response.status_code == codes.ok:
            return

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def delete_role(self, role: str, force: bool = False) -> None:
        """
        Delete a role.

        Parameters
        ----------
        role :
            The role to delete.
        force :
            Also remove the role from every account it is assigned to and drop its permissions,
            instead of refusing to delete a role which is still in use, and delete it even if it is locked.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(force=force) if force else None
        response = self._send_request(url, method=HTTPMethod.DELETE, data=data)

        if response.status_code == codes.ok:
            return

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def list_role_permissions(self, role: str) -> list[dict[str, str]]:
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions")
        response = self._send_request(url, method=HTTPMethod.GET)
        if response.status_code == codes.ok:
            return response.json()
        exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
        raise exc_cls(exc_msg)

    def list_role_accounts(self, role: str) -> list[dict[str, Any]]:
        """
        List the accounts a role is assigned to.

        Parameters
        ----------
        role :
            The role to list the accounts of.

        Returns
        -------
        list[dict[str, Any]]
            One entry per account, with its `account` name and the `expires_at` of the assignment (None if it does not expire).
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}/accounts")
        response = self._send_request(url, method=HTTPMethod.GET)
        if response.status_code == codes.ok:
            return response.json()
        exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
        raise exc_cls(exc_msg)

    def list_account_roles(self, account: Optional[str] = None, use_issuer_account: bool = False, detail: bool = False) -> dict[str, Any]:
        # the server replaces the alias with the issuer's account
        account = ISSUER_ACCOUNT_ALIAS if use_issuer_account else account
        if not account:
            raise ValueError('Either an account or use_issuer_account must be given.')
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/accounts/{quote_plus(account)}")
        response = self._send_request(url, method=HTTPMethod.GET, params={'detail': str(detail).lower()})
        if response.status_code == codes.ok:
            return response.json()
        exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
        raise exc_cls(exc_msg)

    def add_account_role(self, account: str, role: str, expires_at: Optional[Union[str, "datetime"]] = None, force: bool = False) -> None:
        """
        Assign a role to an account.

        Parameters
        ----------
        account :
            The account to assign the role to.
        role :
            The role to assign.
        expires_at :
            An optional date at which the assignment expires. None means that it does not expire.
        force :
            Assign the role even if it is not assignable.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}/accounts/{quote_plus(account)}")
        data = render_json(expires_at=expires_at, force=force) if expires_at is not None or force else None
        response = self._send_request(url, method=HTTPMethod.POST, data=data)
        if response.status_code != codes.created:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)

    def set_account_role_expires_at(self, account: str, role: str, expires_at: Optional[Union[str, "datetime"]]) -> None:
        """
        Overwrite the expiry date of a role assigned to an account.

        Parameters
        ----------
        account :
            The account the role is assigned to.
        role :
            The role to set the `expires_at` of.
        expires_at :
            The new date. None clears it, so that the assignment does not expire.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}/accounts/{quote_plus(account)}")
        response = self._send_request(url, method=HTTPMethod.PUT, data=render_json(expires_at=expires_at))
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)

    def delete_account_role(self, account: str, role: str, force: bool = False) -> None:
        """
        Remove a role from an account.

        Parameters
        ----------
        account :
            The account to remove the role from.
        role :
            The role to remove.
        force :
            Remove the role even if it is not assignable.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}/accounts/{quote_plus(account)}")
        data = render_json(force=force) if force else None
        response = self._send_request(url, method=HTTPMethod.DELETE, data=data)
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)

    def sync_account_roles(self, account: str, roles: Any, dry_run: bool = False) -> dict[str, Any]:
        """
        Synchronize the role assignments of an account with the roles supplied by an identity provider.

        Expired assignments and roles which are not supplied are removed, supplied roles are assigned
        and their expiry dates updated. Roles which are not assignable are left untouched.

        Parameters
        ----------
        account :
            The account whose role assignments are synchronised.
        roles :
            The roles supplied by the IdP: a list of role names and/or of {'role': ..., 'expires_at': ...}
            dictionaries, or a dictionary mapping role name to expiry date.
        dry_run :
            Only report what the synchronisation would do, without changing anything.

        Returns
        -------
            The report of the synchronisation: the roles supplied and currently held, what was (or would be)
            removed, added, updated, left unchanged, held back or ignored, the messages describing each step,
            and a one-line summary.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/accounts/{quote_plus(account)}")
        response = self._send_request(url, method=HTTPMethod.PUT, data=render_json(roles=roles, dry_run=dry_run))
        if response.status_code == codes.ok:
            return response.json()
        exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
        raise exc_cls(exc_msg)

    def add_role_permission(self, role: str, operation: str, scope_pattern: str, force: bool = False) -> None:
        """
        Grant a role a permission on a scope pattern.

        Parameters
        ----------
        role :
            The role to grant the permission to.
        operation :
            The operation to grant.
        scope_pattern :
            The scope pattern to grant the permission on; only a trailing '*' wildcard is accepted (e.g. '*' or 'data*').
        force :
            Grant the permission even if the role is locked.
        """
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope_pattern)}"
        data = render_json(force=force) if force else None
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.POST, data=data)
        if response.status_code != codes.created:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)

    def delete_role_permission(self, role: str, operation: str, scope_pattern: str, force: bool = False) -> None:
        """
        Remove a permission from a role.

        Parameters
        ----------
        role :
            The role to remove the permission from.
        operation :
            The operation to remove.
        scope_pattern :
            The scope pattern to remove the permission from.
        force :
            Remove the permission even if the role is locked.
        """
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope_pattern)}"
        data = render_json(force=force) if force else None
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.DELETE, data=data)
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)
