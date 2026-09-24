from json import loads
from typing import Any, Optional
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url, render_json


class RoleClient(BaseClient):
    ROLES_BASEURL = "roles"

    def list_roles(self) -> list[dict[str, Any]]:
        """
        List all roles.

        Returns
        -------
            A list of dictionaries, one per role, with the keys `role`, `description`,
            `assignable` and `protected`. `description` is None for roles
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
            protected: bool = False) -> None:
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
        protected :
            Whether the role is protected, which prevents a policy package from altering or deleting it.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description, assignable=assignable, protected=protected)
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
            protected: Optional[bool] = None,
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
        protected :
            The new protected state, or None to leave it untouched.
        force :
            Change the description or the assignable state even if the role is protected.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description, assignable=assignable, protected=protected, force=force)
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
            instead of refusing to delete a role which is still in use, and delete it even if it is protected.
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
            Grant the permission even if the role is protected.
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
            Remove the permission even if the role is protected.
        """
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope_pattern)}"
        data = render_json(force=force) if force else None
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.DELETE, data=data)
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)
