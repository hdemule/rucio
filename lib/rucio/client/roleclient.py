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
            `assignment_disabled` and `internal_role_flag`. `description` is None for roles
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
            assignment_disabled: bool = False,
            internal_role_flag: bool = False) -> None:
        """
        Add a new role.

        Parameters
        ----------
        role :
            The name of the role to add.
        description :
            An optional description of the role. An empty description is stored as NULL.
        assignment_disabled :
            Whether an identity provider is barred from assigning this role to, or taking it away from, an account.
        internal_role_flag :
            Whether the role is flagged as internal.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description, assignment_disabled=assignment_disabled, internal_role_flag=internal_role_flag)
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
            assignment_disabled: Optional[bool] = None,
            internal_role_flag: Optional[bool] = None) -> None:
        """
        Update an existing role. Only the parameters explicitly given are changed.

        Parameters
        ----------
        role :
            The role to update.
        description :
            The new description, or None to leave it untouched. An empty string clears it.
        assignment_disabled :
            The new assignment_disabled state, or None to leave it untouched.
        internal_role_flag :
            The new internal_role_flag state, or None to leave it untouched.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description, assignment_disabled=assignment_disabled, internal_role_flag=internal_role_flag)
        response = self._send_request(url, method=HTTPMethod.PUT, data=data)

        if response.status_code == codes.ok:
            return

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def delete_role(self, role: str) -> None:
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        response = self._send_request(url, method=HTTPMethod.DELETE)

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

    def add_role_permission(self, role: str, operation: str, scope_pattern: str) -> None:
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
        """
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope_pattern)}"
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.POST)
        if response.status_code != codes.created:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)

    def delete_role_permission(self, role: str, operation: str, scope_pattern: str) -> None:
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope_pattern)}"
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.DELETE)
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)
