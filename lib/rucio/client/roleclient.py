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
            A list of dictionaries, one per role, with the keys `role`, `description` and `locked`.
            `description` is None for roles without a description.
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

    def add_role(self, role: str, description: Optional[str] = None) -> None:
        """
        Add a new role.

        Parameters
        ----------
        role :
            The name of the role to add.
        description :
            An optional description of the role. An empty description is stored as NULL.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        data = render_json(description=description) if description is not None else None
        response = self._send_request(url, method=HTTPMethod.POST, data=data)

        if response.status_code == codes.created:
            return

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def set_role_description(self, role: str, description: Optional[str]) -> None:
        """
        Overwrite the description of an existing role.

        Parameters
        ----------
        role :
            The role to update.
        description :
            The new description. An empty string (or None) clears the description.
        """
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        response = self._send_request(url, method=HTTPMethod.PUT, data=render_json(description=description))

        if response.status_code == codes.ok:
            return

        exc_cls, exc_msg = self._get_exception(
            headers=response.headers,
            status_code=response.status_code,
            data=response.content,
        )
        raise exc_cls(exc_msg)

    def lock_role(self, role: str) -> None:
        """
        Lock a role, so that it cannot be altered by any external entity (e.g. an identity provider).

        Parameters
        ----------
        role :
            The role to lock.
        """
        self._set_role_locked(role, locked=True)

    def unlock_role(self, role: str) -> None:
        """
        Unlock a role, so that it can be altered by external entities (e.g. an identity provider) again.

        Parameters
        ----------
        role :
            The role to unlock.
        """
        self._set_role_locked(role, locked=False)

    def _set_role_locked(self, role: str, locked: bool) -> None:
        """Lock or unlock a role, warning if it already was in the requested state."""
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/{'lock' if locked else 'unlock'}"
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.POST)
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)
        self._warn_on_response(response)

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

    def add_role_permission(self, role: str, operation: str, scope: str) -> None:
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope)}"
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.POST)
        if response.status_code != codes.created:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)

    def delete_role_permission(self, role: str, operation: str, scope: str) -> None:
        path = f"{self.ROLES_BASEURL}/{quote_plus(role)}/permissions/{quote_plus(operation)}/{quote_plus(scope)}"
        response = self._send_request(build_url(choice(self.list_hosts), path=path), method=HTTPMethod.DELETE)
        if response.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(headers=response.headers, status_code=response.status_code, data=response.content)
            raise exc_cls(exc_msg)
