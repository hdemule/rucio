from json import loads
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url


class RoleClient(BaseClient):
    ROLES_BASEURL = "roles"

    def list_roles(self) -> list[str]:
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

    def add_role(self, role: str) -> None:
        url = build_url(choice(self.list_hosts), path=f"{self.ROLES_BASEURL}/{quote_plus(role)}")
        response = self._send_request(url, method=HTTPMethod.POST)

        if response.status_code == codes.created:
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
