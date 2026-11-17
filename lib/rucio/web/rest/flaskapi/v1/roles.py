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

import logging
from typing import TYPE_CHECKING

from flask import Flask, Response, jsonify, request

from rucio.common.constants import ISSUER_ACCOUNT_ALIAS, RBAC_DISABLED_WARNING, RBAC_WARNING_HEADER, HTTPMethod
from rucio.common.exception import (
    AccessDenied,
    AccountNotFound,
    Duplicate,
    InputValidationError,
    RoleAssignmentDisabled,
    RoleAssignmentNotFound,
    RoleInUse,
    RoleLocked,
    RoleNotFound,
    RolePermissionNotFound,
    RoleReserved,
)
from rucio.common.utils import render_json
from rucio.core.role import is_rbac_enabled
from rucio.gateway.role import (
    add_account_role,
    add_role,
    add_role_permission,
    clean_expired_account_roles,
    delete_account_role,
    delete_role,
    delete_role_permission,
    list_account_roles,
    list_role_accounts,
    list_role_permissions,
    list_roles,
    set_account_role_dates,
    update_role,
)
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, generate_http_error_flask, json_parameters, param_get, param_get_bool, response_headers

if TYPE_CHECKING:
    from flask.typing import ResponseReturnValue


class RBACStatus(ErrorHandlingMethodView):
    def get(self):
        """Tell whether RBAC is enabled on this instance, e.g. for the client to warn before managing roles."""
        return jsonify({"enabled": is_rbac_enabled()}), 200


class RoleList(ErrorHandlingMethodView):
    def get(self):
        try:
            roles = list_roles(issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)

        return jsonify(roles), 200

    def post(self, role_name: str):
        parameters = json_parameters(optional=True)
        description = param_get(parameters, 'description', default=None)
        assignable = param_get(parameters, 'assignable', default=True)
        locked = param_get(parameters, 'locked', default=False)

        try:
            add_role(
                role_name,
                issuer=request.environ['issuer'],
                description=description,
                assignable=assignable,
                locked=locked,
                vo=request.environ['vo'],
            )
        except (AccessDenied, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return jsonify({"message": f"Role '{role_name}' successfully added."}), 201

    def put(self, role_name: str):
        """Update a role. Only the parameters given in the request body are changed; an empty description clears it."""
        parameters = json_parameters()
        description = param_get(parameters, 'description', default=None)
        assignable = param_get(parameters, 'assignable', default=None)
        locked = param_get(parameters, 'locked', default=None)
        force = param_get(parameters, 'force', default=False)

        try:
            update_role(
                role=role_name,
                description=description,
                assignable=assignable,
                locked=locked,
                force=force,
                issuer=request.environ['issuer'],
                vo=request.environ['vo'],
            )
        except (AccessDenied, RoleLocked, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)

        return jsonify({"message": f"Role '{role_name}' successfully updated."}), 200

    def delete(self, role_name: str):
        parameters = json_parameters(optional=True)
        force = param_get(parameters, 'force', default=False)

        try:
            delete_role(role_name, issuer=request.environ['issuer'], force=force, vo=request.environ['vo'])
        except (AccessDenied, RoleLocked, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except RoleInUse as error:
            return generate_http_error_flask(409, error)
        return jsonify({"message": f"Role '{role_name}' successfully deleted."}), 200


class RolePermissions(ErrorHandlingMethodView):
    def get(self, role_name: str):
        try:
            permissions = list_role_permissions(role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        return jsonify(permissions), 200


class RolePermission(ErrorHandlingMethodView):
    """
    The permissions of one type of a role, e.g. `/roles/<role>/permissions/did`.

    The request body names the permission: its target and its parameters, in the shape the permissions
    are listed with, together with `force`, e.g. {"did_pattern": "data:raw*", "operations": ["read", "write"]} for a
    DID permission.

    Granting a DID permission sets exactly its `operations` on the `did_pattern`, replacing what the role had on it.
    They may be empty (`---`): within the role, the most specific pattern matching a DID decides, so such a
    permission withdraws the DIDs it matches from a less specific pattern of the role. Removing a DID permission
    takes only the `did_pattern`, and removes nothing (404) if the role has no permission on it.
    """

    def post(self, role_name: str, permission_type: str):
        parameters = json_parameters()
        force = param_get(parameters, 'force', default=False)

        try:
            add_role_permission(role=role_name, permission_type=permission_type, parameters=_permission_parameters(parameters),
                                issuer=request.environ['issuer'], force=force, vo=request.environ['vo'])
        except (AccessDenied, RoleLocked, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        return jsonify({"message": f"Permission of type '{permission_type}' successfully added to role '{role_name}'."}), 201

    def delete(self, role_name: str, permission_type: str):
        parameters = json_parameters()
        force = param_get(parameters, 'force', default=False)

        try:
            removed = delete_role_permission(role=role_name, permission_type=permission_type, parameters=_permission_parameters(parameters),
                                             issuer=request.environ['issuer'], force=force, vo=request.environ['vo'])
        except (AccessDenied, RoleLocked, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except (RoleNotFound, RolePermissionNotFound) as error:
            return generate_http_error_flask(404, error)
        return jsonify({"message": f"{removed} permission(s) of type '{permission_type}' successfully removed from role '{role_name}'.", "removed": removed}), 200


def _permission_parameters(parameters: dict) -> dict:
    """The target and the parameters of a permission given in a request body, i.e. everything but `force`; its type validates them."""
    return {name: value for name, value in parameters.items() if name != 'force'}


class RoleAccounts(ErrorHandlingMethodView):
    def get(self, role_name: str):
        try:
            accounts = list_role_accounts(role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        # rendered through the API encoder, so that the dates of an assignment are
        # reported in Rucio's date format
        return Response(render_json(accounts), content_type='application/json'), 200

    def post(self, role_name: str, account: str) -> 'ResponseReturnValue':
        parameters = json_parameters(optional=True)
        expires_at = param_get(parameters, 'expires_at', default=None)
        activates_at = param_get(parameters, 'activates_at', default=None)
        force = param_get(parameters, 'force', default=False)

        try:
            add_account_role(
                account=account,
                role=role_name,
                issuer=request.environ['issuer'],
                expires_at=expires_at,
                force=force,
                activates_at=activates_at,
                vo=request.environ['vo'],
            )
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except (AccountNotFound, RoleNotFound) as error:
            return generate_http_error_flask(404, error)
        except RoleAssignmentDisabled as error:
            return generate_http_error_flask(403, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        return jsonify({"message": f"Role '{role_name}' successfully added to account '{account}'."}), 201

    def put(self, role_name: str, account: str) -> 'ResponseReturnValue':
        """
        Overwrite the `activates_at` and/or `expires_at` of a role assigned to an account, in one go.

        Only the dates given in the request body are changed. A null `activates_at` sets it to now,
        a null `expires_at` clears it.
        """
        parameters = json_parameters()
        dates = {name: parameters[name] for name in ('activates_at', 'expires_at') if name in parameters}
        if not dates:
            return generate_http_error_flask(400, InputValidationError("At least one of 'activates_at' or 'expires_at' must be given."))

        try:
            stored = set_account_role_dates(account=account, role=role_name, issuer=request.environ['issuer'], vo=request.environ['vo'], **dates)
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleAssignmentNotFound as error:
            return generate_http_error_flask(404, error)

        if 'activates_at' in dates:
            what = "Activation and expiry dates" if 'expires_at' in dates else "Activation date"
            message = f"{what} of role '{role_name}' for account '{account}' successfully updated."
        elif stored['expires_at'] is None:
            message = f"Expiry date of role '{role_name}' for account '{account}' successfully cleared."
        else:
            message = f"Expiry date of role '{role_name}' for account '{account}' successfully updated."
        return jsonify({"message": message}), 200

    def delete(self, role_name: str, account: str) -> 'ResponseReturnValue':
        parameters = json_parameters(optional=True)
        force = param_get(parameters, 'force', default=False)

        try:
            delete_account_role(account=account, role=role_name, issuer=request.environ['issuer'], force=force, vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleAssignmentNotFound as error:
            return generate_http_error_flask(404, error)
        except RoleAssignmentDisabled as error:
            return generate_http_error_flask(403, error)
        return jsonify({"message": f"Role '{role_name}' successfully removed from account '{account}'."}), 200


class AccountRoles(ErrorHandlingMethodView):
    def get(self, account: str) -> 'ResponseReturnValue':
        detail = param_get_bool(request.args, 'detail', default=False)
        issuer = request.environ['issuer']
        if account == ISSUER_ACCOUNT_ALIAS:
            account = issuer
        try:
            roles = list_account_roles(account=account, issuer=issuer, detail=detail, vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        # rendered through the API encoder, so that the dates of an assignment are
        # reported in Rucio's date format
        return Response(render_json(**roles), content_type='application/json')


class ExpiredAccountRoles(ErrorHandlingMethodView):
    def delete(self) -> 'ResponseReturnValue':
        """
        ---
        summary: Clean expired account roles
        description: |
          Remove the expired role assignments of every account of the VO, whatever the role.
          With `dry_run`, only report what would be removed.
        tags:
          - Role
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                properties:
                  dry_run:
                    description: "Only report what would be removed."
                    type: boolean
                    default: false
        responses:
          200:
            description: "The report of the cleaning: the expired assignments which were (or would be) removed, each with its account, role and expiry date, and a summary."
            content:
              application/json:
                schema:
                  type: object
          401:
            description: "Invalid Auth Token"
          403:
            description: "Not allowed to clean the expired role assignments."
        """
        parameters = json_parameters(optional=True)
        dry_run = param_get_bool(parameters, 'dry_run', default=False)

        try:
            report = clean_expired_account_roles(issuer=request.environ['issuer'], dry_run=dry_run, vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        # rendered through the API encoder, so that the dates are reported in Rucio's date format
        return Response(render_json(**report), content_type='application/json')


def warn_if_rbac_disabled(response: Response) -> Response:
    """Log a warning and pass it on to the client whenever a role endpoint is called while RBAC is disabled: roles can still be managed, but grant nothing."""
    if not is_rbac_enabled():
        logging.warning(RBAC_DISABLED_WARNING)
        response.headers[RBAC_WARNING_HEADER] = RBAC_DISABLED_WARNING
    return response


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint("roles", __name__, url_prefix="/roles")
    role_list_view = RoleList.as_view("role_list")
    bp.add_url_rule("/", view_func=role_list_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/status", view_func=RBACStatus.as_view("rbac_status"), methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>", view_func=role_list_view, methods=[HTTPMethod.POST.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])
    role_permissions_view = RolePermissions.as_view("role_permissions")
    bp.add_url_rule("/<role_name>/permissions", view_func=role_permissions_view, methods=[HTTPMethod.GET.value])
    role_permission_view = RolePermission.as_view("role_permission")
    bp.add_url_rule("/<role_name>/permissions/<permission_type>", view_func=role_permission_view, methods=[HTTPMethod.POST.value, HTTPMethod.DELETE.value])
    role_accounts_view = RoleAccounts.as_view("role_accounts")
    bp.add_url_rule("/<role_name>/accounts", view_func=role_accounts_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>/accounts/<account>", view_func=role_accounts_view, methods=[HTTPMethod.POST.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])
    # a static path, matched before `/accounts/<account>`: a GET or PUT for an account named 'expired' still reaches the account view
    bp.add_url_rule("/accounts/expired", view_func=ExpiredAccountRoles.as_view("expired_account_roles"), methods=[HTTPMethod.DELETE.value])
    account_roles_view = AccountRoles.as_view("account_roles")
    bp.add_url_rule("/accounts/<account>", view_func=account_roles_view, methods=[HTTPMethod.GET.value])
    bp.after_request(response_headers)
    bp.after_request(warn_if_rbac_disabled)
    return bp


def make_doc():
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
