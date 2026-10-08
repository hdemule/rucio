from typing import TYPE_CHECKING

from flask import Flask, Response, jsonify, request

from rucio.common.constants import ISSUER_ACCOUNT_ALIAS, HTTPMethod
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
from rucio.gateway.role import (
    add_account_role,
    add_role,
    add_role_permission,
    delete_account_role,
    delete_role,
    delete_role_permission,
    list_account_roles,
    list_role_accounts,
    list_role_permissions,
    list_roles,
    set_account_role_expires_at,
    sync_account_roles,
    update_role,
)
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, generate_http_error_flask, json_parameters, param_get, param_get_bool, response_headers

if TYPE_CHECKING:
    from flask.typing import ResponseReturnValue


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

    def post(self, role_name: str, operation: str, scope_pattern: str):
        parameters = json_parameters(optional=True)
        force = param_get(parameters, 'force', default=False)

        try:
            add_role_permission(role=role_name, operation=operation, scope_pattern=scope_pattern, issuer=request.environ['issuer'], force=force, vo=request.environ['vo'])
        except (AccessDenied, RoleLocked, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        return jsonify({"message": f"Permission '{operation}' on scope pattern '{scope_pattern}' successfully added to role '{role_name}'."}), 201

    def delete(self, role_name: str, operation: str, scope_pattern: str):
        parameters = json_parameters(optional=True)
        force = param_get(parameters, 'force', default=False)

        try:
            delete_role_permission(role=role_name, operation=operation, scope_pattern=scope_pattern, issuer=request.environ['issuer'], force=force, vo=request.environ['vo'])
        except (AccessDenied, RoleLocked, RoleReserved) as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except RolePermissionNotFound as error:
            return generate_http_error_flask(404, error)
        return jsonify({"message": f"Permission '{operation}' on scope pattern '{scope_pattern}' successfully removed from role '{role_name}'."}), 200


class RoleAccounts(ErrorHandlingMethodView):
    def get(self, role_name: str):
        try:
            accounts = list_role_accounts(role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        # rendered through the API encoder, so that the expiry date of an assignment is
        # reported in Rucio's date format
        return Response(render_json(accounts), content_type='application/json'), 200

    def post(self, role_name: str, account: str) -> 'ResponseReturnValue':
        parameters = json_parameters(optional=True)
        expires_at = param_get(parameters, 'expires_at', default=None)
        force = param_get(parameters, 'force', default=False)

        try:
            add_account_role(account=account, role=role_name, issuer=request.environ['issuer'], expires_at=expires_at, force=force, vo=request.environ['vo'])
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
        """Overwrite the `expires_at` of a role assigned to an account. A null value clears it."""
        parameters = json_parameters()
        expires_at = param_get(parameters, 'expires_at')

        try:
            stored = set_account_role_expires_at(account=account, role=role_name, expires_at=expires_at, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleAssignmentNotFound as error:
            return generate_http_error_flask(404, error)

        if stored is None:
            return jsonify({"message": f"Expiry date of role '{role_name}' for account '{account}' successfully cleared."}), 200
        return jsonify({"message": f"Expiry date of role '{role_name}' for account '{account}' successfully updated."}), 200

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
        # rendered through the API encoder, so that the expiry date of an assignment is
        # reported in Rucio's date format
        return Response(render_json(**roles), content_type='application/json')

    def put(self, account: str) -> 'ResponseReturnValue':
        """
        ---
        summary: Synchronise account roles
        description: |
          Synchronise the role assignments of an account with the roles supplied by an identity provider:
          expired assignments and roles which are not supplied are removed, supplied roles are assigned
          and their expiry dates updated. Roles which are not assignable are left untouched.
          With `dry_run`, only report what would be done.
        tags:
          - Role
        parameters:
        - name: account
          in: path
          description: "The account identifier."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - roles
                properties:
                  roles:
                    description: "The roles supplied by the IdP: a list of role names and/or of {role, expires_at} objects, or an object mapping role name to expiry date."
                    oneOf:
                    - type: array
                    - type: object
                  dry_run:
                    description: "Only report what the synchronisation would do."
                    type: boolean
                    default: false
        responses:
          200:
            description: "The report of the synchronisation: what was (or would be) removed, added, updated, left unchanged, held back or ignored, the messages describing each step, and a summary."
            content:
              application/json:
                schema:
                  type: object
          400:
            description: "The roles are not in an accepted form."
          401:
            description: "Invalid Auth Token"
          403:
            description: "Not allowed to synchronise the roles of this account."
          404:
            description: "No account found."
        """
        parameters = json_parameters()
        roles = param_get(parameters, 'roles')
        dry_run = param_get_bool(parameters, 'dry_run', default=False)

        try:
            report = sync_account_roles(account=account, roles=roles, issuer=request.environ['issuer'], dry_run=dry_run, vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)
        # rendered through the API encoder, so that the dates are reported in Rucio's date format
        return Response(render_json(**report), content_type='application/json')


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint("roles", __name__, url_prefix="/roles")
    role_list_view = RoleList.as_view("role_list")
    bp.add_url_rule("/", view_func=role_list_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>", view_func=role_list_view, methods=[HTTPMethod.POST.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])
    role_permissions_view = RolePermissions.as_view("role_permissions")
    bp.add_url_rule("/<role_name>/permissions", view_func=role_permissions_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>/permissions/<operation>/<scope_pattern>", view_func=role_permissions_view, methods=[HTTPMethod.POST.value, HTTPMethod.DELETE.value])
    role_accounts_view = RoleAccounts.as_view("role_accounts")
    bp.add_url_rule("/<role_name>/accounts", view_func=role_accounts_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>/accounts/<account>", view_func=role_accounts_view, methods=[HTTPMethod.POST.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])
    account_roles_view = AccountRoles.as_view("account_roles")
    bp.add_url_rule("/accounts/<account>", view_func=account_roles_view, methods=[HTTPMethod.GET.value, HTTPMethod.PUT.value])
    bp.after_request(response_headers)
    return bp


def make_doc():
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
