from flask import Flask, Response, jsonify, request

from rucio.common.constants import HTTPMethod
from rucio.common.exception import AccessDenied, Duplicate, InputValidationError, RoleInUse, RoleNotFound, RolePermissionNotFound
from rucio.common.utils import render_json
from rucio.gateway.role import add_role, add_role_permission, delete_role, delete_role_permission, list_role_accounts, list_role_permissions, list_roles, update_role
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, generate_http_error_flask, json_parameters, param_get, response_headers


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
        assignment_disabled = param_get(parameters, 'assignment_disabled', default=False)
        internal_role_flag = param_get(parameters, 'internal_role_flag', default=False)

        try:
            add_role(
                role_name,
                issuer=request.environ['issuer'],
                description=description,
                assignment_disabled=assignment_disabled,
                internal_role_flag=internal_role_flag,
                vo=request.environ['vo'],
            )
        except AccessDenied as error:
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
        assignment_disabled = param_get(parameters, 'assignment_disabled', default=None)
        internal_role_flag = param_get(parameters, 'internal_role_flag', default=None)

        try:
            update_role(
                role=role_name,
                description=description,
                assignment_disabled=assignment_disabled,
                internal_role_flag=internal_role_flag,
                issuer=request.environ['issuer'],
                vo=request.environ['vo'],
            )
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)

        return jsonify({"message": f"Role '{role_name}' successfully updated."}), 200

    def delete(self, role_name: str):
        try:
            delete_role(role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
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
        try:
            add_role_permission(role=role_name, operation=operation, scope_pattern=scope_pattern, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        return jsonify({"message": f"Permission '{operation}' on scope pattern '{scope_pattern}' successfully added to role '{role_name}'."}), 201

    def delete(self, role_name: str, operation: str, scope_pattern: str):
        try:
            delete_role_permission(role=role_name, operation=operation, scope_pattern=scope_pattern, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
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
    bp.after_request(response_headers)
    return bp


def make_doc():
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
