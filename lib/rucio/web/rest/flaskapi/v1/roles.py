from flask import Flask, jsonify, request

from rucio.common.constants import HTTPMethod
from rucio.common.exception import AccessDenied, Duplicate, InputValidationError, RoleInUse, RoleNotFound, RolePermissionNotFound, ScopeNotFound
from rucio.gateway.role import add_role, add_role_permission, delete_role, delete_role_permission, list_role_permissions, list_roles, lock_role, set_role_description, unlock_role
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

        try:
            add_role(role_name, issuer=request.environ['issuer'], description=description, vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return jsonify({"message": f"Role '{role_name}' successfully added."}), 201

    def put(self, role_name: str):
        """Overwrite the description of a role. An empty description clears it."""
        parameters = json_parameters()
        description = param_get(parameters, 'description')

        try:
            stored = set_role_description(role=role_name, description=description, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except InputValidationError as error:
            return generate_http_error_flask(400, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)

        if stored is None:
            return jsonify({"message": f"Description of role '{role_name}' successfully cleared."}), 200
        return jsonify({"message": f"Description of role '{role_name}' successfully updated."}), 200

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


class RoleLock(ErrorHandlingMethodView):
    def post(self, role_name: str):
        """Lock a role, so that it cannot be altered by any external entity (e.g. an identity provider)."""
        try:
            locked = lock_role(role=role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        if not locked:
            return jsonify({"message": f"Role '{role_name}' was already locked.", "warning": f"Role '{role_name}' is already locked."}), 200
        return jsonify({"message": f"Role '{role_name}' successfully locked."}), 200


class RoleUnlock(ErrorHandlingMethodView):
    def post(self, role_name: str):
        """Unlock a role, so that it can be altered by external entities (e.g. an identity provider) again."""
        try:
            unlocked = unlock_role(role=role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        if not unlocked:
            return jsonify({"message": f"Role '{role_name}' was already unlocked.", "warning": f"Role '{role_name}' is already unlocked."}), 200
        return jsonify({"message": f"Role '{role_name}' successfully unlocked."}), 200


class RolePermissions(ErrorHandlingMethodView):
    def get(self, role_name: str):
        try:
            permissions = list_role_permissions(role_name, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        return jsonify(permissions), 200

    def post(self, role_name: str, operation: str, scope: str):
        try:
            add_role_permission(role=role_name, operation=operation, scope=scope, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except ScopeNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        return jsonify({"message": f"Permission '{operation}' on scope '{scope}' successfully added to role '{role_name}'."}), 201

    def delete(self, role_name: str, operation: str, scope: str):
        try:
            delete_role_permission(role=role_name, operation=operation, scope=scope, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except AccessDenied as error:
            return generate_http_error_flask(403, error)
        except RoleNotFound as error:
            return generate_http_error_flask(404, error)
        except RolePermissionNotFound as error:
            return generate_http_error_flask(404, error)
        return jsonify({"message": f"Permission '{operation}' on scope '{scope}' successfully removed from role '{role_name}'."}), 200


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint("roles", __name__, url_prefix="/roles")
    role_list_view = RoleList.as_view("role_list")
    bp.add_url_rule("/", view_func=role_list_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>", view_func=role_list_view, methods=[HTTPMethod.POST.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])
    bp.add_url_rule("/<role_name>/lock", view_func=RoleLock.as_view("role_lock"), methods=[HTTPMethod.POST.value])
    bp.add_url_rule("/<role_name>/unlock", view_func=RoleUnlock.as_view("role_unlock"), methods=[HTTPMethod.POST.value])
    role_permissions_view = RolePermissions.as_view("role_permissions")
    bp.add_url_rule("/<role_name>/permissions", view_func=role_permissions_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>/permissions/<operation>/<scope>", view_func=role_permissions_view, methods=[HTTPMethod.POST.value, HTTPMethod.DELETE.value])
    bp.after_request(response_headers)
    return bp


def make_doc():
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
