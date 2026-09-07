from flask import Flask, jsonify, request

from rucio.common.constants import HTTPMethod
from rucio.gateway.role import add_role, add_role_permission, delete_role, delete_role_permission, list_role_permissions, list_roles
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, response_headers


class RoleList(ErrorHandlingMethodView):
    def get(self):
        return jsonify(list_roles())

    def post(self, role_name: str):
        add_role(role_name)
        return jsonify({"message": f"Role '{role_name}' added."}), 201

    def delete(self, role_name: str):
        delete_role(role_name)
        return '', 200


class RolePermissions(ErrorHandlingMethodView):
    def get(self, role_name: str):
        return jsonify(list_role_permissions(role_name))

    def post(self, role_name: str, operation: str, scope: str):
        add_role_permission(role=role_name, operation=operation, scope=scope, vo=request.environ['vo'])
        return '', 201

    def delete(self, role_name: str, operation: str, scope: str):
        delete_role_permission(role=role_name, operation=operation, scope=scope, vo=request.environ['vo'])
        return '', 200


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint("roles", __name__, url_prefix="/roles")
    role_list_view = RoleList.as_view("role_list")
    bp.add_url_rule("/", view_func=role_list_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>", view_func=role_list_view, methods=[HTTPMethod.POST.value, HTTPMethod.DELETE.value])
    role_permissions_view = RolePermissions.as_view("role_permissions")
    bp.add_url_rule("/<role_name>/permissions", view_func=role_permissions_view, methods=[HTTPMethod.GET.value])
    bp.add_url_rule("/<role_name>/permissions/<operation>/<scope>", view_func=role_permissions_view, methods=[HTTPMethod.POST.value, HTTPMethod.DELETE.value])
    bp.after_request(response_headers)
    return bp


def make_doc():
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
