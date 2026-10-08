#!/usr/bin/env bash
# Migrate the RBAC permission table between the scope-only and the resource-agnostic models.
#
# In the resource-agnostic model every resource type a role can be granted permissions on has
# its own `role_<resource>_permission_map` table. Only scopes exist so far, so this migration
# renames the scope permission table and its constraints; the rows are kept as they are.
#
#   upgrade:   role_permission_map       -> role_scope_permission_map
#   downgrade: role_scope_permission_map -> role_permission_map
#
# Usage: ./scope_permissions_to_generic_permissions.sh upgrade|downgrade
# Override CONTAINER / SCHEMA through the environment if needed.

set -euo pipefail

CONTAINER="${CONTAINER:-dev-ruciodb-1}"
SCHEMA="${SCHEMA:-dev}"

# The suffixes of the constraints of the table, renamed together with it.
CONSTRAINT_SUFFIXES=(PK ROLE_FK ROLE_NN SCOPE_PATTERN_NN OPERATION_NN CREATED_NN UPDATED_NN)

run_sql() {
    docker exec -i "$CONTAINER" psql -U rucio -d rucio -v ON_ERROR_STOP=1
}

# Rename the operation enum: a native PostgreSQL type, or a check constraint when non-native.
# The native type is not necessarily in ${SCHEMA} (Rucio creates it unqualified, so it usually
# lands in 'public'), hence it is looked up through the type of the `operation` column itself.
rename_operation_enum() {
    local table="$1" old="$2" new="$3"
    cat <<EOF
DO \$\$
DECLARE
    type_schema TEXT;
BEGIN
    SELECT n.nspname INTO type_schema
    FROM pg_attribute a
    JOIN pg_type t ON t.oid = a.atttypid
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE a.attrelid = '${SCHEMA}.${table}'::regclass AND a.attname = 'operation' AND t.typname = '${old}';
    IF type_schema IS NOT NULL THEN
        EXECUTE format('ALTER TYPE %I.%I RENAME TO %I', type_schema, '${old}', '${new}');
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
               WHERE n.nspname = '${SCHEMA}' AND c.conname = '${old}') THEN
        ALTER TABLE ${SCHEMA}.${table} RENAME CONSTRAINT "${old}" TO "${new}";
    END IF;
END
\$\$;
EOF
}

# Print the SQL renaming the table `$1` to `$2`, with its constraints and its operation enum.
rename_permission_table() {
    local old="$1" new="$2"
    local old_prefix="${old^^}" new_prefix="${new^^}"

    echo "ALTER TABLE ${SCHEMA}.${old} RENAME TO ${new};"
    for suffix in "${CONSTRAINT_SUFFIXES[@]}"; do
        echo "ALTER TABLE ${SCHEMA}.${new} RENAME CONSTRAINT \"${old_prefix}_${suffix}\" TO \"${new_prefix}_${suffix}\";"
    done
    rename_operation_enum "${new}" "${old_prefix}_OPERATION_CHK" "${new_prefix}_OPERATION_CHK"
}

upgrade() {
    # Upgrade from Scope Permissions to Generic Permissions
    run_sql <<EOF
BEGIN;
$(rename_permission_table role_permission_map role_scope_permission_map)
COMMIT;
EOF
}

downgrade() {
    # Downgrade from Generic Permissions to Scope Permissions
    run_sql <<EOF
BEGIN;
$(rename_permission_table role_scope_permission_map role_permission_map)
COMMIT;
EOF
}

case "${1:-}" in
    upgrade) upgrade ;;
    downgrade) downgrade ;;
    *)
        echo "Usage: $0 upgrade|downgrade" >&2
        exit 1
        ;;
esac
