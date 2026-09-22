"""Bring the RBAC tables of a running database in line with the current models.

The `roles` and `role_permission_map` tables created by earlier RBAC work are not
in line with `rucio.db.sqla.models` any more:

  * `roles.locked` has been replaced with two flags, `assignment_disabled` and
    `internal_role_flag`;
  * `role_permission_map.scope` (a foreign key into `scopes`) has been replaced
    with `scope_pattern`, a plain string that is no longer tied to an existing
    scope (it can hold patterns such as `archive*`).

This script applies both changes directly on the configured database, without
going through alembic. It is idempotent: a step that has already been applied is
skipped, so it can safely be run again.

Note that the values currently stored in `roles.locked` and
`role_permission_map.scope` are dropped together with their columns; `locked` is
not converted into the new flags, and `scope` is not converted into a
`scope_pattern`. Use `--dry-run` to see the statements without applying them.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlalchemy as sa  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.operations import Operations  # noqa: E402

from rucio.db.sqla.session import DEFAULT_SCHEMA_NAME, get_engine  # noqa: E402

EQUIVALENT_PSQL_COMMANDS = """
The same modifications, as psql commands to run against a live PostgreSQL (DBOD)
instance from an admin account. They are what `--dry-run` prints for PostgreSQL,
in the order they have to be applied.

Set the environment first (RUCIO_DB is the database, DBOD_SCHEMA the schema the
Rucio tables live in, i.e. the `schema` option of the `[database]` section):

    export DBOD_HOST=dbod-____.cern.ch
    export DBOD_PORT=____
    export DBOD_ADMIN_PASSWORD=____
    export RUCIO_DB=rucio
    export DBOD_SCHEMA=____

1. Check what the `locked` flags and `scope` values currently hold, since they are discarded:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "SELECT locked, count(*) FROM $DBOD_SCHEMA.roles GROUP BY locked;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "SELECT role, scope FROM $DBOD_SCHEMA.role_permission_map;"

2. Replace `roles.locked` with `assignment_disabled` and `internal_role_flag`. Both are
   added as nullable first, backfilled with false, and only then made NOT NULL, so that
   the table can be migrated while it holds roles. The old check constraint has to go
   before the column it refers to:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ADD COLUMN assignment_disabled BOOLEAN;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "UPDATE $DBOD_SCHEMA.roles SET assignment_disabled = false WHERE assignment_disabled IS NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ALTER COLUMN assignment_disabled SET NOT NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ADD CONSTRAINT \\"ROLES_ASSIGNMENT_DISABLED_NN\\" CHECK (assignment_disabled IS NOT NULL);"

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ADD COLUMN internal_role_flag BOOLEAN;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "UPDATE $DBOD_SCHEMA.roles SET internal_role_flag = false WHERE internal_role_flag IS NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ALTER COLUMN internal_role_flag SET NOT NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ADD CONSTRAINT \\"ROLES_INTERNAL_ROLE_FLAG_NN\\" CHECK (internal_role_flag IS NOT NULL);"

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles DROP CONSTRAINT \\"ROLES_LOCKED_NN\\";"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles DROP COLUMN locked;"

3. Replace `role_permission_map.scope` with `scope_pattern`. The primary key and the
   foreign key into `scopes` are dropped together with the column, and the NOT NULL
   check constraint has to go before the column it refers to:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map ADD COLUMN scope_pattern VARCHAR(25);"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "UPDATE $DBOD_SCHEMA.role_permission_map SET scope_pattern = scope WHERE scope_pattern IS NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map ALTER COLUMN scope_pattern SET NOT NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map ADD CONSTRAINT \\"ROLE_PERMISSION_MAP_SCOPE_PATTERN_NN\\" CHECK (scope_pattern IS NOT NULL);"

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map DROP CONSTRAINT \\"ROLE_PERMISSION_MAP_PK\\";"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map ADD CONSTRAINT \\"ROLE_PERMISSION_MAP_PK\\" PRIMARY KEY (role, scope_pattern, operation);"

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map DROP CONSTRAINT \\"ROLE_PERMISSION_MAP_SCOPE_FK\\";"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map DROP CONSTRAINT \\"ROLE_PERMISSION_MAP_SCOPE_NN\\";"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map DROP COLUMN scope;"

4. Verify that both tables now match the models:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "\\d $DBOD_SCHEMA.roles"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "\\d $DBOD_SCHEMA.role_permission_map"

Steps 2. and 3. are applied in a single transaction when this script is run
without `--dry-run`, so a failure halfway through leaves the tables untouched.
Applied by hand as above, each statement commits on its own.
"""

# the dialects the RBAC migrations support
SUPPORTED_DIALECTS = ('oracle', 'mysql', 'postgresql')

# the schema the tables live in, as configured in the [database] section (None for the default schema)
SCHEMA = DEFAULT_SCHEMA_NAME

ROLES_TABLE = 'roles'
ROLE_PERMISSION_MAP_TABLE = 'role_permission_map'

ROLES_LOCKED_NN = 'ROLES_LOCKED_NN'
ROLES_ASSIGNMENT_DISABLED_NN = 'ROLES_ASSIGNMENT_DISABLED_NN'
ROLES_INTERNAL_ROLE_FLAG_NN = 'ROLES_INTERNAL_ROLE_FLAG_NN'

ROLE_PERMISSION_MAP_PK = 'ROLE_PERMISSION_MAP_PK'
ROLE_PERMISSION_MAP_SCOPE_FK = 'ROLE_PERMISSION_MAP_SCOPE_FK'
ROLE_PERMISSION_MAP_SCOPE_NN = 'ROLE_PERMISSION_MAP_SCOPE_NN'
ROLE_PERMISSION_MAP_SCOPE_PATTERN_NN = 'ROLE_PERMISSION_MAP_SCOPE_PATTERN_NN'

# the length scope_pattern is given, taken from the SCOPE_LENGTH schema value scope used to have
SCOPE_PATTERN_LENGTH = 25


def _column_names(inspector: sa.Inspector, table: str) -> set[str]:
    """Return the names of the columns the given table currently has."""
    return {column['name'] for column in inspector.get_columns(table, schema=SCHEMA)}


def _check_constraint_names(inspector: sa.Inspector, table: str) -> set[str]:
    """Return the names of the check constraints the given table currently has."""
    return {constraint['name'] for constraint in inspector.get_check_constraints(table, schema=SCHEMA) if constraint['name']}


def _foreign_key_names(inspector: sa.Inspector, table: str) -> set[str]:
    """Return the names of the foreign keys the given table currently has."""
    return {constraint['name'] for constraint in inspector.get_foreign_keys(table, schema=SCHEMA) if constraint['name']}


def _add_role_flag(op: Operations, existing_columns: set[str], column: str, check_constraint_name: str) -> None:
    """
    Add one of the new `roles` boolean flags.

    The column is added as nullable, backfilled with False for the existing roles and
    only then made NOT NULL, so that the table can be migrated while it holds roles.

    :param op: The alembic operations to run the statements through.
    :param existing_columns: The columns the `roles` table currently has.
    :param column: The name of the flag to add.
    :param check_constraint_name: The name of the NOT NULL check constraint to create for it.
    """
    if column in existing_columns:
        print("Column %s.%s already exists, nothing to do." % (ROLES_TABLE, column))
        return

    op.add_column(ROLES_TABLE, sa.Column(column, sa.Boolean, default=False), schema=SCHEMA)

    roles = sa.table(ROLES_TABLE, sa.column(column, sa.Boolean), schema=SCHEMA)
    # a literal keeps the statement self-contained, so that --dry-run prints runnable SQL
    op.execute(sa.update(roles).where(roles.c[column].is_(None)).values(**{column: sa.false()}))

    op.alter_column(ROLES_TABLE, column, existing_type=sa.Boolean(), nullable=False, schema=SCHEMA)
    op.create_check_constraint(check_constraint_name, ROLES_TABLE, '%s IS NOT NULL' % column, schema=SCHEMA)
    print("Added column %s.%s, defaulting the existing roles to false." % (ROLES_TABLE, column))


def replace_roles_locked_with_flags(op: Operations, existing_columns: set[str], existing_check_constraints: set[str]) -> None:
    """
    Replace the `locked` flag of the `roles` table with `assignment_disabled` and `internal_role_flag`.

    The value currently stored in `locked` has no unambiguous equivalent among the two new
    flags and is therefore discarded together with the column.

    :param op: The alembic operations to run the statements through.
    :param existing_columns: The columns the `roles` table currently has.
    :param existing_check_constraints: The check constraints the `roles` table currently has.
    """
    _add_role_flag(op, existing_columns, 'assignment_disabled', ROLES_ASSIGNMENT_DISABLED_NN)
    _add_role_flag(op, existing_columns, 'internal_role_flag', ROLES_INTERNAL_ROLE_FLAG_NN)

    if 'locked' not in existing_columns:
        print("Column %s.locked is already gone, nothing to drop." % ROLES_TABLE)
        return

    # the NOT NULL check constraint has to go first, otherwise the column it refers to cannot be dropped
    if ROLES_LOCKED_NN in existing_check_constraints:
        op.drop_constraint(ROLES_LOCKED_NN, ROLES_TABLE, type_='check', schema=SCHEMA)
        print("Dropped constraint %s." % ROLES_LOCKED_NN)

    op.drop_column(ROLES_TABLE, 'locked', schema=SCHEMA)
    print("Dropped column %s.locked." % ROLES_TABLE)


def replace_role_permission_map_scope_with_pattern(
        op: Operations,
        existing_columns: set[str],
        existing_check_constraints: set[str],
        existing_foreign_keys: set[str]) -> None:
    """
    Replace the `scope` foreign key of `role_permission_map` with a plain `scope_pattern` string.

    Existing `scope` values are copied into `scope_pattern` verbatim before the column is
    dropped, since every scope name is also a valid (literal) pattern.

    :param op: The alembic operations to run the statements through.
    :param existing_columns: The columns the `role_permission_map` table currently has.
    :param existing_check_constraints: The check constraints the `role_permission_map` table currently has.
    :param existing_foreign_keys: The foreign keys the `role_permission_map` table currently has.
    """
    if 'scope_pattern' in existing_columns:
        print("Column %s.scope_pattern already exists, nothing to add." % ROLE_PERMISSION_MAP_TABLE)
    else:
        op.add_column(ROLE_PERMISSION_MAP_TABLE, sa.Column('scope_pattern', sa.String(SCOPE_PATTERN_LENGTH)), schema=SCHEMA)

        if 'scope' in existing_columns:
            table = sa.table(ROLE_PERMISSION_MAP_TABLE, sa.column('scope_pattern', sa.String), sa.column('scope', sa.String), schema=SCHEMA)
            op.execute(sa.update(table).where(table.c.scope_pattern.is_(None)).values(scope_pattern=table.c.scope))

        op.alter_column(ROLE_PERMISSION_MAP_TABLE, 'scope_pattern', existing_type=sa.String(SCOPE_PATTERN_LENGTH), nullable=False, schema=SCHEMA)
        op.create_check_constraint(ROLE_PERMISSION_MAP_SCOPE_PATTERN_NN, ROLE_PERMISSION_MAP_TABLE, 'scope_pattern IS NOT NULL', schema=SCHEMA)
        print("Added column %s.scope_pattern, copied over from the existing scope column." % ROLE_PERMISSION_MAP_TABLE)

    if 'scope' not in existing_columns:
        print("Column %s.scope is already gone, nothing to drop." % ROLE_PERMISSION_MAP_TABLE)
        return

    # the primary key has to be redefined around scope_pattern before scope can be dropped
    op.drop_constraint(ROLE_PERMISSION_MAP_PK, ROLE_PERMISSION_MAP_TABLE, type_='primary', schema=SCHEMA)
    op.create_primary_key(ROLE_PERMISSION_MAP_PK, ROLE_PERMISSION_MAP_TABLE, ['role', 'scope_pattern', 'operation'], schema=SCHEMA)
    print("Redefined constraint %s around scope_pattern." % ROLE_PERMISSION_MAP_PK)

    if ROLE_PERMISSION_MAP_SCOPE_FK in existing_foreign_keys:
        op.drop_constraint(ROLE_PERMISSION_MAP_SCOPE_FK, ROLE_PERMISSION_MAP_TABLE, type_='foreignkey', schema=SCHEMA)
        print("Dropped constraint %s." % ROLE_PERMISSION_MAP_SCOPE_FK)

    if ROLE_PERMISSION_MAP_SCOPE_NN in existing_check_constraints:
        op.drop_constraint(ROLE_PERMISSION_MAP_SCOPE_NN, ROLE_PERMISSION_MAP_TABLE, type_='check', schema=SCHEMA)
        print("Dropped constraint %s." % ROLE_PERMISSION_MAP_SCOPE_NN)

    op.drop_column(ROLE_PERMISSION_MAP_TABLE, 'scope', schema=SCHEMA)
    print("Dropped column %s.scope." % ROLE_PERMISSION_MAP_TABLE)


def main() -> None:
    """Apply the RBAC table modifications to the configured database."""
    parser = argparse.ArgumentParser(description='Bring the RBAC tables of a running database in line with the current models.')
    parser.add_argument('--dry-run', action='store_true', help='print the statements instead of executing them')
    args = parser.parse_args()

    engine = get_engine()
    if engine.dialect.name not in SUPPORTED_DIALECTS:
        print("Dialect '%s' is not supported, the RBAC tables can only be modified on %s."
              % (engine.dialect.name, ', '.join(SUPPORTED_DIALECTS)), file=sys.stderr)
        sys.exit(1)

    print("Modifying the RBAC tables on %s (schema: %s)." % (engine.dialect.name, SCHEMA or 'default'))

    inspector = sa.inspect(engine)
    tables = set(inspector.get_table_names(schema=SCHEMA))
    required = {ROLES_TABLE, ROLE_PERMISSION_MAP_TABLE}
    missing = sorted(table for table in required if table not in tables)
    if missing:
        print("Table(s) %s do(es) not exist in schema '%s', run setup.py first."
              % (', '.join(missing), SCHEMA or inspector.default_schema_name), file=sys.stderr)
        sys.exit(1)

    roles_columns = _column_names(inspector, ROLES_TABLE)
    roles_check_constraints = _check_constraint_names(inspector, ROLES_TABLE)
    role_permission_map_columns = _column_names(inspector, ROLE_PERMISSION_MAP_TABLE)
    role_permission_map_check_constraints = _check_constraint_names(inspector, ROLE_PERMISSION_MAP_TABLE)
    role_permission_map_foreign_keys = _foreign_key_names(inspector, ROLE_PERMISSION_MAP_TABLE)

    with engine.begin() as connection:
        context = MigrationContext.configure(connection, opts={'as_sql': args.dry_run, 'output_buffer': sys.stdout})
        op = Operations(context)
        replace_roles_locked_with_flags(op, roles_columns, roles_check_constraints)
        replace_role_permission_map_scope_with_pattern(
            op, role_permission_map_columns, role_permission_map_check_constraints, role_permission_map_foreign_keys)

    if args.dry_run:
        print('Dry run, no modification was applied.')
    else:
        print('RBAC tables are in line with the models.')


if __name__ == '__main__':
    main()
