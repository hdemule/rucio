"""Bring the RBAC tables of a running database in line with the current models.

The tables created by the initial RBAC migration are not in line with
`rucio.db.sqla.models` any more:

  * `roles` is missing the `locked` flag;
  * `account_role_map` still carries a `locked` boolean, whereas the models
    expect a nullable `expires_at` timestamp instead.

This script applies both changes directly on the configured database, without
going through alembic. It is idempotent: a step that has already been applied is
skipped, so it can safely be run again.

Note that the `locked` flags currently stored in `account_role_map` are dropped
together with the column; they are not converted into expiry dates. Use
`--dry-run` to see the statements without applying them.
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

1. Check what the `locked` flags of the role assignments hold, since they are discarded:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "SELECT locked, count(*) FROM $DBOD_SCHEMA.account_role_map GROUP BY locked;"

2. Add the `locked` flag to the roles, as nullable first, so that the existing roles can be backfilled:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ADD COLUMN locked BOOLEAN;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "UPDATE $DBOD_SCHEMA.roles SET locked = false WHERE locked IS NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ALTER COLUMN locked SET NOT NULL;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.roles ADD CONSTRAINT \\"ROLES_LOCKED_NN\\" CHECK (locked IS NOT NULL);"

3. Replace the `locked` flag of the role assignments with an `expires_at`. The check
   constraint has to go before the column it refers to:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_role_map ADD COLUMN expires_at TIMESTAMP WITHOUT TIME ZONE;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_role_map DROP CONSTRAINT \\"ACCOUNT_ROLE_MAP_LOCKED_NN\\";"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_role_map DROP COLUMN locked;"

4. Verify that both tables now match the models:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "\\d $DBOD_SCHEMA.roles"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "\\d $DBOD_SCHEMA.account_role_map"

Steps 2. and 3. are applied in a single transaction when this script is run
without `--dry-run`, so a failure halfway through leaves the tables untouched.
Applied by hand as above, each statement commits on its own.
"""

# the dialects the RBAC migrations support
SUPPORTED_DIALECTS = ('oracle', 'mysql', 'postgresql')

# the schema the tables live in, as configured in the [database] section (None for the default schema)
SCHEMA = DEFAULT_SCHEMA_NAME

ROLES_TABLE = 'roles'
ACCOUNT_ROLE_MAP_TABLE = 'account_role_map'
ACCOUNT_ROLE_MAP_LOCKED_NN = 'ACCOUNT_ROLE_MAP_LOCKED_NN'
ROLES_LOCKED_NN = 'ROLES_LOCKED_NN'


def _column_names(inspector: sa.Inspector, table: str) -> set[str]:
    """Return the names of the columns the given table currently has."""
    return {column['name'] for column in inspector.get_columns(table, schema=SCHEMA)}


def _check_constraint_names(inspector: sa.Inspector, table: str) -> set[str]:
    """Return the names of the check constraints the given table currently has."""
    return {constraint['name'] for constraint in inspector.get_check_constraints(table, schema=SCHEMA) if constraint['name']}


def add_roles_locked(op: Operations, existing_columns: set[str]) -> None:
    """
    Add the `locked` flag to the `roles` table.

    The column is added as nullable, backfilled with False for the existing roles and
    only then made NOT NULL, so that the table can be migrated while it holds roles.

    :param op: The alembic operations to run the statements through.
    :param existing_columns: The columns the `roles` table currently has.
    """
    if 'locked' in existing_columns:
        print("Column %s.locked already exists, nothing to do." % ROLES_TABLE)
        return

    op.add_column(ROLES_TABLE, sa.Column('locked', sa.Boolean, default=False), schema=SCHEMA)

    roles = sa.table(ROLES_TABLE, sa.column('locked', sa.Boolean), schema=SCHEMA)
    # a literal keeps the statement self-contained, so that --dry-run prints runnable SQL
    op.execute(sa.update(roles).where(roles.c.locked.is_(None)).values(locked=sa.false()))

    op.alter_column(ROLES_TABLE, 'locked', existing_type=sa.Boolean(), nullable=False, schema=SCHEMA)
    op.create_check_constraint(ROLES_LOCKED_NN, ROLES_TABLE, 'locked IS NOT NULL', schema=SCHEMA)
    print("Added column %s.locked, defaulting the existing roles to not locked." % ROLES_TABLE)


def replace_account_role_locked_with_expires_at(
        op: Operations,
        existing_columns: set[str],
        existing_check_constraints: set[str],
        locked_count: int = 0) -> None:
    """
    Replace the `locked` flag of the `account_role_map` table with an `expires_at` timestamp.

    The column is nullable, a NULL meaning that the role assignment does not expire.
    The values stored in `locked` have no equivalent as an expiry date and are
    therefore discarded together with the column.

    :param op: The alembic operations to run the statements through.
    :param existing_columns: The columns the `account_role_map` table currently has.
    :param existing_check_constraints: The check constraints the `account_role_map` table currently has.
    :param locked_count: The number of role assignments currently flagged as locked, reported before they are discarded.
    """
    if 'expires_at' in existing_columns:
        print("Column %s.expires_at already exists, nothing to add." % ACCOUNT_ROLE_MAP_TABLE)
    else:
        op.add_column(ACCOUNT_ROLE_MAP_TABLE, sa.Column('expires_at', sa.DateTime, nullable=True, default=None), schema=SCHEMA)
        print("Added column %s.expires_at." % ACCOUNT_ROLE_MAP_TABLE)

    if 'locked' not in existing_columns:
        print("Column %s.locked is already gone, nothing to drop." % ACCOUNT_ROLE_MAP_TABLE)
        return

    if locked_count:
        print("Warning: dropping %s.locked discards the locked flag of %d role assignment(s)."
              % (ACCOUNT_ROLE_MAP_TABLE, locked_count))

    # the NOT NULL check constraint has to go first, otherwise the column it
    # refers to cannot be dropped
    if ACCOUNT_ROLE_MAP_LOCKED_NN in existing_check_constraints:
        op.drop_constraint(ACCOUNT_ROLE_MAP_LOCKED_NN, ACCOUNT_ROLE_MAP_TABLE, type_='check', schema=SCHEMA)
        print("Dropped constraint %s." % ACCOUNT_ROLE_MAP_LOCKED_NN)

    op.drop_column(ACCOUNT_ROLE_MAP_TABLE, 'locked', schema=SCHEMA)
    print("Dropped column %s.locked." % ACCOUNT_ROLE_MAP_TABLE)


def _count_locked_assignments(connection: sa.Connection) -> int:
    """
    Return the number of role assignments currently flagged as locked.

    This query is run on the connection directly rather than through the alembic
    operations, so that it is answered even during a dry run.
    """
    account_role_map = sa.table(ACCOUNT_ROLE_MAP_TABLE, sa.column('locked', sa.Boolean), schema=SCHEMA)
    stmt = sa.select(sa.func.count()).select_from(account_role_map).where(account_role_map.c.locked.is_(True))
    return connection.execute(stmt).scalar() or 0


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
    missing = [table for table in (ROLES_TABLE, ACCOUNT_ROLE_MAP_TABLE) if table not in tables]
    if missing:
        print("Table(s) %s do(es) not exist in schema '%s', run setup.py first."
              % (', '.join(missing), SCHEMA or inspector.default_schema_name), file=sys.stderr)
        sys.exit(1)

    roles_columns = _column_names(inspector, ROLES_TABLE)
    account_role_map_columns = _column_names(inspector, ACCOUNT_ROLE_MAP_TABLE)
    account_role_map_constraints = _check_constraint_names(inspector, ACCOUNT_ROLE_MAP_TABLE)

    with engine.begin() as connection:
        locked_count = _count_locked_assignments(connection) if 'locked' in account_role_map_columns else 0

        context = MigrationContext.configure(connection, opts={'as_sql': args.dry_run, 'output_buffer': sys.stdout})
        op = Operations(context)
        add_roles_locked(op, roles_columns)
        replace_account_role_locked_with_expires_at(op, account_role_map_columns, account_role_map_constraints, locked_count)

    if args.dry_run:
        print('Dry run, no modification was applied.')
    else:
        print('RBAC tables are in line with the models.')


if __name__ == '__main__':
    main()
