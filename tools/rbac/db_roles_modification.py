"""Bring the RBAC tables of a running database in line with the current models.

The tables created by the initial RBAC migration are not in line with
`rucio.db.sqla.models` any more:

  * `roles` is missing the `locked` flag;
  * `account_role_map` still carries a `locked` boolean, whereas the models
    expect a nullable `expires_at` timestamp instead;
  * the foreign keys of the tables around the roles carry no referential action, whereas the
    models now declare an ON UPDATE and an ON DELETE rule for each of them.

The constraints are read from `models.py` itself rather than spelled out here, so that this
script keeps applying whatever the models declare, unique constraints included.

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
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlalchemy as sa  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.operations import Operations  # noqa: E402
from sqlalchemy.schema import ForeignKeyConstraint, UniqueConstraint  # noqa: E402

from rucio.db.sqla import models  # noqa: E402
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

4. Give the foreign keys the referential actions the models declare. They cannot be altered
   in place, so each one is dropped and created again:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_map DROP CONSTRAINT \\"ACCOUNT_MAP_ACCOUNT_FK\\", ADD CONSTRAINT \\"ACCOUNT_MAP_ACCOUNT_FK\\" FOREIGN KEY (account) REFERENCES $DBOD_SCHEMA.accounts (account) ON UPDATE CASCADE ON DELETE RESTRICT;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_map DROP CONSTRAINT \\"ACCOUNT_MAP_ID_TYPE_FK\\", ADD CONSTRAINT \\"ACCOUNT_MAP_ID_TYPE_FK\\" FOREIGN KEY (identity, identity_type) REFERENCES $DBOD_SCHEMA.identities (identity, identity_type) ON UPDATE CASCADE ON DELETE RESTRICT;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.scopes DROP CONSTRAINT \\"SCOPES_ACCOUNT_FK\\", ADD CONSTRAINT \\"SCOPES_ACCOUNT_FK\\" FOREIGN KEY (account) REFERENCES $DBOD_SCHEMA.accounts (account) ON UPDATE CASCADE ON DELETE RESTRICT;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_role_map DROP CONSTRAINT \\"ACCOUNT_ROLE_MAP_ACCOUNT_FK\\", ADD CONSTRAINT \\"ACCOUNT_ROLE_MAP_ACCOUNT_FK\\" FOREIGN KEY (account) REFERENCES $DBOD_SCHEMA.accounts (account) ON UPDATE CASCADE ON DELETE CASCADE;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.account_role_map DROP CONSTRAINT \\"ACCOUNT_ROLE_MAP_ROLE_FK\\", ADD CONSTRAINT \\"ACCOUNT_ROLE_MAP_ROLE_FK\\" FOREIGN KEY (role) REFERENCES $DBOD_SCHEMA.roles (role) ON UPDATE CASCADE ON DELETE RESTRICT;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map DROP CONSTRAINT \\"ROLE_PERMISSION_MAP_ROLE_FK\\", ADD CONSTRAINT \\"ROLE_PERMISSION_MAP_ROLE_FK\\" FOREIGN KEY (role) REFERENCES $DBOD_SCHEMA.roles (role) ON UPDATE CASCADE ON DELETE RESTRICT;"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "ALTER TABLE $DBOD_SCHEMA.role_permission_map DROP CONSTRAINT \\"ROLE_PERMISSION_MAP_SCOPE_FK\\", ADD CONSTRAINT \\"ROLE_PERMISSION_MAP_SCOPE_FK\\" FOREIGN KEY (scope) REFERENCES $DBOD_SCHEMA.scopes (scope) ON UPDATE CASCADE ON DELETE CASCADE;"

   Oracle knows neither an ON UPDATE clause nor ON DELETE RESTRICT, so there the ON UPDATE is
   left out and RESTRICT is the default delete rule anyway.

5. Verify that both tables now match the models:

    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "\\d $DBOD_SCHEMA.roles"
    PGPASSWORD="$DBOD_ADMIN_PASSWORD" psql -h $DBOD_HOST -p $DBOD_PORT -U admin -d $RUCIO_DB -c "\\d $DBOD_SCHEMA.account_role_map"

Steps 2. to 4. are applied in a single transaction when this script is run
without `--dry-run`, so a failure halfway through leaves the tables untouched.
Applied by hand as above, each statement commits on its own.
"""

# the dialects the RBAC migrations support
SUPPORTED_DIALECTS = ('oracle', 'mysql', 'postgresql')

# the schema the tables live in, as configured in the [database] section (None for the default schema)
SCHEMA = DEFAULT_SCHEMA_NAME

# the models whose foreign keys and unique constraints this script brings in line with
# `models.py`, which is the only place where they are declared
MODELS_WITH_CONSTRAINTS = (
    models.IdentityAccountAssociation,
    models.Scope,
    models.Roles,
    models.AccountRoleAssociation,
    models.RolePermissionAssociation,
)

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


def _referential_action(action: Optional[str]) -> Optional[str]:
    """Normalise a referential action, NO ACTION and no action at all being the same thing."""
    action = (action or '').upper() or None
    return None if action == 'NO ACTION' else action


def _declared_foreign_keys(model: Any) -> list[dict[str, Any]]:
    """Describe the foreign keys a model declares, the way the inspector reports them."""
    declared = []
    for constraint in model.__table__.constraints:
        if not isinstance(constraint, ForeignKeyConstraint):
            continue
        declared.append({
            'name': constraint.name,
            'constrained_columns': [element.parent.name for element in constraint.elements],
            'referred_table': constraint.elements[0].column.table.name,
            'referred_columns': [element.column.name for element in constraint.elements],
            'onupdate': _referential_action(constraint.onupdate),
            'ondelete': _referential_action(constraint.ondelete),
        })
    return declared


def _declared_unique_constraints(model: Any) -> list[dict[str, Any]]:
    """Describe the named unique constraints a model declares."""
    return [
        {'name': constraint.name, 'column_names': [column.name for column in constraint.columns]}
        for constraint in model.__table__.constraints
        if isinstance(constraint, UniqueConstraint) and constraint.name
    ]


def _actions_for_dialect(foreign_key: dict[str, Any], dialect: str) -> tuple[Optional[str], Optional[str], list[str]]:
    """
    Return the referential actions the dialect can express, and what it cannot.

    Oracle only knows ON DELETE CASCADE and ON DELETE SET NULL: it has no ON UPDATE clause at
    all, and its default delete rule already refuses to delete a referenced row, which is what
    RESTRICT asks for.

    :param foreign_key: The foreign key as the models declare it.
    :param dialect: The name of the dialect the statements are for.
    :returns: The ON UPDATE and ON DELETE action to use, and the notes about the ones dropped.
    """
    onupdate, ondelete = foreign_key['onupdate'], foreign_key['ondelete']
    notes = []

    if dialect == 'oracle':
        if onupdate:
            notes.append("%s: Oracle has no ON UPDATE clause, so ON UPDATE %s is left out" % (foreign_key['name'], onupdate))
            onupdate = None
        if ondelete == 'RESTRICT':
            notes.append("%s: Oracle has no ON DELETE RESTRICT, its default delete rule behaves the same" % foreign_key['name'])
            ondelete = None

    return onupdate, ondelete, notes


def apply_declared_constraints(op: Operations, inspector: sa.Inspector, dialect: str) -> None:
    """
    Give the foreign keys and unique constraints of the tables the models' definition.

    The referential actions of a foreign key cannot be altered in place, so a foreign key whose
    actions differ from the declared ones is dropped and created again. A missing unique
    constraint is simply added.

    :param op: The alembic operations to run the statements through.
    :param inspector: The inspector to read the current constraints from.
    :param dialect: The name of the dialect the statements are for.
    """
    for model in MODELS_WITH_CONSTRAINTS:
        table = model.__table__.name
        current_foreign_keys = {foreign_key['name']: foreign_key for foreign_key in inspector.get_foreign_keys(table, schema=SCHEMA)}

        for declared in _declared_foreign_keys(model):
            onupdate, ondelete, notes = _actions_for_dialect(declared, dialect)
            for note in notes:
                print("Note: %s." % note)

            current = current_foreign_keys.get(declared['name'])
            options = (current or {}).get('options') or {}
            if current is not None and _referential_action(options.get('onupdate')) == onupdate and _referential_action(options.get('ondelete')) == ondelete:
                print("Constraint %s already has the declared referential actions, nothing to do." % declared['name'])
                continue

            if current is not None:
                op.drop_constraint(declared['name'], table, type_='foreignkey', schema=SCHEMA)
            op.create_foreign_key(declared['name'], table, declared['referred_table'],
                                  declared['constrained_columns'], declared['referred_columns'],
                                  onupdate=onupdate, ondelete=ondelete,
                                  source_schema=SCHEMA, referent_schema=SCHEMA)
            print("Constraint %s on %s now has ON UPDATE %s and ON DELETE %s."
                  % (declared['name'], table, onupdate or 'NO ACTION', ondelete or 'NO ACTION'))

        current_unique = {constraint['name'] for constraint in inspector.get_unique_constraints(table, schema=SCHEMA)}
        for declared_unique in _declared_unique_constraints(model):
            if declared_unique['name'] in current_unique:
                print("Constraint %s already exists, nothing to do." % declared_unique['name'])
                continue
            op.create_unique_constraint(declared_unique['name'], table, declared_unique['column_names'], schema=SCHEMA)
            print("Added constraint %s on %s(%s)." % (declared_unique['name'], table, ', '.join(declared_unique['column_names'])))


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
    required = {ROLES_TABLE, ACCOUNT_ROLE_MAP_TABLE} | {model.__table__.name for model in MODELS_WITH_CONSTRAINTS}
    missing = sorted(table for table in required if table not in tables)
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
        apply_declared_constraints(op, inspector, engine.dialect.name)

    if args.dry_run:
        print('Dry run, no modification was applied.')
    else:
        print('RBAC tables are in line with the models.')


if __name__ == '__main__':
    main()
