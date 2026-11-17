# Proposal: hierarchical DID operations (`d` ⊃ `w` ⊃ `r`)

Status: implemented, see `DID_PERMISSIONS.md` (section 1) and `ROLE_OVERLAPS.md` (section 1.2).

## Summary

Today the three DID operations of a role are independent: `w` does not include `r`, and `d` includes neither. The
proposal makes them levels instead: **`w` always includes `r`, and `d` always includes `w` and `r`**. A DID
permission then grants one of four levels: none (`---`), read (`r--`), write (`rw-`) or delete (`rwd`).

This would be enforced **when a permission is stored**, not when it is evaluated. Granting `w` stores `rw-`,
granting `d` stores `rwd`, and the CLI says so. What `rucio role permission did list` shows is then exactly what
applies, and the permission checks (`DidAccess`, the generic policy) do not change.

## What it simplifies

- **One mental model.** `r` reads; `w` reads and creates, and manages your own DIDs; `d` reads, creates and acts on
  other accounts' DIDs. That is the intended paradigm: `w` is high-privilege but not destructive, and `d` is close to
  admin for the pattern.
- **Owners always see their own DIDs.** Ownership requires `w` on the DID, which then includes `r`: an owner who may
  administer a DID can always read it.
- **No more "write but blind" surprises:**
  - with `r` on `atlas:*` and `w` on `atlas:raw*` in the same role, the raw DIDs become `rw-` instead of `-w-`
    (unreadable);
  - a role with only `d` can see what it alters.

## The edge case it removes

Take an account that owns `atlas:file` and has only `-w-` on it.

- **Today:** it can read `atlas:file` by name, but `list_dids atlas:*` is refused, because listing a scope requires
  some `r` in it. If an **unrelated** role later grants `r` on any `atlas:x`, the listing is suddenly allowed and
  `atlas:file` appears. What you see depends on grants that have nothing to do with your DID.
- **With the hierarchy:** `w` on `atlas:file` includes `r`, so the account always has some `r` in `atlas`. Its
  listing consistently shows its own DIDs, whatever other grants it holds.

## What it implies, and what is lost

- **No more blind roles.** It is no longer possible to grant:
  - write-only access (a "drop box" where accounts attach or create DIDs without seeing the content);
  - delete-only access (a role that alters DIDs without reading them).

  Anyone who may attach into a collection may also list its content.
- **`d` also grants creation** (`w`) on its patterns.
- **Metadata permissions** were made hierarchical too (`w` ⊃ `r`), see `HIERARCHICAL_METADATA_OPERATIONS.md`.
- **Unchanged:** ownership, the admin-only actions, `test_no_role_grants_what_is_left_to_admins`, and the rule that
  RBAC is decided only by the permission policy, never by the gateway.
- **No migration.** RBAC is not released, so only dev databases may hold old rows, and a one-off update can complete
  them.

---

## Implementation Steps

> Implement hierarchical DID operations (`d` ⊃ `w` ⊃ `r`), completed when stored, as described in
> `tools/rbac/HIERARCHICAL_DID_OPERATIONS.md`. Fold every change into the commit that introduces it (no new commits),
> and propagate the changes to `issue-8888`, `issue-8888-ci` and all `feature-xx*` branches as in the previous
> rewrites:
> - back up every branch under `refs/backup/<name>/*` first;
> - keep the original commit metadata (authors, committers, dates, messages);
> - use a scripted `git filter-branch --index-filter`, or edit stops on a rebase;
> - do not push.
>
> 1. **Core (`lib/rucio/core/role.py`), in the commit "feat(Core): grant DID permissions to roles, the most specific
>    DID pattern deciding":**
>    - In the DID permission handler, when parameters are validated or stored, complete the operations: `w` adds
>      `r`, and `d` adds `w` and `r`. Do this in one small helper; `DidOperationType` keeps its three values.
>    - Only DID permissions are affected, not metadata permissions. An empty list (`none`) stays empty.
>    - Update the comment and docstrings describing DID operations: they say the operations are independent.
> 2. **CLI (`lib/rucio/cli/role.py`), in the commit "feat(Clients): add the 'rucio role' CLI to manage roles, their
>    DID permissions and assignments":**
>    - When the stored operations differ from those given, print a one-line notice, e.g.
>      `w implies r: stored rw- on atlas:raw*`.
>    - Keep the existing warning about narrower patterns withdrawing operations, checking that it still makes sense.
> 3. **Tests, in the commits that introduced each test:**
>    - **Core** (`tests/test_role_did_permission.py`): add a test that granting `w` stores `rw` and granting `d`
>      stores `rwd`. Update every case relying on independent operations: `test_did_permission_replaces_its_operations`,
>      the `-w-` / `--d` rows of `test_most_specific_pattern_decides` and `test_roles_add_up_despite_none`, and the
>      ownership and listing tests using `w`-only or `d`-only grants.
>    - **Gateway** (`tests/test_rbac_did_permissions.py`):
>      - `test_independent_operations` becomes a test of the hierarchy;
>      - update the `_access` expectations (`'-w-'`, `'--d'`, `'r-d'`, ...) in
>        `test_most_specific_pattern_decides_within_a_role`, `test_roles_add_up` and
>        `test_inactive_assignments_grant_nothing`;
>      - bob's `w`-only world cases now read: `list_dids` allowed, his DIDs listed, `list_scopes` shows the scope;
>      - check `test_ownership` and the world docstring.
>    - **Metadata** (`tests/test_rbac_metadata_permissions.py`): review the cases mixing DID `w` / `d` without `r`,
>      e.g. `test_metadata_read_is_not_did_read` with DID `w` on `alice.*`. The metadata `-w` blind-write cases stay
>      as they are.
>    - **CLI** (`tests/test_cli_role*`, and the CLI commits): update any rendered operations and add the notice.
>    - Keep `test_no_role_grants_what_is_left_to_admins` passing, unchanged.
> 4. **REST/API docs, in the docs commits** ("docs(API): document the ... permissions in the gateway and the REST
>    API"): update any description of DID operations as independent.
> 5. **Dev docs, in the `DROP:` commit** (`tools/rbac/DID_PERMISSIONS.md`, `tools/rbac/ROLE_OVERLAPS.md`):
>    - state the hierarchy and the storage-time completion;
>    - remove "independent operations" and the `-w-` / `--d` examples;
>    - fix §1.2 of the overlaps doc, the bob examples and the "`w` withdraws `r`" footgun;
>    - mention that blind roles are no longer possible;
>    - in the dev environment's setup script (`tools/rbac/db_setup/setup_test_db.py`), complete any `w`-only or
>      `d`-only grants;
>    - mark this proposal as implemented, or remove it.
> 6. **Verify:**
>    - no conflict markers;
>    - ruff 0.14.9 on every changed commit;
>    - unchanged metadata on every commit;
>    - in the dev container: the RBAC suites at each feature tip (xx03, xx04, xx05, xx08, xx09, xx10) and at the
>      final tip;
>    - the standard suites once with `rbac.enabled=False` (restore it afterwards);
>    - report failures that already existed separately.
