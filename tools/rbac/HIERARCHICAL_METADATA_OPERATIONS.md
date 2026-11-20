# Proposal: hierarchical metadata operations (`w` ⊃ `r`)

Status: implemented, see `DID_PERMISSIONS.md` (section 7) and `ROLE_OVERLAPS.md` (section 3). It extends
`HIERARCHICAL_DID_OPERATIONS.md` to the metadata permissions.

## Summary

Today the two operations of a metadata permission are independent: `w` on a key does not include `r`, so `-w` writes
a key without seeing it, nor the DID. The proposal makes them levels, as for the DID permissions: **`w` always
includes `r`**. A metadata permission then grants one of three levels on a key: none (`--`), read (`r-`) or write
(`rw`).

It would be enforced **when the permission is stored**, as for the DID permissions: granting `w` stores `rw`, and the
CLI says so. What `rucio role permission list` shows is exactly what applies, and the checks (`MetadataAccess`, the
generic policy, the key filter of the listings) do not change.

## Does it break something?

Nothing in the permission logic: the checks only look at the stored `can_read` and `can_write` columns, which keep
their meaning. Below is everything that relies on `w` without `r` today, found by reading the code and the tests.

| Where | Today | With the hierarchy | Action |
|---|---|---|---|
| `MetadataPermissionHandler.normalize_parameters` (`lib/rucio/core/role.py`) | stores the operations as given | completes them: `w` → `rw` | the change itself |
| A permission on no key (only makes DIDs visible) | must be exactly `r`: `w` and `rw` refused | `w` becomes `rw`, still refused | none, the error message stays right |
| The keys no metadata permission writes (`METADATA_KEYS_NOT_WRITABLE`: protected and deletion keys) | `w` refused on them | `w` (stored `rw`) still refused | none |
| `--` (none) | stored, withdraws the key | unchanged | none |
| `MetadataAccess.is_visible`, `is_visible_in_scope` | a row with `r` makes its DIDs visible | unchanged code, but **every row granting an operation** now has `r`: a `w` row makes its DIDs visible | document it (see below) |
| `MetadataAccess.can_read_key` / `can_write_key`, the key filter of listings | per stored column | unchanged | none |
| The DID permissions, and the fallback of a key to them (`r` reads, `d` writes) | `d` includes `r` already | unchanged: a key written through DID `d` is readable already | none |
| `tests/test_rbac_metadata_permissions.py::test_writing_blindly` | `w` on `project`: the DID is not visible, `project` is written | **fails**: the DID is visible with `project`, which is still written | becomes a test of the hierarchy |
| `test_invalid_metadata_permissions_are_refused` (`w on no key`, `w on a protected key`, `w on the name`) | refused | still refused | none |
| `test_roles_add_up` rows mixing `w` in one role and `r` in another | `rw` | `rw` | none |
| The other tests (`tests/test_role_did_permission.py`, `tests/test_rbac_restapi.py`, `tests/test_role.py`) | no metadata `w` without `r` | | none |
| The CLI (`lib/rucio/cli/role.py`, `metadata add`) | `Note: without r, the DIDs matching ... are not made visible: the keys can be written but not read.` | that note can no longer happen | replaced by `w implies r: stored rw on ... of ...` |
| The dev environment (`tools/rbac/db_setup/setup_test_db.py`) | every metadata grant includes `r`, or is `--` | | none |
| Databases | RBAC is not released | | no migration; a one-off update completes the dev rows |

So the only real behaviour change is the visibility one, and only one test encodes the old behaviour.

## What it simplifies

- **One paradigm for DIDs and keys:** `w` always includes `r`, whatever the permission type. "Blind" access is gone
  everywhere.
- **No existence oracle.** With `-w` on `project` of `atlas:*`, an account sees no DID of `atlas`, yet
  `set_metadata atlas:x project ...` passes the permission check whether or not `atlas:x` exists. The core then
  answers with a success or `DataIdentifierNotFound`, which tells whether a DID it may not see exists. With the
  hierarchy the account sees the DIDs it writes, so nothing is revealed.
- **Fewer surprises within a role:** with DID `r` on `atlas:*` and metadata `w` on `project`, the key `project` is
  `-w` today (the metadata row decides the key, and withdraws its `r` from the DID fallback): writable but no longer
  readable. With the hierarchy it is `rw`.

## What it implies, and what is lost

- **A `w` row makes the DIDs visible.** Granting `w` on a key of a pattern now lists the DIDs it matches (and their
  scope), and lets `get_did`, `get_metadata` (with the keys the rows grant), the content, the rules and the locks of
  these DIDs be read, without their data (no replica PFN, hence no download), as an `r` row does today. In
  particular `w` on `*` shows every key of every DID the pattern matches.
- **No write-only keys.** A key can no longer be written without being read, e.g. a "drop box" key where accounts
  submit a value they cannot read back, nor written on DIDs the account cannot see.
- **Unchanged:** the keys Rucio holds and the deletion keys (never written through a metadata permission), the
  permission on no key (`r` only), `--` withdrawing a key within its role, the roles adding up, the data of a DID
  never granted by a metadata permission, ownership (DID `w` on the DID), and the rule that RBAC is decided only by
  the permission policy.

---

## Implementation Steps

To do as for the DID operations: "To Squash: <SHA>" commits on top of `issue-8888`, each holding the changes of one
earlier commit.

1. **Core (`lib/rucio/core/role.py`), "feat(Core): grant metadata permissions to roles, overriding their DID
   permissions on the keys they name" (`ea4f81332`):**
   - in `MetadataPermissionHandler.normalize_parameters`, complete the operations (`w` adds `r`) before the checks
     on no key and on the non-writable keys;
   - reuse the helper of the DID permissions: either a second mapping `_INCLUDED_METADATA_OPERATIONS` next to
     `_INCLUDED_DID_OPERATIONS`, or one helper taking the mapping, `_complete_operations(operations, included)`,
     introduced in `01a657f1a` (recommended: one helper, no duplication);
   - update the comment of the metadata permissions and the docstring of the handler ("a row granting READ makes the
     DIDs visible" becomes "a row granting an operation").
2. **Tests, "test(API): test the metadata permissions of roles end to end, through the gateway" (`89239dd7b`):**
   - `test_writing_blindly` becomes a test of the hierarchy: `w` on `project` is stored `rw`, the DID is visible with
     `project` only, and `project` is written;
   - add a test that granting `w` stores `rw` and `r` stays `r-`.
3. **CLI (`lib/rucio/cli/role.py`), "feat(Clients): manage the metadata permissions of roles in the CLI"
   (`33be86110`):** read back what the server stored, print `w implies r: stored rw on <keys> of <pattern>` instead of
   the "without r" note, and say in the help of `metadata add` that `w` also grants `r`.
4. **REST/API docs, "docs(API): document the metadata permissions in the gateway and the REST API" (`2c4703875`),
   and the client docstring:** state that `write` includes `read`.
5. **Dev docs, the `DROP:` commit (`280a6cb8e`):** `DID_PERMISSIONS.md` section 7 (the levels of access, "a row with
   only `w` writes blindly"), `ROLE_OVERLAPS.md` (the `-w` on `quality` row, and the lines saying the metadata
   operations stay independent), the "metadata permissions are unchanged" line of `HIERARCHICAL_DID_OPERATIONS.md`,
   and mark this proposal as implemented.
6. **Verify:** ruff 0.14.9, and the RBAC suites in the dev container, `test_rbac_restapi.py` with `rbac.enabled=True`
   (restored afterwards).
