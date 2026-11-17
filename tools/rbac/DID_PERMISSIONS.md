# RBAC DID permissions

What a DID permission grants, as implemented on `rbac/main`.
Everything here applies only when RBAC is enabled: with RBAC off, the generic policy behaves exactly as standard Rucio.
The gateway always asks the permission policy, whether RBAC is enabled or not: deciding with or without RBAC is the
policy's business. A policy package which denies the actions it does not know has to grant the new ones.

- **Metadata permissions** refine what a role grants on the metadata keys of DIDs: see section 7.
- **Overlaps:** how permissions and roles combine when they cover the same DID, key or RSE is in `ROLE_OVERLAPS.md`.

```bash
rucio role permission did add ROLE DID_PATTERN OPERATIONS   # OPERATIONS: any of r, w, d, or none
rucio role permission did remove ROLE DID_PATTERN
```

- **Adding sets exactly OPERATIONS** on the pattern, replacing what the role had on it. `none` stores a row
  granting nothing, listed `---`, which matters because of the specificity rule below.
- **`---` grants nothing at all**, exactly like no row: the DIDs it matches are not listed, read, downloaded nor
  written through that role, and none of their metadata is shown. Its only effect is to override a wider pattern of
  the same role. To let DIDs be **browsed** (listed with their scope, name and type, without data nor metadata),
  give a metadata permission `r` on no key instead (section 7).
- **Removing deletes the row** of the pattern, whatever it grants. The DIDs it matched are then decided by the
  next most specific pattern of the role, if any. The CLI says which one.

## 1. Patterns

A pattern is always stored and listed with a scope part and a name part.

| Pattern | Matches | Input shorthand |
|---|---|---|
| `*:*` | every DID of every scope | `*` |
| `atlas*:*` | every DID of the scopes starting with `atlas` | `atlas*` |
| `atlas:*` | every DID of the scope `atlas` | `atlas` |
| `atlas:file*` | the DIDs of `atlas` whose name starts with `file` | |
| `atlas:file1` | the DID `atlas:file1` | |

- `*` is accepted only at the end of a part. A wildcard scope part only takes the `*` name part: `atlas*:file*`, `*:file1` and `*atlas:*` are invalid.
- A pattern is matched against the DID itself only. **There is no inheritance, by design:** a DID lives in its scope, whatever the collections it is attached to, so `atlas:ds1` does not cover the files inside `ds1`, and each DID is checked on its own.
- **Reading:** an account reads the DIDs on which a role grants `r` (through the pattern deciding them), plus the DIDs it owns and may write (`w` on them, section 4). Example: `r` on `atlas:calib*` reads `atlas:calib1`, but neither `atlas:file1` nor its own `atlas:x`; `w` on `atlas:x` lets it read `atlas:x` too.
- **Some `r` in a scope:** a role grants `r` on some DIDs of a scope if the pattern deciding the whole scope (`atlas:*`, else the longest `atlas*:*`) grants `r`, or one of its name patterns in the scope (`atlas:calib*`, `atlas:file1`) does. `r` on `atlas*:*` with `none` on `atlas:*` gives no `r` in `atlas`.
- **Whole-scope items:** only the patterns with the `*` name part grant a whole scope, and only if no name pattern of the same role withdraws the operation from some DIDs of the scope. `atlas:file*` never grants the whole scope `atlas`, and `r` on `atlas:*` with `none` on `atlas:secret*` does not grant it either. This only matters where an item stands for the whole scope rather than for DIDs (section 3).
- **Within a role, the most specific pattern decides:** for each DID, the row of the role whose pattern matches it
  and is the most specific gives every operation the role grants on it. The other rows matching it are ignored.
  The order is: exact name (`atlas:file1`), then name prefix (`atlas:file*`), then whole scope (`atlas:*`), then
  scope prefix (`atlas*:*`), a longer prefix being more specific. Examples:
  - `rwd` on `atlas:*` and `r` on `atlas:raw*`: the raw DIDs are read-only, the others `rwd`;
  - `rwd` on `atlas:*` and `none` on `atlas:tmp*`: the role grants nothing on the temporary DIDs;
  - `r` on `atlas:*` and `w` on `atlas:raw*`: the raw DIDs are `-w-`, **not readable**. To keep `r`, grant `rw` on `atlas:raw*`.
- **Across roles, everything adds up:** an operation is granted on a DID if one role grants it. A `---` only
  withdraws DIDs within its own role, it never hides what another role grants.
- **Independent operations:** `d` does not imply `w`, and `w` does not imply `r`.

## 2. Who is never limited by roles

| Account | Access |
|---|---|
| root, admins (the `admin` role, or the `admin` account attribute, as in standard Rucio) | everything, as in standard Rucio |
| owner of the scope | everything in the scope (standard Rucio), except that with RBAC on, attached DIDs and rule targets must be readable (section 5) |
| owner of a DID | see section 4 |

## 3. What each operation grants on the DIDs a pattern matches

### `r`: read

| Action | Granted by |
|---|---|
| Read checks naming a DID: `get_did`, `get_metadata`, `list_content`, `list_files`, `list_parent_dids`, the locks, the dataset replicas (per RSE) and the rules of a DID or of a rule (its DID), ... | `r` on the DID, or owning it; or a metadata permission making it visible (section 7) |
| Reading the data of a DID: `list_replicas` (the PFNs, hence downloading), its current transfer requests (the past ones: root/admin only) | `r` on the DID, or owning it; a metadata permission is **not** enough |
| Listings of a scope, naming no DID: `list_dids`, `scope_list` | some `r` in the scope (section 1); the results are then filtered per DID |
| Listings (results filtered by RBAC): DIDs, content, parents, replicas, locks, rules, ... | each item needs `r` on its DID, or owning it (with `w` on it) |
| Listings of scopes: `list_scopes`, `get_scopes`, ... | some `r` in the scope |
| Items standing for a whole scope: the counts of the bad replicas summary | `r` on the whole scope (`*` name part), withdrawn by no name pattern of that role (section 1) |
| The metadata keys of a DID | every key, unless a metadata permission of the role decides otherwise for some keys (section 7) |
| Prerequisite for: adding a rule, being attached, registering a replica of an existing file (section 5) | `r` on the DID, or owning it |

### `w`: write (creating, and adding content)

| Action | Requires |
|---|---|
| Create a DID: `add_did`, `add_dids`, the new files of an upload or of `add_replicas` | `w` on the new DID; the new DID must belong to the issuer itself (creating for another account: root/admin/scope owner only) |
| Metadata given at creation | ordinary keys and deletion keys (`lifetime`, `expired_at`, `eol_at`, `purge_replicas`): nothing more, the issuer owns the new DID with `w` on it (section 4). Protected keys (section 6): refused |
| Create a sample | `w` on the output DID, plus `r` on the input collection (or owning it) |
| Attach content into a collection | `w` on the collection |
| Detach content from a collection | `w` on the collection, if every detached DID is owned by the issuer (detaching the DIDs of others: `d`, see below) |

`w` does **not** let you write on an existing DID of another account. That needs `d`.
On your own DIDs, `w` makes you their owner (section 4): you may then alter and remove them.

### `d`: overwrite and delete (altering existing DIDs)

Each of these requires `d` on the DID, or owning it (with `w` on it):

| Action | Applies to |
|---|---|
| `set_metadata`, `set_metadata_bulk` (any non-protected key, not recursive) | the DID, unless a metadata permission of the role decides otherwise for some keys (section 7) |
| `delete_metadata` | the DID, same |
| `detach_dids` | the collection: then any content, whoever owns it (`w` only detaches your own DIDs, see above) |

`d` never grants what standard Rucio leaves to root and admins, such as altering rules or the states of replicas (section 6).

## 4. Ownership

- **Who owns:** a DID is owned by its `account`, its creator by default.
- **When ownership counts:** the owner acts as **admin of that DID** only while a role grants the owner `w` on that DID (through the pattern deciding it, section 1). `w` is what lets an account create DIDs and alter or remove its own ones, so withdrawing `w` on a DID also withdraws what owning it grants.
- **Ownership is withdrawn by a pattern:** with `w` on `atlas:*` and `r` (or `none`) on `atlas:file1`, owned, the owner does not administer `atlas:file1`.
- **Without `w` on it, ownership grants nothing,** not even seeing the DID. Example: an account with only `r` on `atlas:calib*` cannot see its own `atlas:x`; with `-w-` on `atlas:x`, it sees and administers it.
- **What ownership never gives:**
  - the protected keys (section 6);
  - recursive metadata;
  - closing a collection;
  - what standard Rucio leaves to root and admins (section 6), e.g. altering its rules or the states of its replicas.
- **Being inside an unreadable collection does not hide an owned DID:** DIDs belong to a scope, and collections only attach them.

## 5. Reading as a prerequisite (RBAC on, every account except root/admin)

| Action | Requires on each DID involved |
|---|---|
| Add a rule (`add_rule`, and the `rules` given to `add_did`/`add_dids`) | `r` on the DID, or owning it (a new DID: `w` on it, as its future owner) |
| Attach DIDs (`attach_dids`, `attach_dids_to_dids`, the `dids` given to `add_did`/`add_dids`), also as scope owner | `r` on each attached DID. With an RSE, a file that doesn't exist yet needs `w` instead (it gets created) |
| Register a replica (`add_replicas`, DIRAC `add_files`), user RSEs only | an existing file: `r` on it. A new file: its creation (`w`) |

## 6. Never granted by a role

A role grants at most what owning a scope grants in standard Rucio: what the generic policy leaves to root and admins
(or to nobody) stays so with RBAC, whatever the roles, the ownership of the scope or of the DID. The
`test_no_role_grants_what_is_left_to_admins` test of `tests/test_role_did_permission.py` checks every such action.

| What | Who can still do it |
|---|---|
| Writing the protected metadata keys (a metadata permission may grant reading them): `name`, `scope`, `account`, `did_type`, `bytes`, `length`, `events`, `adler32`, `md5`, `guid`, `availability`, `complete`, `is_open`, `monotonic`, `obsolete`, `suppressed`, `hidden`, `transient`, `is_archive`, `constituent`, `is_new`, `closed_at`, `deleted_at`, `accessed_at`, `access_cnt`, `created_at`, `updated_at` | root, admins, scope owner |
| Recursive metadata updates (propagated to the whole content) | root, admins, scope owner |
| Creating a DID owned by another account | root, admins, scope owner |
| Closing or reopening a collection (`set_status`) | root, admins, scope owner (reopening: root/admin only) |
| Locked rules, or rules for another account | root, admins |
| Updating, reducing, moving or deleting a rule, even one's own | root, admins |
| Changing the state of a replica, even to finish one's own upload (`rucio upload` then needs `--register-after-upload`) | root, admins |
| Deleting replicas through the API | nobody, as in standard Rucio |
| Getting the past transfer requests of a DID | root, admins |
| Registering replicas on RSEs not ending with `SCRATCHDISK`, `USERDISK`, `MOCK`, `LOCALGROUPDISK` | root, admins |
| Open data add/update/delete | not RBAC: no check at all upstream (left as is) |

## 7. Metadata permissions

```bash
rucio role permission metadata add ROLE DID_PATTERN OPERATIONS [KEY...]   # OPERATIONS: r, w, rw, or none
rucio role permission metadata remove ROLE DID_PATTERN [KEY...]
```

A metadata permission grants `r` (see the key and its value) and `w` (add, modify or delete it) on metadata keys
of the DIDs its pattern matches. Its patterns are those of the DID permissions (section 1), matched the same way,
without inheritance, the most specific one deciding within a role.

- **Keys:** one row per key. `*` covers every key; no key at all gives a row that only makes the DIDs visible,
  so it must be `r`: `w`, `rw` and `none` on no key are refused. Adding replaces the operations a role had on a
  key; `none` (listed `--`) is stored too.
- **Levels of access** to a DID, for an account that owns nothing:

  | Grant | The account |
  |---|---|
  | no row, or DID `---` | sees nothing |
  | metadata `r` on no key | sees the DID listed (scope, name, type, content), no metadata key, no data |
  | metadata `r` on some keys | sees the DID listed with these keys, no data |
  | DID `r` | reads everything, data included |
  | DID `rw`, `rwd` | also writes, alters and deletes (section 3) |

  A metadata `--`, even on every key (`*`), never hides the DID itself: alone it grants nothing, and with DID `r`
  the DID stays listed and its data readable, only its keys being hidden. To keep a DID out of listings, use DID `---`.
- **Within a role, the narrowest subject decides** for each key of each DID: a row naming the key, otherwise a
  row on `*`, otherwise the DID permission of the role deciding the DID (`r` shows every key, `d` lets every
  non-protected key be set). Within a level, the most specific pattern decides: exact name, name prefix, whole
  scope, scope prefix. Example: with DID `rwd` on `atlas:*` and `r` on `atlas:raw*`, the keys of the raw DIDs are
  read-only.
- **Across roles, everything adds up:** a key is readable or writable if one role makes it so. A `--` only
  withdraws a key from the DID permissions of its own role: it never hides what another role shows.
- **Visibility:** a row with `r`, whatever its key, makes the DIDs its pattern matches visible: they are listed,
  their scope too, and read as with `r` (section 3), but only with the keys the rows grant. A row with only `w`
  writes blindly, like `-w-`.
- **What a metadata permission never grants:**
  - the data of a DID: its replicas with their PFNs, downloading it, its transfer requests;
  - `r` as a prerequisite: adding a rule, being attached, registering a replica; nor ownership, which takes DID `w` (section 4);
  - writing the protected keys (section 6), nor the keys leading to a deletion (`lifetime`, `expired_at`,
    `eol_at`, `purge_replicas`), which stay with `d` or ownership. Reading them can be granted.
- **Who bypasses them:** root, admins, the owner of the scope, and the owner of the DID (with DID `w` on it) see
  and write every key, as without metadata permissions.
- **Listings:** the keys an account may not read are left out of what the DID and metadata endpoints return.
  A `list_dids` filter on a key it may not read on a DID leaves that DID out, as if it did not match.

Example, the role `user` of the dev environment (`tools/rbac/db_setup/setup_test_db.py`), held by alice, who has no
DID permission on `physics`:

| Metadata permission | Effect for alice |
|---|---|
| `r` on `datatype`, `project` of `physics:*` | every DID of `physics` is visible, with these two keys only, without its data |
| `rw` on `campaign`, `version` of `physics:raw*` | she also reads and writes these keys on the raw files |
| `--` on `datatype` of `physics:calib.00456789._0001.data` | `datatype` is hidden on that file only |

## 8. Examples

Results from running the real checks of `generic.py` over the world below. Each row gives the result and its reason.

**World (scope `atlas`, owned by root):** alice's narrower patterns repeat the `r` of `atlas:*`, since within a
role the most specific pattern decides alone: `w` alone on `atlas:alice.*` would make her DIDs unreadable through
that pattern.

| Account | Grants |
|---|---|
| alice | `atlas:*` r; `atlas:alice.*` rw; `atlas:shared_ds` rw; `atlas:file1` rd |
| bob | `atlas:bob.*` w (no `r` anywhere) |
| carol | `atlas:calib*` r |

- **DIDs and owners:**
  - root: `file1`, `calib1`, `shared_ds`, `root_ds`;
  - alice: `alice.f1`, `alice.ds`, `alice.up`;
  - bob: `bob.f1`;
  - carol: `carol_file`.
- **Replicas** on `X_USERDISK`:
  - `file1` A, locked by root;
  - `alice.f1` A, locked by alice;
  - `alice.up` C, locked by alice;
  - `bob.f1` C, locked by bob;
  - `carol_file` A, locked by carol and root.
- **Replicas** on `Y_USERDISK`:
  - `file1` C, alice's copy, locked by alice;
  - `calib1` C, carol's copy, locked by carol.
- **Rules:** `r_root_file1` (root), `r_alice_file1` (alice) on `file1`; `r_bob` on `bob.f1`; `r_carol` on `carol_file`.

### DIDs

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `add_did atlas:alice.new` | ✅ | `rw` on `atlas:alice.*` |
| alice | `add_did atlas:other.new` | ❌ | `atlas:*` decides the name: `r` only |
| bob | `add_did atlas:bob.new` | ✅ | `w` on `atlas:bob.*`; creating needs no `r` |
| carol | `add_did atlas:calib2` | ❌ | `r` only |
| alice | `add_did atlas:alice.new`, account bob (also via `add_dids`) | ❌ | creating for another account |
| root | `add_did`, account bob | ✅ | scope owner, as upstream |
| alice | `add_did` with meta `project` | ✅ | ordinary key |
| alice | `add_did` with meta `bytes` | ❌ | protected key |
| alice | `add_did` with meta `lifetime` | ✅ | will own the new DID, with `w` on it |
| bob | `add_did` with meta `lifetime` | ✅ | will own it, with `w` on it, even without `r` |
| alice | `add_did` with a rule of her own | ✅ | will own the new DID |
| bob | `add_did` with a rule of his own | ✅ | will own the new DID |
| alice | `add_did` with a rule for bob | ❌ | rule for another account |
| alice | `add_did`/`add_dids alice.new` with content `file1` | ✅ | `w` on the new DID, `r` on `file1` |
| bob | `add_did`/`add_dids bob.new` with content `file1` | ❌ | bob cannot read `file1` |
| alice | attach `file1` into `shared_ds` (owned by root) | ✅ | `rw` on `shared_ds`, `rd` on `file1` |
| alice | attach `file1` into `root_ds` | ❌ | no `w` on `root_ds` |
| alice | attach `file1` into her `alice.ds` | ✅ | `rw` on `alice.*` |
| alice | attach and register a new file `alice.nf` on an RSE | ✅ | new file: `rw` on `alice.*` |
| alice | attach and register a new file `zz` | ❌ | new file: `atlas:*` decides `zz`, `r` only |
| bob | attach `bob.f1` into `bob.ds` | ✅ | `w` on `bob.ds`; owns `bob.f1`, with `w` on it |
| bob | attach `file1` into `bob.ds` | ❌ | bob cannot read `file1` |
| alice | detach her `alice.f1` from `shared_ds` | ✅ | `rw` on `shared_ds`, and she owns `alice.f1` |
| alice | detach `file1` from `shared_ds` | ❌ | `file1` is root's: removing it needs `d` on `shared_ds` |
| alice | detach `alice.f1` and `file1` from `shared_ds` at once | ❌ | every detached DID must be hers |
| alice | detach from her `alice.ds` | ✅ | owner, `rw` on `alice.*` |
| alice | detach from `file1` | ✅ | `rd` on `file1` |
| alice | `set_metadata project` on her `alice.f1` | ✅ | owner |
| alice | `set_metadata project` on `root_ds` | ❌ | not owner, no `d` |
| alice | `set_metadata project` on `file1` | ✅ | `rd` on `file1` |
| alice | `set_metadata lifetime` on her `alice.f1` | ✅ | owner may delete her own data |
| alice | `set_metadata bytes` on her `alice.f1` | ❌ | protected key |
| alice | `set_metadata` (or bulk), recursive, on her `alice.ds` | ❌ | would rewrite the content unchecked |
| root | `set_metadata`, recursive | ✅ | scope owner, as upstream |
| bob | `set_metadata` on his `bob.f1` | ✅ | owner, with `w` on it |
| carol | `set_metadata` on her `carol_file` | ❌ | owner without `w` on it |
| alice | `delete_metadata` on her `alice.f1` / on `root_ds` | ✅ / ❌ | owner / not owner, no `d` |
| alice | close her `alice.ds` | ❌ | closing is root/admin/scope owner only |
| root | close `alice.ds` | ✅ | scope owner |

### Reading

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `get_metadata atlas:file1` | ✅ | `rd` on `atlas:file1` |
| carol | `get_metadata atlas:calib1` | ✅ | `r` on `atlas:calib*` |
| carol | `get_metadata atlas:file1` | ❌ | not covered |
| carol | `get_metadata` on her `atlas:carol_file` | ❌ | owner without `r` nor `w` on it |
| bob | `get_metadata` on his `atlas:bob.f1` | ✅ | owner, with `w` on it |
| carol | `get_did atlas:calib1` | ✅ | `r` on `atlas:calib*` |
| carol | `list_dids atlas:*`, all types | ✅ | lists `calib1` only: she may not write her `carol_file` |
| carol | `list_content` of `shared_ds` | ❌ | cannot read the collection itself |
| carol | `list_scopes` | ✅ | lists `atlas`, where she reads some DIDs |
| bob | `list_dids atlas:*` | ❌ | no `r` in `atlas` (he still reads his own `bob.f1` by name) |

### Rules

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `add_rule` on `file1` | ✅ | reads `file1` |
| carol | `add_rule` on `file1` / on `calib1` | ❌ / ✅ | cannot / can read it |
| bob | `add_rule` on his `bob.f1` | ✅ | owner, with `w` on it |
| alice | `add_rule` locked, or for bob | ❌ | root/admin only |
| alice | delete, update, reduce or move her own rule | ❌ | root/admin only, as in standard Rucio |
| alice | delete root's `r_root_file1` | ❌ | root/admin only, even with `rd` on `file1` |
| root | delete alice's rule | ✅ | root |

### Replicas

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `add_replicas` of a new file `alice.n` on `X_USERDISK` | ✅ | creation checked as `add_dids` (`w`) |
| alice | `add_replicas` of `file1` on `Y_USERDISK` (a copy) | ✅ | reads `file1` |
| carol | `add_replicas` of `file1` | ❌ | cannot read `file1` |
| alice | `add_replicas` on `X_DATADISK` | ❌ | not a user RSE |
| alice | finish her upload `alice.up`, C to A | ❌ | replica states: root/admin only, as in standard Rucio |
| alice | mark her `alice.f1` U, or `file1` with `rd` on it | ❌ | root/admin only |
| root | finish alice's upload `alice.up` | ✅ | root |
| alice | delete her `alice.f1` replica, or her copy of `file1` | ❌ | nobody deletes replicas through the API, as in standard Rucio |

### The most specific pattern

One role held by alice, on the DIDs `file1`, `calib1`, `secret1` of `atlas` (root's) and `mine` (hers):

| Role | Result | Why |
|---|---|---|
| `rw` on `atlas:*`, `r` on `atlas:file*` | `file1` `r--`, `calib1` `rw-` | the name pattern decides `file1` |
| `r` on `atlas:*`, `w` on `atlas:file*` | `file1` `-w-` | `r` is withdrawn too: give `rw` on `atlas:file*` to keep it |
| `rwd` on `atlas:*`, `r` on `atlas:raw*` | alters `file1`, creates `atlas:other_new`; cannot alter a raw DID, nor create `atlas:raw_new` | the raw DIDs are read-only |
| `rwd` on `atlas:*`, `none` on `atlas:secret*` | `secret1` `---`, `file1` `rwd` | |
| `r` on `atlas:*`, `none` on `atlas:secret*` | `list_dids` lists `file1`, `calib1`, not `secret1`; the bad replicas summary of `atlas` refused | some `r` in the scope, but not on the whole scope |
| `r` on `atlas*:*`, `none` on `atlas:*` | nothing in `atlas`, not even some `r` in it; `r` in `atlas2` | the whole scope beats the scope prefix |
| `w` on `atlas:*`, `none` on `atlas:mine` | alice neither reads nor administers `mine` | she owns it, but the deciding pattern withdraws `w` from it |
| role A: `rwd` on `atlas:*`; role B: `none` on `atlas:*` | `file1` `rwd` | the roles add up |

## 9. Accepted edge cases

By design, change here if needed:
- **No inheritance:** `w` on `atlas:ds1` does not cover new files uploaded into it (`rucio upload --dataset`), and `d` on it does not cover its files: grant the files a pattern of their own, e.g. a name prefix.
- **Uploads finish through the registration:** marking a replica available is left to root and admins, so `rucio upload` needs `--register-after-upload` for a non-admin, as with the generic policy of standard Rucio.
- **Rules and replicas are cleaned by root and admins:** no role lets an account delete its rules or replicas, as with the generic policy of standard Rucio; a policy package may grant it.
- **Listings may look up owners:** each listed DID the account may write but not read costs one lookup of its owner, to know whether it owns it. Accounts with `r` on the whole scope cost nothing more.
- **Rules check the ruled DID only:** a rule on a readable collection copies all its content, including files attached by others that the rule's account cannot read.
- **Attach into a file:** carol passes the permission check to attach into her `carol_file`, but the core refuses attaching into a file.
- **Scope owners keep standard Rucio's power,** e.g. recursive metadata propagated into content of other scopes.
- **Replicas are not checked against their file:** the server does not compare a new replica's size and checksums with the file's, as in standard Rucio.

## 10. Where it lives

- `lib/rucio/core/role.py`:
  - patterns: `_validate_did_pattern`, `_did_pattern_matches`, `_did_pattern_specificity`;
  - DID permissions: `DidAccess` (the most specific pattern of each role, union across roles, whole scope, some DIDs of a scope);
  - metadata permissions: `MetadataPermissionHandler`, `MetadataAccess` (resolution), `has_metadata_visibility`, `can_write_metadata_keys`;
  - checks: `has_did_permission`;
  - "some grant in the scope": `has_any_scope_prefix_access`;
  - which filters the policy package disables: `is_filter_disabled`.
- `lib/rucio/core/permission/generic.py`:
  - constants: `RBAC_*` (protected and deletion keys);
  - ownership: `_owns_did` (owner with `w` on the DID; the owner of the scope is checked on its own, with `is_scope_owner`, as in standard Rucio), `_new_did_owner`;
  - role grants: `rucio.core.role.has_did_permission`, and the helpers shared by several permission functions: `_rbac_can_alter_metadata`, `_rbac_can_attach_dids`;
  - every other check is written in its permission function (`perm_add_did`, `perm_detach_dids`, `perm_add_replicas`, ...);
  - read checks: `perm_read_data` (DIDs, with metadata visibility), `perm_list_replicas` (replicas and transfer requests, DID permissions only);
  - metadata: `_rbac_can_alter_metadata`, `perm_delete_metadata`;
  - listings: `is_listing_filtered`, `did_filter` (per DID), `scope_filter` (per scope, `any_did` for the scope listings), `MetadataKeyFilter` (hidden keys).
- `lib/rucio/core/permission/__init__.py`: the listing filters of the policy package of the VO, falling back to the generic ones
  (`did_filter`, `scope_filter`, `metadata_key_filter`, `is_listing_filtered`), and `filter_dids`, `filter_scopes`, `filter_metadata_keys` for the gateway.
- Tests:
  - `tests/test_role_did_permission.py` (patterns, permission functions, and the actions no role grants);
  - `tests/test_rbac_did_permissions.py` (end to end, through the gateway);
  - `tests/test_rbac_restapi.py` (end to end, through the REST API, on the dev environment), which leaves the database as it found it.
