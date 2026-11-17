# RBAC DID permissions

What a DID permission grants, as implemented on `rbac/main`.
Everything here applies only when RBAC is enabled: with RBAC off, the generic policy behaves exactly as standard Rucio.

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
- **Reading:** an account reads the DIDs on which a role grants `r` (through the pattern deciding them), plus the DIDs it owns in a scope where it has some `r`. Example: `r` on `atlas:calib*` reads `atlas:calib1`, and `atlas:x` if it owns it, but not `atlas:file1`.
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
| root, admins (the `admin` role) | everything, as in standard Rucio |
| owner of the scope | everything in the scope (standard Rucio), except that with RBAC on, attached DIDs and rule targets must be readable (section 5) |
| owner of a DID or a rule | see section 4 |

## 3. What each operation grants on the DIDs a pattern matches

### `r`: read

| Action | Granted by |
|---|---|
| Read checks naming a DID: `get_did`, `get_metadata`, `list_content`, `list_files`, `list_parent_dids`, the locks, the dataset replicas (per RSE) and the rules of a DID or of a rule (its DID), ... | `r` on the DID, or owning it; or a metadata permission making it visible (section 7) |
| Reading the data of a DID: `list_replicas` (the PFNs, hence downloading), its transfer requests, current and past | `r` on the DID, or owning it; a metadata permission is **not** enough |
| Listings of a scope, naming no DID: `list_dids`, `scope_list` | some `r` in the scope (section 1); the results are then filtered per DID |
| Listings (results filtered by RBAC): DIDs, content, parents, replicas, locks, rules, ... | each item needs `r` on its DID, or owning it (some `r` in its scope) |
| Listings of scopes: `list_scopes`, `get_scopes`, ... | some `r` in the scope |
| Items standing for a whole scope: the counts of the bad replicas summary | `r` on the whole scope (`*` name part), withdrawn by no name pattern of that role (section 1) |
| The metadata keys of a DID | every key, unless a metadata permission of the role decides otherwise for some keys (section 7) |
| Prerequisite for: adding a rule, being attached, registering a replica of an existing file (section 5) | `r` on the DID, or owning it |

### `w`: write (creating, and adding content)

| Action | Requires |
|---|---|
| Create a DID: `add_did`, `add_dids`, the new files of an upload or of `add_replicas` | `w` on the new DID; the new DID must belong to the issuer itself (creating for another account: root/admin/scope owner only) |
| Metadata given at creation | ordinary keys: nothing more. Deletion keys (`lifetime`, `expired_at`, `eol_at`, `purge_replicas`): `d`, or owning the new DID (some `r` in the scope). Protected keys (section 6): refused |
| Create a sample | `w` on the output DID, plus `r` on the input collection (or owning it) |
| Attach content into a collection | `w` on the collection, or owning it |
| Detach content from a collection | `w` on the collection, if every detached DID is owned by the issuer (detaching the DIDs of others: `d`, see below) |
| Finish an upload: mark a replica, in `C` (copying), as `A` (available), with no new path | what registering it requires: `w` on a file you own, or `r` on the file (copy of an existing file) |

`w` does **not** let you write on an existing DID of another account. That needs `d` (or ownership).
The only removal `w` grants is taking your own DIDs back out of a collection you may write into.

### `d`: overwrite and delete (altering existing DIDs)

Each of these requires `d` on the DID, or owning it:

| Action | Applies to |
|---|---|
| `set_metadata`, `set_metadata_bulk` (any non-protected key, not recursive) | the DID, unless a metadata permission of the role decides otherwise for some keys (section 7) |
| `delete_metadata` | the DID, same |
| `detach_dids` | the collection: then any content, whoever owns it (`w` only detaches your own DIDs, see above) |
| Update (only `lifetime`, `comment`, `notify`, `purge_replicas`), reduce, move or delete a rule | the rule's DID, or owning the rule |
| Change the state (any state) or the path of a replica, other than finishing an upload | the file; replica RSEs only, see below |
| Delete replicas | the file; replica RSEs only, see below |

Replica RSEs are those whose name ends with `SCRATCHDISK`, `USERDISK`, `MOCK` or `LOCALGROUPDISK`. On any replica held by **another account's rule**, no role grants a state change or a deletion. State changes there are root/admin only; replica deletion through the API is refused to everyone, as in standard Rucio.

Moving a rule also requires that the new rule is not locked and belongs to the account itself.

## 4. Ownership

- **Who owns:** a DID is owned by its `account`, its creator by default; a rule by its account.
- **When ownership counts:** the owner acts as **admin of that DID or rule** only if a role grants the owner some `r` in its scope (section 1). `r` on any name pattern of the scope is enough (e.g. `atlas:calib*` for an owned `atlas:file1`).
- **Ownership is not withdrawn by a pattern:** with some `r` in the scope, the owner administers its DID even if a pattern of a role grants nothing on it (e.g. `r` on `atlas:calib*` and `none` on `atlas:file1`, owned).
- **Without `r` in the scope, ownership grants nothing,** not even seeing the DID. Example: an account with only `-w-` on `atlas` can create `atlas:x`, but cannot see or administer it afterwards.
- **What ownership never gives:**
  - the protected keys (section 6);
  - recursive metadata;
  - deleting a replica, or changing its state, while another account's rule holds it;
  - closing a collection.
- **Being inside an unreadable collection does not hide an owned DID:** DIDs belong to a scope, and collections only attach them.
- **Exception:** finishing your own upload needs only `w` + owning the file, even without `r` in the scope.

## 5. Reading as a prerequisite (RBAC on, every account except root/admin)

| Action | Requires on each DID involved |
|---|---|
| Add a rule (`add_rule`, and the `rules` given to `add_did`/`add_dids`) | `r` on the DID, or owning it (a new DID: owning it once created) |
| Attach DIDs (`attach_dids`, `attach_dids_to_dids`, the `dids` given to `add_dids`), also as scope owner | `r` on each attached DID. With an RSE, a file that doesn't exist yet needs `w` instead (it gets created) |
| Register a replica (`add_replicas`, DIRAC `add_files`), user RSEs only | an existing file: `r` on it. A new file: its creation (`w`) |

## 6. Never granted by a role

| What | Who can still do it |
|---|---|
| Writing the protected metadata keys (a metadata permission may grant reading them): `name`, `scope`, `account`, `did_type`, `bytes`, `length`, `events`, `adler32`, `md5`, `guid`, `availability`, `complete`, `is_open`, `monotonic`, `obsolete`, `suppressed`, `hidden`, `transient`, `is_archive`, `constituent`, `is_new`, `closed_at`, `deleted_at`, `accessed_at`, `access_cnt`, `created_at`, `updated_at` | root, admins, scope owner |
| Recursive metadata updates (propagated to the whole content) | root, admins, scope owner |
| Creating a DID owned by another account | root, admins, scope owner |
| Closing or reopening a collection (`set_status`) | root, admins, scope owner (reopening: root/admin only) |
| Locked rules, or rules for another account (add or move) | root, admins |
| Updating rule options other than `lifetime`, `comment`, `notify`, `purge_replicas` | root, admins |
| Deleting a replica, or changing its state, while another account's rule holds it | state changes: root/admin. Deletion through the API: nobody, as in standard Rucio |
| Anything on RSEs not ending with `SCRATCHDISK`, `USERDISK`, `MOCK`, `LOCALGROUPDISK` (replica registration, state, deletion) | root, admins |
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
  - `r` as a prerequisite: adding a rule, being attached, registering a replica, ownership (section 4);
  - writing the protected keys (section 6), nor the keys leading to a deletion (`lifetime`, `expired_at`,
    `eol_at`, `purge_replicas`), which stay with `d` or ownership. Reading them can be granted.
- **Who bypasses them:** root, admins, the owner of the scope, and the owner of the DID (with some `r` in its
  scope) see and write every key, as without metadata permissions.
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
| alice | `add_did` with meta `lifetime` | ✅ | owns the new DID and reads `atlas` |
| bob | `add_did` with meta `lifetime` | ❌ | owns it but no `r` in `atlas`, no `d` |
| alice | `add_did` with a rule of her own | ✅ | reads `atlas` |
| bob | `add_did` with a rule of his own | ❌ | a rule needs `r` |
| alice | `add_did` with a rule for bob | ❌ | rule for another account |
| alice | `add_dids alice.new` with content `file1` | ✅ | `w` on the new DID, `r` on `file1` |
| alice | attach `file1` into `shared_ds` (owned by root) | ✅ | `rw` on `shared_ds`, `rd` on `file1` |
| alice | attach `file1` into `root_ds` | ❌ | no `w`, not owner |
| alice | attach `file1` into her `alice.ds` | ✅ | `rw` on `alice.*` (and owner) |
| alice | attach and register a new file `alice.nf` on an RSE | ✅ | new file: `rw` on `alice.*` |
| alice | attach and register a new file `zz` | ❌ | new file: `atlas:*` decides `zz`, `r` only |
| bob | attach `bob.f1` into `bob.ds` | ❌ | bob reads nothing, so he can't attach |
| alice | detach her `alice.f1` from `shared_ds` | ✅ | `rw` on `shared_ds`, and she owns `alice.f1` |
| alice | detach `file1` from `shared_ds` | ❌ | `file1` is root's: removing it needs `d` on `shared_ds` |
| alice | detach `alice.f1` and `file1` from `shared_ds` at once | ❌ | every detached DID must be hers |
| alice | detach from her `alice.ds` | ✅ | owner, reads `atlas` |
| alice | detach from `file1` | ✅ | `rd` on `file1` |
| alice | `set_metadata project` on her `alice.f1` | ✅ | owner |
| alice | `set_metadata project` on `root_ds` | ❌ | not owner, no `d` |
| alice | `set_metadata project` on `file1` | ✅ | `rd` on `file1` |
| alice | `set_metadata lifetime` on her `alice.f1` | ✅ | owner may delete her own data |
| alice | `set_metadata bytes` on her `alice.f1` | ❌ | protected key |
| alice | `set_metadata` (or bulk), recursive, on her `alice.ds` | ❌ | would rewrite the content unchecked |
| root | `set_metadata`, recursive | ✅ | scope owner, as upstream |
| bob | `set_metadata` on his `bob.f1` | ❌ | owner without `r` in `atlas` |
| alice | `delete_metadata` on her `alice.f1` / on `root_ds` | ✅ / ❌ | owner / not owner, no `d` |
| alice | close her `alice.ds` | ❌ | closing is root/admin/scope owner only |
| root | close `alice.ds` | ✅ | scope owner |

### Reading

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `get_metadata atlas:file1` | ✅ | `rd` on `atlas:file1` |
| carol | `get_metadata atlas:calib1` | ✅ | `r` on `atlas:calib*` |
| carol | `get_metadata atlas:file1` | ❌ | not covered |
| carol | `get_metadata` on her `atlas:carol_file` | ✅ | owner, reads `atlas` |
| bob | `get_metadata` on his `atlas:bob.f1` | ❌ | owner without `r` in `atlas` |
| carol | `get_did atlas:calib1` | ✅ | `r` on `atlas:calib*` |
| carol | `list_dids atlas:*`, all types | ✅ | lists `calib1` and her `carol_file` only |
| carol | `list_content` of `shared_ds` | ❌ | cannot read the collection itself |
| carol | `list_scopes` | ✅ | lists `atlas`, where she reads some DIDs |
| bob | `list_dids atlas:*` | ❌ | no `r` in `atlas`, not even his own `bob.f1` |

### Rules

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `add_rule` on `file1` | ✅ | reads `file1` |
| carol | `add_rule` on `file1` / on `calib1` | ❌ / ✅ | cannot / can read it |
| bob | `add_rule` on his `bob.f1` | ❌ | owner without `r` in `atlas` |
| alice | `add_rule` locked, or for bob | ❌ | root/admin only |
| alice | delete her `r_alice_file1` | ✅ | rule owner, reads `atlas` |
| alice | delete root's `r_root_file1` | ✅ | `rd` on `file1` |
| alice | delete bob's `r_bob` | ❌ | not owner, no `d` on `bob.f1` |
| bob | delete his `r_bob` | ❌ | owner without `r` in `atlas` |
| carol | delete her `r_carol` | ✅ | owner, reads `atlas` (through `calib*`) |
| alice | update her rule's comment / bob's rule's comment | ✅ / ❌ | owner / not owner, no `d` |
| alice | update her rule's `copies` or `account` | ❌ | option not updatable through roles |
| alice | reduce or move her rule | ✅ | owner |
| alice | move her rule as locked, or to bob | ❌ | root/admin only |
| alice | move root's `r_root_file1` to herself | ✅ | `rd` on `file1` |

### Replicas

| Who | Action | Result | Why |
|---|---|---|---|
| alice | `add_replicas` of a new file `alice.n` on `X_USERDISK` | ✅ | creation checked as `add_dids` (`w`) |
| alice | `add_replicas` of `file1` on `Y_USERDISK` (a copy) | ✅ | reads `file1` |
| carol | `add_replicas` of `file1` | ❌ | cannot read `file1` |
| alice | `add_replicas` on `X_DATADISK` | ❌ | not a user RSE |
| alice | finish her upload `alice.up`, C to A | ✅ | owner |
| bob | finish his upload `bob.f1`, C to A | ✅ | `w` + owner, even without `r` |
| alice | finish her copy of `file1` on `Y_USERDISK`, C to A | ✅ | may register the copy, so may finish it |
| carol | finish her copy of `calib1` on `Y_USERDISK`, C to A | ✅ | reads `calib1` |
| carol | same, with a new path / set to `U` | ❌ | not finishing an upload: needs `d` or owner |
| carol | mark bob's `bob.f1` A | ❌ | held by bob's rule |
| alice | mark `file1` U on `X_USERDISK` | ❌ | held by root's rule: admin only, even with `d` |
| alice | mark her `alice.f1` B, or give it a new path | ✅ | owner, only her own lock |
| carol | mark her `carol_file` U | ❌ | also held by root's rule |
| alice | delete her `alice.f1` replica | ✅ | owner, only her own lock |
| alice | delete `file1` on `X_USERDISK` | ❌ | held by root's rule, even with `d` |
| alice | delete her copy of `file1` on `Y_USERDISK` | ✅ | `rd` on `file1`, only her own lock |
| bob | delete his `bob.f1` replica | ❌ | owner without `r` in `atlas` |
| alice | delete on `X_DATADISK` | ❌ | not a user RSE |

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
| `r` on `atlas:calib*`, `none` on `atlas:mine` | alice reads and administers `mine` | she owns it, and has some `r` in `atlas` |
| role A: `rwd` on `atlas:*`; role B: `none` on `atlas:*` | `file1` `rwd` | the roles add up |

## 9. Accepted edge cases

By design, change here if needed:
- **No inheritance:** `w` on `atlas:ds1` does not cover new files uploaded into it (`rucio upload --dataset`), and `d` on it does not cover its files: grant the files a pattern of their own, e.g. a name prefix.
- **Uploads need `r`:** `rucio upload` adds a rule, so bob (`-w-` only) cannot upload: the DID creation passes, the rule is refused.
- **Copies can't be cleaned by their uploader:** carol cannot delete her own copy of `calib1`, since she neither owns `calib1` nor has `d` on it. Once her rule is removed, the reaper cleans the copy.
- **Listings may look up owners:** for an account reading through name patterns, each listed DID that no pattern matches costs one lookup of its owner. Accounts with `r` on the whole scope cost nothing more.
- **Rules check the ruled DID only:** a rule on a readable collection copies all its content, including files attached by others that the rule's account cannot read.
- **Attach into a file:** carol passes the permission check to attach into her `carol_file`, but the core refuses attaching into a file.
- **Scope owners keep standard Rucio's power,** e.g. recursive metadata propagated into content of other scopes.
- **Replicas are not checked against their file:** the server does not compare a new replica's size and checksums with the file's, as in standard Rucio.

## 10. Where it lives

- `lib/rucio/core/role.py`:
  - patterns: `_validate_did_pattern`, `_did_pattern_matches`, `_did_pattern_specificity`;
  - DID permissions: `DidAccess` (the most specific pattern of each role, union across roles, whole scope, some DIDs of a scope);
  - metadata permissions: `MetadataPermissionHandler`, `MetadataAccess` (resolution), `MetadataKeyFilter` (hidden keys), `has_metadata_visibility`;
  - requests: `DidPermissionRequest`, `has_permission`;
  - "some grant in the scope": `has_any_scope_prefix_access`;
  - listings: `did_access_checker`, `filter_iterable_by_did_access` (per DID), `scope_access_checker`, `filter_iterable_by_scope_access` (per scope, `any_did` for the scope listings).
- `lib/rucio/core/permission/generic.py`:
  - constants: `RBAC_*` (protected and deletion keys, rule options, replica RSE suffixes);
  - ownership: `_owns_did` (the owner of the scope is checked on its own, with `is_scope_owner`, as in standard Rucio);
  - role grants: `_rbac_permission_access`, and the helpers shared by several permission functions: `_rbac_can_alter_rule`, `_rbac_can_alter_metadata`, `_rbac_can_attach_dids`;
  - every other check is written in its permission function (`perm_add_did`, `perm_detach_dids`, `perm_add_replicas`, `perm_update_replicas_states`, ...);
  - read checks: `perm_read_data` (DIDs, with metadata visibility), `perm_list_replicas` (replicas and transfer requests, DID permissions only);
  - metadata: `_rbac_can_alter_metadata`, `perm_delete_metadata`.
- Tests:
  - `tests/test_role_did_permission.py` (patterns, permission functions);
  - `tests/test_rbac_restapi.py` (end to end), which leaves the database as it found it.
