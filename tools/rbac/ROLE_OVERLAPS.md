# RBAC: overlapping permissions and roles

What an account gets when several permissions or several roles cover the same DID, metadata key or RSE, as
implemented on `rbac/main`. Everything here applies only when RBAC is enabled; with RBAC off, Rucio behaves as
standard Rucio. What each permission grants on its own is in `DID_PERMISSIONS.md`.
The gateway always asks the permission policy, whether RBAC is enabled or not: deciding with or without RBAC is the
policy's business. A policy package which denies the actions it does not know has to grant the new ones.

The non-obvious rows were checked against the real code of `rucio.core.role` and
`rucio.core.permission.generic`.

## 0. The rules in short

| | Within one role | Across the roles of an account |
|---|---|---|
| **DID** | the most specific matching pattern decides: its row gives every operation the role grants on the DID | the roles add up |
| **Metadata** | the narrowest subject decides: a row naming the key, then a row on every key (`*`), then the DID permission of the role deciding the DID; within a level, the most specific DID pattern | the roles add up: a key is readable (writable) if one role makes it readable (writable) |
| **DID vs metadata** | metadata decides on the keys it names, the DID permissions on the rest and on the DID itself | the roles add up; metadata permissions never grant the data of a DID, nor count as DID READ or WRITE |
| **Limits** | one local limit per RSE; its global limits only restrict it | on an RSE, the role leaving the most space is taken; the account limits only apply where no role has a local limit |

Common to everything:

- **Roles only grant.** No role can take away what another role grants: there is no deny. Within a role, a
  narrower pattern can grant less than a wider one, down to nothing (`---` for a DID permission, `--` for a
  metadata permission), but only *for that role*.
- **Specificity, from the most to the least specific:** an exact name (`atlas:file1`), a name prefix
  (`atlas:file*`), a whole scope (`atlas:*`), a scope prefix (`atlas*:*`), a longer prefix being more specific.
- **Only active assignments count.** A role whose assignment has not started yet (`activates_at` in the
  future) or has expired grants nothing at all.
- **Some accounts are never limited by roles:** root, admins (the reserved `admin` role, or the `admin` account
  attribute) and the owner of the scope. The owner of a DID is too, on that DID, while some role gives it WRITE
  on that DID (section 1.4). None of them gets from a role what standard Rucio leaves to root and admins, such as
  altering rules or the states of replicas.

The examples use the account **alice**, holding the roles A and B, on the scope **atlas**, owned by root,
whose DIDs `file1`, `file2`, `calib1` and the collection `ds1` are owned by root, and `mine` by alice.
A DID permission is written `r`, `w`, `d` (`---` for none) and a metadata permission `r`, `w`, `rw`, `--`.

---

## 1. DID permissions within the same role

Within a role, the most specific pattern matching a DID decides: its row gives **every** operation the role grants
on that DID, and the other rows matching it are not looked at. A narrower pattern can therefore grant more or less
than a wider one. The order the rows were added in does not matter.

### 1.1 Patterns covering the same DIDs

| Role A | `atlas:file1` gets | `atlas:calib1` gets | Why |
|---|---|---|---|
| `r` on `atlas:*`, `r` on `atlas:file*` | `r--` | `r--` | redundant rows |
| `r` on `atlas*:*`, `rw` on `atlas:*` | `rw-` | `rw-` | `atlas:*` is more specific than `atlas*:*` |
| `rw` on `atlas:*`, `r` on `atlas:file*` | `r--` | `rw-` | the name pattern decides `file1`: a read-only area within a writable scope |
| `r` on `atlas:*`, `w` on `atlas:file*` | `-w-` | `r--` | the rows do **not** add up: `r` is withdrawn from `file1` too. Grant `rw` on `atlas:file*` to keep it |
| `r` on `atlas:file1`, `d` on `atlas:*` | `r--` | `--d` | an exact name beats the whole scope |
| `d` on `atlas:fi*`, `r` on `atlas:file*` | `r--` | nothing | the longer prefix decides |
| `rwd` on `atlas:*`, `---` on `atlas:file*` | `---` | `rwd` | a row granting nothing withdraws the DIDs it matches: not even listed, as with no row |
| `w` on `atlas:file*` | `-w-` | nothing | a name pattern only covers the names it matches |

The CLI warns when a new row withdraws operations a wider row of the same role grants, e.g. `atlas:file* (r--) is
more specific than atlas:* (rw-) [...]: w withdrawn from them`, and tells which row decides again when one is removed.

### 1.2 The operations are independent

| Role A | Result on `atlas:file1` | Why |
|---|---|---|
| `d` only | can set its metadata and detach its content, **without seeing it** | `d` does not imply `r` |
| `w` only | can attach into it (as a collection) and create DIDs whose name matches, without seeing them | `w` does not imply `r` |
| `d` only, then "add a rule" | refused | a rule needs `r` on its DID |
| `r` only, then "set metadata" | refused | altering an existing DID needs `d` (or owning it, with `w` on it) |
| `rd` | can see and alter it, but not attach into it (as a collection) | `d` does not imply `w` |

### 1.3 Name patterns and whole scopes

| Role A | Result | Why |
|---|---|---|
| `r` on `atlas:file*` | `list_dids atlas:*` and `list_scopes` show `atlas`, then only the matching DIDs | a scope is accessible as soon as a pattern touches it; the listings are filtered per DID |
| `r` on `atlas:file*` | items standing for the whole scope (e.g. the bad replicas summary) are refused | only a `*` name part (`atlas:*`, `atlas*:*`) grants the whole scope |
| `r` on `atlas:*`, `---` on `atlas:secret*` | `list_dids atlas:*` lists every DID but the `secret*` ones; the whole-scope items are refused | the whole scope is only granted if no name pattern of the role withdraws the operation |
| `r` on `atlas:*`, `rw` on `atlas:raw*` | the whole-scope items are shown | no name pattern withdraws `r` |
| `r` on `atlas*:*`, `---` on `atlas:*` | nothing in `atlas`, not even listing it; `atlas2` readable | `atlas:*` decides the whole scope `atlas` |
| `r` on `atlas:ds1` | the files inside `ds1` are **not** readable | no inheritance: a pattern matches the DID itself, not its content |
| `w` on `atlas:ds1` | can attach into `ds1`; a file uploaded into it is not covered | same |

### 1.4 Ownership

The owner of a DID (its `account`) acts as admin of it only while a role gives it WRITE on that DID, through the
pattern deciding it (section 1.1). Withdrawing WRITE on a DID withdraws what owning it grants.

| Role A | `atlas:mine` (owned by alice) | Why |
|---|---|---|
| `w` on `atlas:mine` | readable, and alterable: metadata, detaching, deletion keys | WRITE on the DID |
| `w` on `atlas:*` | same | the whole-scope pattern decides `mine` |
| `w` on `atlas:*`, `---` on `atlas:mine` | **nothing** | the deciding pattern withdraws WRITE: ownership is withdrawn too |
| `r` on `atlas:mine` | readable only, not alterable | READ is not WRITE: owner without WRITE |
| `r` on `atlas:calib*` | **nothing**, not even seeing it | READ elsewhere in the scope gives nothing on `mine` |
| `w` on `atlas:file*` | **nothing** | WRITE elsewhere in the scope gives nothing on `mine` either |
| metadata `r` on `atlas:*` only | visible (section 5), but **not** owner-admin | metadata READ is not DID WRITE |
| any role | never: altering its rules, changing the states of its replicas | left to root and admins, as in standard Rucio |

### 1.5 Collections

| Role A | On the collection `atlas:ds1` (owned by root) | Why |
|---|---|---|
| `w` on `atlas:ds1`, `r` on `atlas:file1` | can attach `file1` into `ds1` | `w` on the collection and `r` on what is attached |
| `w` on `atlas:ds1`, no `r` on `atlas:file2` | cannot attach `file2` | attached DIDs must be readable |
| `w` on `atlas:ds1` | can detach the DIDs alice owns (with `w` on them), not those of others | `w` only takes your own DIDs back |
| `d` on `atlas:ds1` | can detach any content | `d` alters the collection |
| `w` on `atlas:ds1` | cannot close or reopen it | closing is root/admin/scope owner only |

---

## 2. DID permissions across different roles

Across roles, everything adds up: each role decides a DID on its own (section 1), and the account gets the union of
what its active roles grant. A `---` in one role never hides what another role grants.

| Role A | Role B | Result | Why |
|---|---|---|---|
| `r` on `atlas:file1` | `w` on `atlas:file1` | `rw` on `file1` | union |
| `r` on `atlas:*` | `d` on `atlas:file1` | reads everything, alters `file1` only | union |
| `r` on `atlas:*` | `r` on `atlas:*` | `r` | redundant |
| `rwd` on `atlas:*` | nothing on `atlas` | `rwd` | B cannot restrict A: there is no deny |
| `rwd` on `atlas:*` | `---` on `atlas:*` | `rwd` | a `---` only withdraws within its own role |
| `r` on `atlas:*`, `---` on `atlas:file*` | `w` on `atlas:file1` | `-w-` on `file1` | A grants nothing on `file1`, B grants `w` |
| `r` on `atlas:calib*` | `w` on `atlas:mine*` | alice creates `atlas:mine2` and administers it afterwards | ownership needs WRITE on the DID, from *any* role |
| `r` on `atlas:*` | `w` on `atlas:new*` | can create `atlas:new1` with `lifetime` in its metadata, and a rule on it | she will own it, with WRITE on it from B |
| `rw` on `atlas:*` (expired) | `w` on `atlas:file*` | `-w-` on `file1`; `mine` neither readable nor administered | an expired assignment grants nothing, B gives no WRITE on `mine` |
| `r` on `atlas:*` (activates tomorrow) | none | nothing until tomorrow | same |

---

## 3. Metadata permissions within the same role

For each key of each DID, a role decides on its own, in this order:

1. its metadata rows **naming that key** whose DID pattern matches the DID;
2. otherwise, its rows on **every key** (`*`) whose pattern matches;
3. otherwise, its **DID permission deciding the DID** (section 1): DID READ shows the key, DID DELETE lets it be set.

Within levels 1 and 2, the **most specific DID pattern** decides: an exact name (`atlas:file1`), then a name
prefix (`atlas:file*`), then a whole scope (`atlas:*`), then a scope prefix (`atlas*:*`), a longer prefix
being more specific. The deciding row's operations are exact: `--` grants nothing, `r` only reads.

### 3.1 The same key on several patterns

| Role A (all on the key `quality`) | `quality` on `file1` | on `file2` | on `calib1` | Why |
|---|---|---|---|---|
| `rw` on `atlas:*`, `--` on `atlas:file*`, `r` on `atlas:file1` | `r` | `--` | `rw` | the most specific matching pattern decides |
| `rw` on `atlas*:*`, `r` on `atlas:*` | `r` | `r` | `r` | `atlas:*` is more specific than `atlas*:*` |
| `--` on `atlas:*`, `rw` on `atlas:file1` | `rw` | `--` | `--` | |

### 3.2 A key against every key (`*`)

| Role A | `quality` on `file1` | other keys on `file1` | Why |
|---|---|---|---|
| `rw` on `*` of `atlas:file1`, `r` on `quality` of `atlas:*` | `r` | `rw` | a row naming the key beats `*`, **even with a less specific pattern** |
| `--` on `*` of `atlas:*`, `r` on `quality` of `atlas:file1` | `r` | `--` | |
| `r` on `*` of `atlas:*`, `--` on `quality` of `atlas:*` | `--` | `r` | |

### 3.3 Metadata permissions against the DID permissions of the role

| Role A | `quality` on `file1` | other keys | DID itself | Why |
|---|---|---|---|---|
| DID `r` on `atlas:*`, metadata `--` on `quality` of `atlas:file1` | `--` | `r` | visible, data readable | the row withdraws the key from the DID READ |
| DID `r` on `atlas:*`, metadata `--` on `*` of `atlas:file1` | `--` | `--` | visible, data readable | hiding every key hides no DID nor its data |
| DID `r`, metadata `rw` on `quality` | `rw` | `r` | | the row grants more than the DID permission |
| DID `rwd`, metadata `r` on `quality` | `r` | `rw` | | the row grants less than DID DELETE on that key |
| DID `rwd` on `atlas:*`, `r` on `atlas:file*` | `r` | `r` | visible, not alterable | the keys fall back to the deciding DID permission, `r` on `atlas:file*` |
| DID `r`, metadata `rw` on `quality` of `atlas:file1`, then one call setting `quality` and `campaign` | refused | | | every key of the call must be writable; `campaign` falls back to DID READ only |

### 3.4 Metadata permissions alone

| Role A | Result on `file1` | Why |
|---|---|---|
| `r` on `quality` | visible, only `quality` shown (plus its scope, name and type), no data | a READ row makes the DID visible |
| `r` on no key | visible, no key shown, no data | the no-key permission only makes DIDs visible |
| `--` (or `w`) on no key | refused when granting it | a permission on no key only makes DIDs visible, so it is `r` |
| `--` on `*` | nothing at all, not even listed | `--` never makes a DID visible; use DID `---` to hide DIDs within a role |
| `rw` on `quality` | visible, `quality` readable and writable | |
| `-w` on `quality` | **not visible**, `quality` writable blindly | like DID `-w-` |
| `--` on `quality` | nothing at all | `--` alone grants nothing |

### 3.5 Keys Rucio holds, and keys leading to a deletion

| Role A | Result | Why |
|---|---|---|
| metadata `r` on `bytes` (protected) | `bytes` readable, the DID visible | protected keys behave like any key for READ |
| metadata `rw` on `*` | every key writable **but** the protected ones and the deletion keys | `*` never covers what no metadata permission may write |
| metadata `w` on `bytes` or `lifetime` | refused when granting it | no metadata permission writes them |
| DID `rd`, metadata `--` on `lifetime` of `atlas:file1` | `lifetime` hidden, **but still settable** | a deletion key is set through the DID (DELETE or ownership), whatever the metadata rows say |
| DID `rwd` | protected keys still not writable | only root, admins and the scope owner set them |

### 3.6 Owners

| Role A | `atlas:mine` (owned by alice) | Why |
|---|---|---|
| DID `w` on `atlas:mine`, metadata `--` on `*` of `atlas:*` | every key readable and writable | the owner (with DID WRITE on it) bypasses the metadata rows |
| metadata `r` on no key of `atlas:*` only | visible, but its keys not writable | without DID WRITE on it, owning gives nothing |

---

## 4. Metadata permissions across different roles

Each role decides on its own as in section 3, then the roles add up: a key is readable if one role makes it
readable, and writable if one role makes it writable. A `--` in one role never hides what another role
shows.

| Role A | Role B | `quality` on `file1` | other keys | Why |
|---|---|---|---|---|
| DID `r` | metadata `--` on `quality` | `r` | `r` | B grants nothing on `quality`, A's DID READ shows it |
| DID `r` | metadata `--` on `*` | `r` | `r` | same, for every key |
| DID `r`, metadata `--` on `quality` | metadata `rw` on `quality` | `rw` | `r` | A hides it, B grants it |
| DID `rwd` | metadata `--` on `quality` | `rw` | `rw` | A's DID DELETE lets the key be set |
| metadata `r` on `quality` | metadata `w` on `quality` | `rw` | `--` | the operations of the roles add up |
| metadata `r` on `quality` of `atlas:*` | metadata `--` on `quality` of `atlas:file1` | `r` | `--` | specificity only applies within a role |
| metadata `rw` on `*` | metadata `r` on `quality` | `rw` | `rw` | within A, `*` decides `quality`; B adds nothing |
| metadata `-w` on `quality` | nothing | `-w`, DID not visible | | |
| metadata `-w` on `quality` | DID `r` | `rw`, DID visible | `r` | |

**Listings with filters:** `rucio did list --filter 'quality=gold'` only lists a DID if `quality` is readable
on it, under the union of all roles. With A: DID `r`, metadata `--` on `quality` and nothing else, `file1`
is never listed by that filter, whatever its value.

**Consequence:** to restrict a key, put the `--` in the role that grants it. A role made only of `--` rows
restricts nothing.

---

## 5. DID and metadata permissions across different roles

What makes a DID visible, its keys readable or writable, adds up across roles. What metadata permissions never
give, whatever the other roles hold:

- the **data** of a DID: its replicas with their PFNs (`list_replicas`), downloading it, its transfer requests;
- **READ** for the prerequisites: adding a rule, being attached, registering a replica;
- **WRITE** for ownership.

| Role A | Role B | Result on `file1` | Why |
|---|---|---|---|
| DID `r` | metadata `--` on `quality` | visible, every key readable, data readable | B restricts nothing |
| metadata `r` on `quality` | DID `r` on `atlas:file1` | `file1`: every key, data; `file2`: visible, `quality` only, no data | each DID on its own |
| metadata `r` on `*` of `atlas:*` | nothing | every DID of `atlas` visible with every key, no data, no download | metadata READ is not data |
| metadata `r` on `*` of `atlas:*` | DID `w` on `atlas:*` | can create DIDs and use her own ones (rules, attaching them), but neither add rules on nor attach the DIDs of others | prerequisites need DID READ, or owning the DID (DID WRITE on it, from B) |
| metadata `r` on `atlas:*` | — | alice **is not** admin of her `atlas:mine` | ownership needs DID WRITE on it |
| metadata `r` on `atlas:*` | DID `w` on `atlas:mine` | alice administers her `atlas:mine` | B gives WRITE on it |
| metadata `rw` on `quality` | DID `d` on `atlas:file1` | `quality` writable; every other non-protected key writable through B | B's DID DELETE |
| metadata `r` on `atlas:ds1` | DID `r` on `atlas:file1` | content of `ds1`: lists `file1` (B), not `file2` | the content of a visible collection is filtered per child |
| metadata `r` on `atlas:*` | nothing | `list_scopes` shows `atlas`; `list_dids atlas:*` lists its DIDs | visibility counts for the scope listings |
| metadata `r` on `atlas:*` | nothing | rules and locks of `file1` listed, its dataset replicas (per RSE) listed, file replicas refused | RSE-level only |

---

## 6. Limits across different roles

Within a role, an RSE may be written to only if a **local** limit of the role covers it, and only as long as
every **global** limit of that role covering it still has room. Across roles:

1. the roles with a local limit on the RSE are the candidates; the others are ignored for that RSE;
2. for each candidate, the space left is the smallest of what its local limit and each of its global limits
   covering the RSE leave;
3. **the role leaving the most space is taken**;
4. if no role has a local limit on the RSE, the **account limits** apply, as in standard Rucio; if one does,
   the account limits are not looked at, local nor global.

The usage is the account's own: each account holding a role gets the whole limit for itself, measured against
everything it uses on the RSE, whichever role it was written under.

In the examples, alice uses 3 GB on RSE1 and 4 GB on RSE2.

| Role A | Role B | Space left for alice on RSE1 | Why |
|---|---|---|---|
| local 5 GB on RSE1 | — | 2 GB | |
| local 5 GB on RSE1, global 8 GB on `RSE1\|RSE2` | — | 1 GB | the global limit has 1 GB left (7 GB used) |
| local 5 GB on RSE1 | local 10 GB on RSE1 | 7 GB | B leaves more |
| local 20 GB on RSE1, global 8 GB on `RSE1\|RSE2` | local 6 GB on RSE1 | 3 GB | A leaves 1 GB because of its global limit, B leaves 3 GB |
| local 5 GB on RSE1 | global 1 GB on `RSE1\|RSE2` | 2 GB | a global limit only restricts the local limits of its own role |
| global 10 GB on `tier=1` | — | account limits | no local limit of any role covers RSE1 |
| local 0 on RSE1 | — | nothing, and the account limits are **not** used | a local 0 still covers the RSE |
| local 0 on RSE1 | local no cap on RSE1 | no cap | B leaves the most space |
| local 5 GB on RSE1 (expired) | — | account limits | an expired assignment grants nothing |
| local 5 GB on RSE1 | local 5 GB on RSE1 | 2 GB | identical limits; usage counted once, not per role |

More cases worth knowing:

- **Account limits and roles:** an account limit of 100 GB on RSE1 is ignored as soon as one of alice's
  roles has a local limit on RSE1, even if that limit is smaller.
- **A global limit's expression is resolved each time it is applied:** a new RSE tagged `tier=1` joins its
  global limits at once. A global limit whose expression matches no RSE is ignored.
- **Global limits never grant:** a role with only global limits lets alice write nowhere by itself.
- **No overlap within one role:** a role has at most one local limit per RSE, and setting it again overwrites it.

---

## 7. What is not an overlap, but is often taken for one

| Situation | What happens |
|---|---|
| DID permission on a collection and on its files | independent: no inheritance, each DID is checked on its own |
| DID permission and a rule on a collection | a rule copies the whole content of a readable collection, including files the rule's account cannot read |
| The same role assigned twice | not possible: an account holds a role once |
| A role locked or not assignable | changes who may manage the role, not what it grants |
| Reserved `admin` role | not a permission: its holders bypass every check, as do the accounts with the `admin` attribute |

---

## 8. Where it lives

- `lib/rucio/core/role.py`:
  - DID patterns, specificity and union: `_did_pattern_matches`, `_did_pattern_specificity`, `DidAccess`, `has_did_permission`, `has_any_scope_prefix_access`;
  - metadata resolution: the "Metadata" section comment, `MetadataAccess`;
  - limits: the "RSE quotas" section comment, `list_account_rse_quota_grants`, `rse_quota_left`.
- `lib/rucio/cli/role.py`: the warning when a narrower DID pattern withdraws operations (`_did_pattern_covers`, `_deciding_did_pattern`);
- `lib/rucio/core/permission/generic.py`: ownership (`_owns_did`), role grants (`rucio.core.role.has_did_permission`),
  metadata (`_rbac_can_alter_metadata`, `perm_delete_metadata`), reads (`perm_read_data`, `perm_list_replicas`),
  listings (`did_filter`, `scope_filter`, `MetadataKeyFilter`).
