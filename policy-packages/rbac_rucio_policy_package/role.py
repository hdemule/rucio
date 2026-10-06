# Filters that can be disabled:
#
# By default, every listing below filters out the items whose scope the account may not READ
# (through a role, scope ownership or admin/root privileges). A role disables a filter by naming
# it in its "disable-filters": the accounts holding that role (through an assignment which has
# not expired yet) then get the listing unfiltered. A role without "disable-filters" disables
# nothing, and a filter is disabled as soon as one role of the account disables it.
#
# Scopes (rucio.gateway.scope)
# list_scopes                               => allow the user with the role to list all scopes.
# get_scopes                                => allow the user with the role to list all scopes of an account.
# list_scopes_with_account                  => allow the user with the role to list all scopes with their owner.
#
# DIDs (rucio.gateway.did)
# list_dids                                 => allow the user with the role to list, recursively, all DIDs in the content of an authorized collection.
# list_new_dids                             => allow the user with the role to list all new DIDs.
# list_content                              => allow the user with the role to list all the content of an authorized collection.
# list_content_history                      => allow the user with the role to list all the content history of an authorized collection.
# list_files                                => allow the user with the role to list all files of an authorized collection.
# bulk_list_files                           => allow the user with the role to list all files of several authorized collections.
# scope_list                                => allow the user with the role to list all DIDs in, and below, an authorized scope.
# get_dataset_by_guid                       => allow the user with the role to get all datasets holding a GUID.
# list_parent_dids                          => allow the user with the role to list all parents of an authorized DID.
# list_archive_content                      => allow the user with the role to list all the content of an authorized archive.
#
# Replicas (rucio.gateway.replica, rucio.core.replica)
# list_replicas                             => allow the user with the role to list all replicas, and their parents, of authorized DIDs.
# get_did_from_pfns                         => allow the user with the role to resolve all PFNs to their DID.
# list_datasets_per_rse                     => allow the user with the role to list all datasets on an RSE.
# get_suspicious_files                      => allow the user with the role to list all suspicious files.
# list_bad_replicas_status                  => allow the user with the role to list all bad replicas.
#
# Rules (rucio.gateway.rule)
# list_replication_rules                    => allow the user with the role to list all replication rules.
# list_associated_replication_rules_for_file => allow the user with the role to list all rules protecting an authorized file, including the rules on its parents.
#
# Locks (rucio.gateway.lock)
# get_dataset_locks_by_rse                  => allow the user with the role to list all dataset locks on an RSE.
# get_replica_locks_for_rule_id             => allow the user with the role to list all replica locks of an authorized rule.
#
# Example:
#     {
#         "name": "data-scientist",
#         "description": "...",
#         "disable-filters": ["list_scopes", "list_content"],
#     },

roles = [
    {
        "name": "data-scientist",
        "description": "Data scientist role with read access to data scope and archived content.",
    },
    {
        "name": "superuser",
        "description": "Full read access to all scopes.",
    },
]

default_roles = []  # Default roles assigned to new users
