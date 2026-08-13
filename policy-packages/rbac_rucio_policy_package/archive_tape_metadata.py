from typing import Any, Optional

import rucio.core.did
from rucio.db.sqla.constants import DIDType
from rucio.transfertool.fts3_plugins import FTS3TapeMetadataPlugin

class ATLASArchiveMetadataPlugin(FTS3TapeMetadataPlugin):
    """
    Specification: https://codimd.web.cern.ch/bmEXKlYqQbu529PUdAFfYw#
    """

    def __init__(self) -> None:
        policy_algorithm = 'atlas'
        self.register(
            policy_algorithm,
            func=lambda x: self.get_atlas_archive_metadata(x)
        )
        super().__init__(policy_algorithm)

    @staticmethod
    def get_atlas_archive_metadata(hints: dict[str, Any]) -> dict[str, Any]:
        archive_metadata = {
            'file_metadata': ATLASArchiveMetadataPlugin._get_file_metadata(**hints),
            'additional_hints': {
                'activity': hints.get('activity'),
            },
            'schema_version': 1
        }

        scope, name = hints['scope'], hints['name']
        parent_did = None
        parent_did_level = None
        did_metadata = rucio.core.did.get_metadata(scope, name)

        datatype = did_metadata['datatype'] or ''
        project = did_metadata['project'] or ''

        # AOD/data
        if datatype == 'AOD' and project.startswith('data'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '4'

            archive_metadata['collocation_hints'] = {
                    "0": datatype + '_data',
                    "1": did_metadata['stream_name'] or None,
                    "2": project,
                    "3": did_metadata['version'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None
                }

        # AOD/mc
        elif datatype == 'AOD' and project.startswith('mc'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '3'

            archive_metadata['collocation_hints'] = {
                    "0": datatype + '_mc',
                    "1": project,
                    "2": did_metadata['version'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None
                }

        # EVNT/mc
        elif datatype == 'EVNT' and project.startswith('mc'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '3'

            archive_metadata['collocation_hints'] = {
                    "0": datatype,
                    "1": project,
                    "2": did_metadata['version'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None,
                }

        # HITS/mc
        elif datatype == 'HITS' and project.startswith('mc'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '3'

            archive_metadata['collocation_hints'] = {
                    "0": datatype,
                    "1": project,
                    "2": did_metadata['version'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None,
                }

        # HITS/valid
        elif datatype == 'HITS' and project.startswith('valid'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '3'

            archive_metadata['collocation_hints'] = {
                    "0": datatype + '_valid',
                    "1": project,
                    "2": did_metadata['version'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None,
                }

        # RAW/data
        elif datatype == 'RAW' and project.startswith('data'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '3'

            archive_metadata['collocation_hints'] = {
                    "0": datatype,
                    "1": project,
                    "2": did_metadata['stream_name'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None,
                }

        # RDO/mc
        elif datatype == 'RDO' and project.startswith('mc'):

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '3'

            archive_metadata['collocation_hints'] = {
                    "0": datatype,
                    "1": project,
                    "2": did_metadata['version'] or None,
                    parent_did_level: parent_did.get('name') if parent_did else None
                }

        # Fallback to just dataset name
        else:

            parent_did = ATLASArchiveMetadataPlugin._get_parent_did(scope, name)
            parent_did_level = '0'

            archive_metadata['collocation_hints'] = {
                    parent_did_level: parent_did.get('name') if parent_did else None,
                }

        if parent_did:
            dataset_did = rucio.core.did.get_did(parent_did['scope'], parent_did['name'], dynamic_depth=DIDType.DATASET)
            archive_metadata['additional_hints'][parent_did_level] = ATLASArchiveMetadataPlugin._get_additional_dataset_hints(dataset_did)

        return archive_metadata

    @staticmethod
    def _get_parent_did(scope: str, name: str) -> Optional[dict[str, Any]]:
        parent_dids = rucio.core.did.list_parent_dids(scope, name, order_by=['created_at'])
        # Get first parent DID (if it exists)
        if parent_dids:
            parent_did = next(parent_dids)
            return parent_did
        return None

    @staticmethod
    def _get_file_metadata(**hints: dict[str, Any]) -> dict[str, Any]:
        return {
            'size': hints.get('filesize'),
            'md5': hints.get('md5'),
            'adler32': hints.get('adler32'),
        }

    @staticmethod
    def _get_additional_dataset_hints(dataset_did: dict[str, Any]) -> dict[str, Any]:
        return {
            'length': dataset_did.get('length'),
            'size': dataset_did.get('bytes'),
        }

# Trigger registration
ATLASArchiveMetadataPlugin()
