from typing import TYPE_CHECKING, Optional

import rucio.common.utils
from rucio.common.exception import RucioException

if TYPE_CHECKING:
    from collections.abc import Sequence

class ATLASScopeExtractionAlgorithm(rucio.common.utils.ScopeExtractionAlgorithms):
    def __init__(self) -> None:
        """
        Initialises scope extraction algorithm object
        """
        super().__init__()

    @classmethod
    def _module_init_(cls) -> None:
        """
        Registers the included scope extraction algorithms
        """
        cls.register('atlas', cls.extract_scope_atlas)

    @staticmethod
    def extract_scope_atlas(did: str, scopes: Optional['Sequence[str]']) -> 'Sequence[str]':
        # Try to extract the scope from the DSN
        if did.find(':') > -1:
            if len(did.split(':')) > 2:
                raise RucioException('Too many colons. Cannot extract scope and name')
            scope, name = did.split(':')[0], did.split(':')[1]
            if name.endswith('/'):
                name = name[:-1]
            return scope, name
        else:
            scope = did.split('.')[0]
            if did.startswith('user') or did.startswith('group'):
                scope = ".".join(did.split('.')[0:2])
            if did.endswith('/'):
                did = did[:-1]
            return scope, did


ATLASScopeExtractionAlgorithm._module_init_()
