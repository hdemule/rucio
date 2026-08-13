from typing import TYPE_CHECKING

from rucio.rse.translation import RSEDeterministicScopeTranslation

if TYPE_CHECKING:
    from collections.abc import Mapping

class ATLASRSEDeterministicScopeTranslation(RSEDeterministicScopeTranslation):
    """
        Translates a pfn dictionary into a scope and name
    """

    def __init__(self, vo: str = 'def'):
        super().__init__()

    @classmethod
    def _module_init_(cls):
        """
        Initialize the class object on first module load.
        """
        cls.register(cls.pfn2lfn_atlas, "atlas")

    @staticmethod
    def pfn2lfn_atlas(parsed_pfn: 'Mapping[str, str]') -> tuple[str, str]:
        """ Translate pfn to name/scope pair

        :param parsed_pfn: dictionary representing pfn containing:
            - path: str,
            - name: str
        :return: tuple containing name, scope
        """
        path = parsed_pfn['path']
        if path.startswith('/user') or path.startswith('/group'):
            scope = '%s.%s' % (path.split('/')[1], path.split('/')[2])
            name = parsed_pfn['name']
        else:
            name, scope = RSEDeterministicScopeTranslation._default(parsed_pfn)

        return name, scope

ATLASRSEDeterministicScopeTranslation._module_init_()
