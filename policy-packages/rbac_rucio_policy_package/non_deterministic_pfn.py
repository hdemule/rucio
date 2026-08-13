import re
from typing import Optional

from rucio.common.utils import NonDeterministicPFNAlgorithms


class ATLASNonDeterministicPFNAlgorithm(NonDeterministicPFNAlgorithms):
    """
    ATLAS specific non-deterministic PFN algorithm
    """

    def __init__(self):
        super().__init__()

    @classmethod
    def _module_init_(cls) -> None:
        """
        Registers the included non-deterministic PFN algorithms
        """
        cls.register('T0', cls.construct_non_deterministic_pfn_t0)
        cls.register('DQ2', cls.construct_non_deterministic_pfn_dq2)

    @staticmethod
    def construct_non_deterministic_pfn_t0(dsn: str, scope: Optional[str], filename: str) -> Optional[str]:
        """
        Defines relative PFN for new replicas. This method
        contains Tier0 convention. To be used for non-deterministic sites.

        @return: relative PFN for new replica.
        @rtype: str
        """
        fields = dsn.split('.')
        nfields = len(fields)
        if nfields >= 3:
            return '/%s/%s/%s/%s/%s' % (fields[0], fields[2], fields[1], dsn, filename)
        elif nfields == 1:
            return '/%s/%s/%s/%s/%s' % (fields[0], 'other', 'other', dsn, filename)
        elif nfields == 2:
            return '/%s/%s/%s/%s/%s' % (fields[0], fields[2], 'other', dsn, filename)
        elif nfields == 0:
            return '/other/other/other/other/%s' % (filename)

    @staticmethod
    def construct_non_deterministic_pfn_dq2(dsn: str, scope: Optional[str], filename: str) -> str:
        """
        Defines relative PFN for new replicas. This method
        contains DQ2 convention. To be used for non-deterministic sites.
        Method imported from DQ2.

        @return: relative PFN for new replica.
        @rtype: str
        """
        # check how many dots in dsn
        fields = dsn.split('.')
        nfields = len(fields)

        if nfields == 0:
            return '/other/other/%s' % (filename)
        elif nfields == 1:
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/other/%s/%s' % (stripped_dsn, filename)
        elif nfields == 2:
            project = fields[0]
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s' % (project, stripped_dsn, filename)
        elif nfields < 5 or re.match('user*|group*', fields[0]):
            project = fields[0]
            f2 = fields[1]
            f3 = fields[2]
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s/%s/%s' % (project, f2, f3, stripped_dsn, filename)
        else:
            project = fields[0]
            dataset_type = fields[4]
            if nfields == 5:
                tag = 'other'
            else:
                tag = NonDeterministicPFNAlgorithms.__strip_tag(fields[-1])
            stripped_dsn = NonDeterministicPFNAlgorithms.__strip_dsn(dsn)
            return '/%s/%s/%s/%s/%s' % (project, dataset_type, tag, stripped_dsn, filename)

ATLASNonDeterministicPFNAlgorithm._module_init_()
