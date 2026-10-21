# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest

from rucio.cli.utils import SizeFormat, format_limits, format_quota, format_quota_usage
from rucio.common.constants import ROLE_QUOTA_NOCAP

GB = 10**9


@pytest.mark.parametrize("used, limit, sizes, expected", [
    (1_395_864_371, 10 * GB, SizeFormat.COMPACT, "1.4/10 GB (14% used)"),
    (950_000_000, 10 * GB, SizeFormat.COMPACT, "950 MB/10 GB (10% used)"),
    (0, 10 * GB, SizeFormat.COMPACT, "0/10 GB (0% used)"),
    (12 * GB, 10 * GB, SizeFormat.COMPACT, "12/10 GB (>100% used)"),
    # beyond the limit of a role, e.g. another role of the account leaving more space
    (10 * GB + 1, 10 * GB, SizeFormat.EXACT, "10,000,000,001/10,000,000,000 B (>100% used)"),
    (10 * GB, 10 * GB, SizeFormat.COMPACT, "10/10 GB (100% used)"),
    # the rounding neither hides a usage nor shows a limit reached before it is
    (1, 10**12, SizeFormat.COMPACT, "1 B/1 TB (<1% used)"),
    (9_999_000_000, 10 * GB, SizeFormat.COMPACT, "10/10 GB (>99% used)"),
    (3_200_000_000_000, ROLE_QUOTA_NOCAP, SizeFormat.COMPACT, "3.2 TB/no cap"),
    (0, ROLE_QUOTA_NOCAP, SizeFormat.COMPACT, "0/no cap"),
    (0, 0, SizeFormat.COMPACT, "0/0 B (full)"),
    (1_395_864_371, 10 * GB, SizeFormat.EXACT, "1,395,864,371/10,000,000,000 B (14.0% used)"),
    (1, 10**12, SizeFormat.EXACT, "1/1,000,000,000,000 B (<0.1% used)"),
    (3_200_000_000_000, ROLE_QUOTA_NOCAP, SizeFormat.EXACT, "3,200,000,000,000/no cap"),
    (1_395_864_371, 10 * GB, SizeFormat.RAW, "1395864371/10000000000 (14.0% used)"),
])
def test_format_quota_usage(used, limit, sizes, expected):
    """CLI (ROLE): a limit is rendered with the usage measured against it, in each size format"""
    assert format_quota_usage(used, limit, sizes) == expected


@pytest.mark.parametrize("bytes_, sizes, expected", [
    (100 * GB, SizeFormat.COMPACT, "100 GB"),
    (1_234_000_000_000, SizeFormat.COMPACT, "1.234 TB"),
    (999_999_999, SizeFormat.COMPACT, "1 GB"),
    (100 * GB, SizeFormat.EXACT, "100,000,000,000 B"),
    (100 * GB, SizeFormat.RAW, "100000000000"),
    (ROLE_QUOTA_NOCAP, SizeFormat.EXACT, "no cap"),
])
def test_format_quota(bytes_, sizes, expected):
    """CLI (ROLE): a limit alone is rendered in each size format"""
    assert format_quota(bytes_, sizes) == expected


def test_format_limits_usage():
    """CLI (ROLE): the usage of a global limit is summed over the RSEs its expression matches, by the resolver given"""
    usage = {'MOCK2': 30 * GB, 'MOCK3': 12 * GB}
    rses = {'MOCK2|MOCK3': ['MOCK2', 'MOCK3']}
    permission = {'type': 'limit', 'rse_expression': 'MOCK2|MOCK3', 'global': 100 * GB}

    assert format_limits(permission) == "global: 100 GB"
    assert format_limits(permission, used=lambda expression: sum(usage[rse] for rse in rses[expression])) == "global: 42/100 GB (42% used)"


def test_size_format_of():
    """CLI (ROLE): --robot gives bare numbers, whatever else is asked for"""
    assert SizeFormat.of(human=True) == SizeFormat.COMPACT
    assert SizeFormat.of(human=True, exact=True) == SizeFormat.EXACT
    assert SizeFormat.of(human=False, exact=True) == SizeFormat.RAW
