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

# To run a single test, use `pytest tests/test_rbac.py::TestDID::test_did_content_list_rbac`

import os

from rucio.tests.common import execute

# def test_config():
#     """RBAC(USER): Check that the test config files exist"""
#     assert os.path.exists('etc/rucio-bob.cfg')
#     assert os.path.exists('etc/rucio-alice.cfg')
#     assert os.path.exists('etc/rucio.cfg')

#     # test if accounts exist
#     _, out, _ = execute('rucio account list')
#     assert out.find('bob') != -1
#     assert out.find('alice') != -1
#     assert out.find('root') != -1

#     _, out, _ = execute('rucio account attribute list bob')
#     assert out.find('read_scopes') != -1
#     assert out.find('bob') != -1

#     _, out, _ = execute('rucio account attribute list alice')
#     assert out.find('read_scopes') != -1
#     assert out.find('alice') != -1

#     _, out, _ = execute('rucio account attribute list root')
#     assert out.find('admin') != -1


class TestDID:
    def test_did_list_content_rbac(self):
        """RBAC(USER): rucio did content list bob:bob_ds is only visible to root and bob, not alice"""
        original_config = os.environ.get('RUCIO_CONFIG')
        try:
            # root has admin rights and can see any scope
            os.environ.pop('RUCIO_CONFIG', None)
            exitcode, out, err = execute('rucio did content list bob:bob_ds')
            assert exitcode == 0

            # bob owns the bob scope, so he can list its content
            os.environ['RUCIO_CONFIG'] = 'etc/rucio-bob.cfg'
            exitcode, out, err = execute('rucio did content list bob:bob_ds')
            assert exitcode == 0

            # alice has no read_scopes access to bob's scope, so this must fail
            os.environ['RUCIO_CONFIG'] = 'etc/rucio-alice.cfg'
            exitcode, out, err = execute('rucio did content list bob:bob_ds')
            assert exitcode == 2  # AccessDenied Error

        finally:
            if original_config is not None:
                os.environ['RUCIO_CONFIG'] = original_config
            else:
                os.environ.pop('RUCIO_CONFIG', None)

    def test_did_list(self):
        original_config = os.environ.get('RUCIO_CONFIG')
        try:
            # root has admin rights and can see any scope
            os.environ.pop('RUCIO_CONFIG', None)
            exitcode, out, err = execute('rucio did list bob:*')
            assert exitcode == 0

            # bob owns the bob scope, so he can list its content
            os.environ['RUCIO_CONFIG'] = 'etc/rucio-bob.cfg'
            exitcode, out, err = execute('rucio did list bob:*')
            assert exitcode == 0

            # alice has no read_scopes access to bob's scope, so this must fail
            os.environ['RUCIO_CONFIG'] = 'etc/rucio-alice.cfg'
            exitcode, out, err = execute('rucio did list bob:*')
            assert exitcode == 2  # AccessDenied Error

        finally:
            if original_config is not None:
                os.environ['RUCIO_CONFIG'] = original_config
            else:
                os.environ.pop('RUCIO_CONFIG', None)

    def test_did_show(self):
        original_config = os.environ.get('RUCIO_CONFIG')
        try:
            # root has admin rights and can see any scope
            os.environ.pop('RUCIO_CONFIG', None)
            exitcode, out, err = execute('rucio did show bob:bob_ds')
            assert exitcode == 0

            # bob owns the bob scope, so he can list its content
            os.environ['RUCIO_CONFIG'] = 'etc/rucio-bob.cfg'
            exitcode, out, err = execute('rucio did show bob:bob_ds')
            assert exitcode == 0

            # alice has no read_scopes access to bob's scope, so this must fail
            os.environ['RUCIO_CONFIG'] = 'etc/rucio-alice.cfg'
            exitcode, out, err = execute('rucio did show bob:bob_ds')
            assert exitcode == 2  # AccessDenied Error

        finally:
            if original_config is not None:
                os.environ['RUCIO_CONFIG'] = original_config
            else:
                os.environ.pop('RUCIO_CONFIG', None)


class TestLOCK:
    pass


class TestOPENDATA:
    pass


class TestREPLICA:
    pass


class TestREQUEST:
    pass


class TestRULE:
    pass


class TestSCOPE:
    pass


class TestSUBSCRIPTION:
    pass
