import ipdb
from unittest import TestCase
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

from stsauth import STSAuth


class TestSTSAuth(TestCase):
    def setUp(self):
        self.username = 'username'
        self.password = 'password'
        config = {
            'default': {
                'idpentryurl': '',
                'domain': '',
                'region': '',
                'output': ''
            }
        }
        self.credentialsfile = './fixtures/credentials'
        self.sts_auth = STSAuth(self.username, self.password, self.credentialsfile)
        self.sts_auth.config = MagicMock(return_value=config)

    def test_sts_auth(self):
        # ipdb.set_trace()
        self.assertEquals(1, 1)
