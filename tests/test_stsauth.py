import ipdb
from unittest import TestCase
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

from stsauth import STSAuth
from stsauth import from_epoch, to_epoch

from datetime import datetime, timedelta


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
        print("test print")
        self.assertEquals(1, 1)


class TestToFromEpoch(TestCase):
    def test_to_from_epoch(self):
        time_delta = timedelta(seconds=1)
        datetime_now = datetime.now()
        util_func_now = from_epoch(to_epoch(datetime.now()))
        self.assertTrue(abs((util_func_now - datetime_now)) < time_delta)
