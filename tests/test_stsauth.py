from unittest import TestCase
from unittest.mock import MagicMock

from sts_auth.stsauth import STSAuth


class TestSTSAuth(TestCase):
    def setUp(self):
        self.username = "username"
        self.password = "password"
        config = {"default": {"idpentryurl": "", "domain": "", "region": "", "output": ""}}
        self.credentialsfile = "./fixtures/credentials"
        self.sts_auth = STSAuth(self.username, self.password, self.credentialsfile)
        self.sts_auth.config = MagicMock(return_value=config)

    def test_sts_auth(self):
        self.assertEqual(1, 1)
