import configparser
from unittest import TestCase
from mock import patch  # type: ignore[import]


from sts_auth.config import Config
from .fixtures import fixtures


class TestAwsAccountNames(TestCase):
    def setUp(self):
        self.config_file = configparser.RawConfigParser()
        self.config_file.read_dict(fixtures.aws_credentials_conf)

        with patch("configparser.RawConfigParser", autospec=True) as config_parser:
            config_parser.return_value = self.config_file
            self.config = Config("fakefile")
            self.config.load()

        self.account_map = {
            v.get("account_id", "None"): v.get("account_name", "None") for _, v in fixtures.aws_credentials_conf.items()
        }

    def test_aws_account_names(self):
        account_map = self.config.profile_set.aws_account_names
        self.assertDictEqual(account_map, self.account_map)
