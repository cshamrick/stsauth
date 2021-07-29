import configparser
from datetime import datetime, timedelta
from unittest import TestCase

from sts_auth import utils
from sts_auth.profile import Profile
from .fixtures import fixtures


class TestIsProfileActive(TestCase):
    def setUp(self):
        self.config = configparser.RawConfigParser()
        self.config.read_dict(fixtures.aws_credentials_conf)
        self.profile = Profile(list(self.config.values())[1])

    def test_profile_has_no_expiry(self):
        self.config.remove_option(self.profile.name, "aws_credentials_expiry")
        self.profile = Profile(list(self.config.values())[1])
        self.assertIsNone(self.profile.expiry)
        self.assertTrue(self.profile.active)

    def test_profile_is_expired(self):
        past = utils.to_epoch(datetime.utcnow() + timedelta(-1))
        self.config.set(self.profile.name, "aws_credentials_expiry", past)
        self.profile = Profile(list(self.config.values())[1])
        self.assertFalse(self.profile.active)

    def test_profile_is_not_expired(self):
        future = utils.to_epoch(datetime.utcnow() + timedelta(1))
        self.config.set(self.profile.name, "aws_credentials_expiry", future)
        self.profile = Profile(list(self.config.values())[1])
        self.assertEqual(self.profile.expiry, future)
        self.assertTrue(self.profile.active)
