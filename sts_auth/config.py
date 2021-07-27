import os
import sys
import configparser
from typing import Optional, Mapping

import click

from sts_auth import utils
from sts_auth.profile import Profile
from sts_auth.profile_set import ProfileSet
from sts_auth.utils import logger


class Config(object):
    """Represent and maniputlate configuration for STSAuth

    :param credentials: Path to AWS credentials file.
    :param user_values: KeywordArgs of user-provided values to merge into Config.
    """

    def __init__(self, credentialsfile: str, **user_values: Optional[Mapping[str, str]]):
        self.user_values = user_values
        self.credentialsfile = os.path.expanduser(credentialsfile)
        self.values = configparser.RawConfigParser()
        self.values.read(self.credentialsfile)
        self.username = user_values.get("username")
        self.password = user_values.get("password")
        self.profile = user_values.get("profile")
        self.region = user_values.get("region")
        self.output = user_values.get("output")
        self.idpentryurl = user_values.get("idpentryurl")
        self.domain = user_values.get("domain")
        self.okta_org = user_values.get("okta_org")
        self.okta_shared_secret = user_values.get("okta_shared_secret")

    @property
    def valid(self) -> bool:
        """Validate configuration

        :return bool: Whether or not the configuration is valid.
        """
        valid = True
        url = self.values.get("default", "idpentryurl", fallback=self.user_values.get("idpentryurl"))
        domain = self.values.get("default", "domain", fallback=self.user_values.get("domain"))
        region = self.values.get("default", "region", fallback=self.user_values.get("region"))
        output = self.values.get("default", "output", fallback=self.user_values.get("output"))

        _map = {
            "idpentryurl": url,
            "domain": domain,
            "region": region,
            "output": output,
        }
        items = [k for k, v in _map.items() if not v or v is None]
        if items:
            msg = (
                "Config value missing for the items {}.\n"
                "Please add these to {} or provide them "
                "through CLI flags (see `stsauth --help`) and try again.".format(items, self.credentialsfile)
            )
            click.secho(msg, fg="red")
            valid = False
        return valid

    def load(self) -> None:
        """Read configuration file and only set values if they were not passed in from the CLI."""
        if self.values.has_section("default"):
            logger.debug("Found 'default' section in {0.credentialsfile!r}!".format(self))
            default = self.values["default"]
            msg = "Attribute {1!r} not set, using value from {0.credentialsfile!r}"
            if not self.region:
                logger.debug(msg.format(self, "region"))
                self.region = default.get("region")
            if not self.output:
                logger.debug(msg.format(self, "output"))
                self.output = default.get("output")
            if not self.idpentryurl:
                logger.debug(msg.format(self, "idpentryurl"))
                self.idpentryurl = default.get("idpentryurl")
            if not self.domain:
                logger.debug(msg.format(self, "domain"))
                self.domain = default.get("domain")
            if not self.okta_org:
                logger.debug(msg.format(self, "okta_org"))
                self.okta_org = default.get("okta_org")
            if not self.okta_shared_secret:
                logger.debug(msg.format(self, "okta_shared_secret"))
                self.okta_shared_secret = default.get("okta_shared_secret")
        else:
            logger.debug("Could not find 'default' section in {0.credentialsfile!r}!".format(self))

    @property
    def profile_set(self) -> ProfileSet:
        """Generate ProfileSet

        :return ProfileSet: A set of Profile objects.
        """
        return ProfileSet(self.values.values())

    @property
    def domain_user(self) -> str:
        if self.domain:
            return "{0.domain}\\{0.username}".format(self)
        else:
            return self.username

    def set_attribute(self, section: str, attribute: str, value: str) -> None:
        if value is not None and value != "":
            logger.debug(f"Setting attribute '{attribute}' in section '{section}' to '{value}'.")
            self.values.set(section, attribute, value)
        else:
            logger.debug(f"Not updating empty attribute '{attribute}' in section '{section}'.")

    def write(
        self, token: Mapping[str, str], account_name: str, account_id: str, profile: Optional[str] = None
    ) -> None:
        """Store credentials in a specific profile.

        Takes the credentials and details from the token provided and writes them out to a
        configuration

        Args:
            token: Object containing the credentials to write out.
            account_name: Name of AWS Account
            profile: optional profile paramater. Uses the class profile if undefined
        """
        if profile is None:
            profile = self.profile

        if not self.values.has_section(profile):
            self.values.add_section(profile)

        if not self.values.has_section("default"):
            self.values.add_section("default")

        self.set_attribute("default", "idpentryurl", self.idpentryurl)

        credentials = token.get("Credentials", {})
        expiration = utils.to_epoch(credentials.get("Expiration", ""))
        self.set_attribute(profile, "output", self.output)
        self.set_attribute(profile, "region", self.region)
        self.set_attribute(profile, "account_name", account_name)
        self.set_attribute(profile, "account_id", account_id)
        self.set_attribute(profile, "aws_access_key_id", credentials.get("AccessKeyId", "None"))
        self.set_attribute(profile, "aws_secret_access_key", credentials.get("SecretAccessKey", "None"))
        self.set_attribute(profile, "aws_session_token", credentials.get("SessionToken", "None"))
        self.set_attribute(profile, "aws_credentials_expiry", expiration)

        # Write the AWS STS token into the AWS credential file
        with open(self.credentialsfile, "w") as f:
            self.values.write(f)
