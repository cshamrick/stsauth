import os
import re
import sys
import configparser
from datetime import datetime

import boto3
import click
import requests
from requests_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup
from botocore.exceptions import ProfileNotFound

from sts_auth import utils
from sts_auth.okta import Okta
from sts_auth.utils import logger

try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse


class STSAuth(object):
    """Initializes an STS Authenticator.

    :param username: Username to authenticate with (required).
    :param password: Password to authenticate with (required).
    :param credentialsfile: A path to an AWS Credentials file (required).
        See https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html
        for more details.
    :param idpentryurl: URL to the IDP Entrypoint.
    :param profile: Name of an AWS Profile to automatically fetch credentials for.
    :param okta_org: Name of the Okta organization, ex: `my-company`.
    :param domain: Domain which your username resides if required.
    :param region: Region for AWS to authenticate in.
    :param output: Output format, one of: `json`, `text`, `table`.
    """

    def __init__(
        self,
        username,
        password,
        credentialsfile,
        idpentryurl=None,
        profile=None,
        okta_org=None,
        okta_shared_secret=None,
        domain=None,
        region=None,
        output=None,
        vip_access_security_code=None,
        force=False,
    ):
        self.domain = domain
        self.username = username
        self.password = password
        self.credentialsfile = os.path.expanduser(credentialsfile)
        self.idpentryurl = idpentryurl
        self.profile = profile
        self.region = region
        self.output = output
        self.okta_org = okta_org
        self.okta_shared_secret = okta_shared_secret
        self.vip_access_security_code = vip_access_security_code
        self.session = requests.Session()

        self.session.headers.update({"content-type": "application/json"})
        self.session.auth = HttpNtlmAuth(self.domain_user, self.password)
        self.config = configparser.RawConfigParser()
        self.config.read(self.credentialsfile)

    @property
    def domain_user(self):
        if self.domain:
            return "{0.domain}\\{0.username}".format(self)
        else:
            return self.username

    @property
    def config_file_is_valid(self):
        valid = True
        url = self.config.get("default", "idpentryurl", fallback=self.idpentryurl)
        domain = self.config.get("default", "domain", fallback=self.domain)
        region = self.config.get("default", "region", fallback=self.region)
        output = self.config.get("default", "output", fallback=self.output)

        _map = {
            "idpentryurl": url,
            "domain": domain,
            "region": region,
            "output": output,
        }
        items = [k for k, v in _map.items() if not v]
        if items:
            msg = (
                "Config value missing for the items {}.\n"
                "Please add these to {} or provide them "
                "through CLI flags (see `stsauth --help`) and try again.".format(items, self.credentialsfile)
            )
            click.secho(msg, fg="red")
            valid = False
        return valid

    @property
    def credentials_expired(self):
        return not utils.is_profile_active(self.config, self.profile)

    def parse_config_file(self):
        """Read configuration file and only set values if they
        were not passed in from the CLI.
        """
        if self.config.has_section("default"):
            logger.debug("Found 'default' section in {0.credentialsfile!r}!".format(self))
            default = self.config["default"]
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

    def get_saml_response(self, response=None):
        if not response:
            logger.debug("No response provided. Fetching IDP Entry URL...")
            response = self.session.get(self.idpentryurl)
        response.soup = BeautifulSoup(response.text, "lxml")
        assertion_pattern = re.compile(r"name=\"SAMLResponse\" value=\"(.*)\"\s*/><noscript>")
        assertion = re.search(assertion_pattern, response.text)

        if assertion:
            # If there is already an assertion in the response body,
            # we can attach the parsed assertion to the response object and
            # return the whole response for use later.
            # return account_map, assertion.group(1)
            response.assertion = assertion.group(1)
            return response
        logger.debug("No SAML assertion found in response. Attempting to log in...")

        login_form = response.soup.find(id="loginForm")
        okta_login = response.soup.find(id="okta-login-container")

        if okta_login:
            state_token = utils.get_state_token_from_response(response.text)
            if state_token is None:
                click.secho("No State Token found in response. Exiting...", fg="red")
                sys.exit(1)
            okta_client = Okta(
                session=self.session,
                state_token=state_token,
                okta_org=self.okta_org,
                okta_shared_secret=self.okta_shared_secret,
            )
            okta_response = okta_client.handle_okta_verification(response)
            return self.get_saml_response(response=okta_response)

        if login_form:
            # If there is no assertion, it is possible the user is attempting
            # to authenticate from outside the network, so we check for a login
            # form in their response.
            form_response = self.authenticate_to_adfs_portal(response)
            return self.get_saml_response(response=form_response)

        else:
            msg = "Response did not contain a valid SAML assertion, a valid login form, or request MFA."
            click.secho(msg, fg="red")
            sys.exit(1)

    def generate_payload_from_login_page(self, response):
        login_page = BeautifulSoup(response.text, "html.parser")
        payload = {}

        for input_tag in login_page.find_all(re.compile("(INPUT|input)")):
            name = input_tag.get("name", "")
            value = input_tag.get("value", "")
            logger.debug("Adding value for {!r} to Login Form payload.".format(name))
            if "user" in name.lower():
                payload[name] = self.domain_user
            elif "email" in name.lower():
                payload[name] = self.domain_user
            elif "pass" in name.lower():
                payload[name] = self.password
            elif "security_code" in name.lower():
                payload[name] = self.vip_access_security_code
            else:
                payload[name] = value

        return payload

    def build_idp_auth_url(self, response):
        idp_auth_form_submit_url = response.url
        login_page = BeautifulSoup(response.text, "html.parser")

        for form in login_page.find_all(re.compile("(FORM|form)")):
            action = form.get("action")
            if action:
                parsed_action = urlparse(action)
                parsed_idp_url = urlparse(self.idpentryurl)
                # Fallback to the IDP Entry URL from the config file if the
                # form action does not contain a fully defined URL.
                # i.e. action='/path/to/something' vs action='http://test.com/path/to/something'
                scheme = parsed_action.scheme if parsed_action.scheme else parsed_idp_url.scheme
                netloc = parsed_action.netloc if parsed_action.netloc else parsed_idp_url.netloc
                url_parts = (
                    scheme,
                    netloc,
                    parsed_action.path,
                    None,
                    parsed_action.query,
                    None,
                )
                idp_auth_form_submit_url = urlunparse(url_parts)

        return idp_auth_form_submit_url

    def authenticate_to_adfs_portal(self, response):
        payload = self.generate_payload_from_login_page(response)
        idp_auth_form_submit_url = self.build_idp_auth_url(response)

        logger.debug("Posting login data to URL: {}".format(idp_auth_form_submit_url))
        login_response = self.session.post(idp_auth_form_submit_url, data=payload, verify=True)
        login_response_page = BeautifulSoup(login_response.text, "html.parser")
        # Checks for errorText id on page to indicate any errors
        login_error_message = login_response_page.find(id="errorText")
        # Checks for specific text in a paragraph element to indicate any errors
        vip_login_error_message = login_response_page.find(
            lambda tag: tag.name == "p" and "Authentication failed" in tag.text
        )
        if (login_error_message and len(login_error_message.string) > 0) or (
            vip_login_error_message and len(vip_login_error_message) > 0
        ):
            msg = "Login page returned the following message. Please resolve this issue before continuing:"
            click.secho(msg, fg="red")
            error_msg = login_error_message if login_error_message else vip_login_error_message
            click.secho(error_msg.string, fg="red")
            sys.exit(1)
        return login_response

    def fetch_aws_sts_token(
        self, role_arn, principal_arn, assertion, duration_seconds=3600, aws_profile=None,
    ):
        """Use the assertion to get an AWS STS token using `assume_role_with_saml`"""
        try:
            session = boto3.Session(profile_name=aws_profile)
            sts = session.client("sts")
        except ProfileNotFound as e:
            click.secho(str(e), fg="red")
            sys.exit(1)
        except Exception as e:
            # TODO: Proper exception and message
            raise e

        token = sts.assume_role_with_saml(
            RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion, DurationSeconds=duration_seconds,
        )
        return token

    def write_to_configuration_file(self, token, account_name, account_id, profile=None):
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

        if not self.config.has_section(profile):
            self.config.add_section(profile)

        if not self.config.has_section("default"):
            self.config.add_section("default")

        self.config.set("default", "idpentryurl", self.idpentryurl)

        credentials = token.get("Credentials", {})
        expiration = utils.to_epoch(credentials.get("Expiration", ""))
        self.config.set(profile, "output", self.output)
        self.config.set(profile, "region", self.region)
        if account_name != "":
            self.config.set(profile, "account_name", account_name)
        if account_id != "":
            self.config.set(profile, "account_id", account_id)
        self.config.set(profile, "aws_access_key_id", credentials.get("AccessKeyId", "None"))
        self.config.set(profile, "aws_secret_access_key", credentials.get("SecretAccessKey", "None"))
        self.config.set(profile, "aws_session_token", credentials.get("SessionToken", "None"))
        self.config.set(profile, "aws_credentials_expiry", expiration)

        # Write the AWS STS token into the AWS credential file
        with open(self.credentialsfile, "w") as f:
            self.config.write(f)

    def fetch_aws_account_names(self, response):
        hiddenform = response.soup.find("form", {"name": "hiddenform"})
        headers = {
            "Referer": response.url,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        selectors = ",".join("{}[name]".format(i) for i in ("input", "button", "textarea", "select"))
        data = [(tag.get("name"), tag.get("value")) for tag in hiddenform.select(selectors)]
        url = hiddenform.attrs.get("action")
        try:
            adfs_response = self.session.post(url, data=data, headers=headers, timeout=5)
        except requests.exceptions.ConnectionError as e:
            msg_fmt = "Could not fetch account aliases from {} due to an exception. Using cached values!\n {}"
            click.secho(msg_fmt.format(url, str(e)), fg="red")
            return None
        adfs_response.soup = BeautifulSoup(adfs_response.text, "lxml")

        return adfs_response

    def generate_login_url(self, token):
        federation_base_url = "https://signin.aws.amazon.com/federation"
        request_params = {
            "Action": "getSigninToken",
            "SessionDuration": "43200",
            "Session": str(
                {
                    "sessionId": token["Credentials"]["AccessKeyId"],
                    "sessionKey": token["Credentials"]["SecretAccessKey"],
                    "sessionToken": token["Credentials"]["SessionToken"],
                }
            ),
        }
        r = self.session.get(federation_base_url, params=request_params)
        signin_token = r.json()

        login_params = {
            "Action": "login",
            "Destination": "https://console.aws.amazon.com/",
            "SigninToken": signin_token["SigninToken"],
        }
        request_parameters = requests.compat.urlencode(login_params)
        request_url = "{base_url}?{request_parameters}".format(
            base_url=federation_base_url, request_parameters=request_parameters
        )
        return request_url
