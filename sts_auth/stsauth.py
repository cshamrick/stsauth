import os
import re
import sys
from datetime import datetime
from typing import Optional, Mapping
from urllib.parse import urlparse, urlunparse

import boto3  # type: ignore[import]
import click  # type: ignore[import]
import requests
from requests_ntlm import HttpNtlmAuth  # type: ignore[import]
from bs4 import BeautifulSoup  # type: ignore[import]
from botocore.exceptions import ProfileNotFound, ClientError  # type: ignore[import]

from sts_auth import utils
from sts_auth.okta import Okta
from sts_auth.config import Config
from sts_auth.utils import logger


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
        username: str,
        password: str,
        credentialsfile: str,
        idpentryurl: Optional[str] = None,
        profile: Optional[str] = None,
        okta_org: Optional[str] = None,
        okta_shared_secret: Optional[str] = None,
        domain: Optional[str] = None,
        region: Optional[str] = None,
        output: Optional[str] = None,
        vip_access_security_code: Optional[str] = None,
        force: Optional[bool] = False,
    ):
        self.credentialsfile = os.path.expanduser(credentialsfile)
        self.vip_access_security_code = vip_access_security_code
        self.config = Config(
            self.credentialsfile,
            username=username,  # type: ignore[arg-type]
            password=password,  # type: ignore[arg-type]
            domain=domain,  # type: ignore[arg-type]
            idpentryurl=idpentryurl,  # type: ignore[arg-type]
            region=region,  # type: ignore[arg-type]
            output=output,  # type: ignore[arg-type]
            okta_org=okta_org,  # type: ignore[arg-type]
            okta_shared_secret=okta_shared_secret,  # type: ignore[arg-type]
            profile=profile,  # type: ignore[arg-type]
        )
        self.config.load()
        self.profile = self.config.profile

        self.session = requests.Session()
        self.session.headers.update({"content-type": "application/json"})
        self.session.auth = HttpNtlmAuth(self.config.domain_user, self.config.password)

    def get_saml_response(self, response: Optional[requests.Response] = None) -> requests.Response:
        if not response:
            logger.debug("No response provided. Fetching IDP Entry URL...")
            response = self.session.get(self.config.idpentryurl)
        response.soup = BeautifulSoup(response.text, "lxml")  # type: ignore[attr-defined]
        assertion_pattern = re.compile(r"name=\"SAMLResponse\" value=\"(.*)\"\s*/><noscript>")
        assertion = re.search(assertion_pattern, response.text)

        if assertion:
            # If there is already an assertion in the response body,
            # we can attach the parsed assertion to the response object and
            # return the whole response for use later.
            # return account_map, assertion.group(1)
            response.assertion = assertion.group(1)  # type: ignore[attr-defined]
            return response
        logger.debug("No SAML assertion found in response. Attempting to log in...")

        login_form = response.soup.find(id="loginForm")  # type: ignore[attr-defined]
        okta_login = response.soup.find(id="okta-login-container")  # type: ignore[attr-defined]

        if okta_login:
            state_token = utils.get_state_token_from_response(response.text)
            if state_token is None:
                click.secho("No State Token found in response. Exiting...", fg="red")
                sys.exit(1)
            okta_client = Okta(
                session=self.session,
                state_token=state_token,
                okta_org=self.config.okta_org,
                okta_shared_secret=self.config.okta_shared_secret,
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

    def generate_payload_from_login_page(self, response: requests.Response) -> Mapping[str, str]:
        login_page = BeautifulSoup(response.text, "html.parser")
        payload = {}

        for input_tag in login_page.find_all(re.compile("(INPUT|input)")):
            name = input_tag.get("name", "")
            value = input_tag.get("value", "")
            logger.debug("Adding value for {!r} to Login Form payload.".format(name))
            if "user" in name.lower():
                payload[name] = self.config.domain_user
            elif "email" in name.lower():
                payload[name] = self.config.domain_user
            elif "pass" in name.lower():
                payload[name] = self.config.password
            elif "security_code" in name.lower():
                payload[name] = self.vip_access_security_code  # type: ignore[assignment]
            else:
                payload[name] = value

        return payload

    def build_idp_auth_url(self, response: requests.Response) -> str:
        idp_auth_form_submit_url = response.url
        login_page = BeautifulSoup(response.text, "html.parser")

        for form in login_page.find_all(re.compile("(FORM|form)")):
            action = form.get("action")
            if action:
                parsed_action = urlparse(action)
                parsed_idp_url = urlparse(self.config.idpentryurl)
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

    def authenticate_to_adfs_portal(self, response: requests.Response) -> requests.Response:
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

    def fetch_aws_account_names(self, response: requests.Response) -> Optional[requests.Response]:
        """Posts ADFS form to get account list response"""
        hiddenform = response.soup.find("form", {"name": "hiddenform"})  # type: ignore[attr-defined]
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
        adfs_response.soup = BeautifulSoup(adfs_response.text, "lxml")  # type: ignore[attr-defined]

        return adfs_response

    def generate_login_url(self, token: Mapping[str, Mapping[str, str]]) -> str:
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
        request_parameters = requests.compat.urlencode(login_params)  # type: ignore[attr-defined]
        request_url = "{base_url}?{request_parameters}".format(
            base_url=federation_base_url, request_parameters=request_parameters
        )
        return request_url


def fetch_aws_sts_token(
    role_arn: str,
    principal_arn: str,
    assertion: str,
    duration_seconds: Optional[int] = 3600,
    aws_profile: Optional[str] = None,
) -> Mapping[str, str]:
    """Use the assertion to get an AWS STS token using `assume_role_with_saml`"""

    sts = sts_client(aws_profile)
    token = sts.assume_role_with_saml(
        RoleArn=role_arn,
        PrincipalArn=principal_arn,
        SAMLAssertion=assertion,
        DurationSeconds=duration_seconds,
    )
    return token


def fetch_aws_sts_token_assume_role(
    role_arn: str,
    role_session_name: str,
    aws_profile: str,
    duration_seconds: Optional[int] = 3600,
) -> Mapping[str, str]:
    """Use the assertion to get an AWS STS token using `assume_role_with_saml`"""

    sts = sts_client(aws_profile)
    try:
        token = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
            DurationSeconds=duration_seconds,
        )
    except ClientError as e:
        click.secho(str(e), fg="red")
        sys.exit(1)
    return token


def sts_client(aws_profile: Optional[str]) -> boto3.Session.client:
    """Generate a boto3 sts client."""

    try:
        session = boto3.Session(profile_name=aws_profile)
        sts = session.client("sts")
    except ProfileNotFound as e:
        click.secho(str(e), fg="red")
        sys.exit(1)
    except Exception as e:
        # TODO: Proper exception and message
        raise e
    return sts
