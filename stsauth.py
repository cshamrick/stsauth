import os
import re
import sys
import time
import base64
import configparser
from collections import defaultdict
from datetime import datetime
from xml.etree import ElementTree
import logging

import boto3
import click
import requests
import pyotp
from requests_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup

try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

logger = logging.getLogger(__name__)


class STSAuth:
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
    def __init__(self, username, password, credentialsfile,
                 idpentryurl=None, profile=None, okta_org=None,
                 okta_shared_secret=None, domain=None, region=None,
                 output=None, force=False):
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
        self.session = requests.Session()

        self.session.headers.update({'content-type': 'application/json'})
        self.session.auth = HttpNtlmAuth(self.domain_user, self.password)
        self.config = configparser.RawConfigParser()
        self.config.read(self.credentialsfile)

    @property
    def domain_user(self):
        if self.domain:
            return '{0.domain}\\{0.username}'.format(self)
        else:
            return self.username

    @property
    def config_file_is_valid(self):
        valid = True
        url = self.config.get('default', 'idpentryurl', fallback=self.idpentryurl)
        domain = self.config.get('default', 'domain', fallback=self.domain)
        region = self.config.get('default', 'region', fallback=self.region)
        output = self.config.get('default', 'output', fallback=self.output)

        _map = {'idpentryurl': url, 'domain': domain, 'region': region, 'output': output}
        items = [k for k, v in _map.items() if not v]
        if items:
            msg = ('Config value missing for the items {}.\n'
                   'Please add these to {} or provide them '
                   'through CLI flags (see `stsauth --help`) and try again.'
                   .format(items, self.credentialsfile))
            click.secho(msg, fg='red')
            valid = False
        return valid

    @property
    def credentials_expired(self):
        if self.config.has_section(self.profile):
            expiry = self.config.get(self.profile, 'aws_credentials_expiry', fallback=None)
            if expiry:
                return from_epoch(expiry) <= datetime.now()
        else:
            return True

    def parse_config_file(self):
        """Read configuration file and only set values if they
        were not passed in from the CLI.
        """
        if self.config.has_section('default'):
            logger.debug('Found \'default\' section in'
                         ' {0.credentialsfile!r}!'.format(self))
            default = self.config['default']
            msg = ('Attribute {1!r} not set, using value from {0.credentialsfile!r}')
            if not self.region:
                logger.debug(msg.format(self, 'region'))
                self.region = default.get('region')
            if not self.output:
                logger.debug(msg.format(self, 'output'))
                self.output = default.get('output')
            if not self.idpentryurl:
                logger.debug(msg.format(self, 'idpentryurl'))
                self.idpentryurl = default.get('idpentryurl')
            if not self.domain:
                logger.debug(msg.format(self, 'domain'))
                self.domain = default.get('domain')
            if not self.okta_org:
                logger.debug(msg.format(self, 'okta_org'))
                self.okta_org = default.get('okta_org')
            if not self.okta_shared_secret:
                logger.debug(msg.format(self, 'okta_shared_secret'))
                self.okta_shared_secret = default.get('okta_shared_secret')
        else:
            logger.debug('Could not find \'default\' section in'
                         ' {0.credentialsfile!r}!'.format(self))

    def get_saml_response(self, response=None):
        if not response:
            logger.debug('No response provided. Fetching IDP Entry URL...')
            response = self.session.get(self.idpentryurl)
        response.soup = BeautifulSoup(response.text, "lxml")
        assertion_pattern = re.compile(r'name=\"SAMLResponse\" value=\"(.*)\"\s*/><noscript>')
        assertion = re.search(assertion_pattern, response.text)

        if assertion:
            # If there is already an assertion in the response, we can simply
            # return that and continue, otherwise, we will have to dance
            # through authentication.
            return assertion.groups()[0]

        login_form = response.soup.find(id='loginForm')
        okta_login = response.soup.find(id='okta-login-container')

        if okta_login:
            # If there is no assertion, and we find an Okta portal on the page,
            # we have to pass through the Okta portal regardless of whether MFA
            # will be required or not.
            if not self.okta_org:
                msg = ('Okta MFA required but no Okta Organization set. '
                'Please either set in the config or use `--okta-org`')
                click.secho(msg, fg='red')
                sys.exit(1)

            logger.debug('No SAML assertion found in response. Attempting to begin MFA...')
            verification_status = self.get_verification_status_from_response(response)
            logger.debug('Current Verification Status: {}.'.format(verification_status))
            if verification_status == 'success':
                logger.debug('Okta portal already authenticated, passing through...')
                # If the Okta portal status is already 'success', we can just
                # pass through the Okta portal, otherwise, we will have to do MFA.
                okta_form_submit_response = self.submit_adapter_glue_form(response)
                return self.get_saml_response(okta_form_submit_response)
            elif verification_status == 'mfa_required':
                # If the Okta portal is in 'mfa_required' status,
                # we need to begin the MFA process.
                mfa_verified = self.process_okta_mfa(response)
                if mfa_verified:
                    okta_response = self.submit_adapter_glue_form(response)
                    return self.get_saml_response(response=okta_response)
            else:
                click.secho('Okta verification failed. Exiting...', fg='red')
                sys.exit(1)

        if login_form:
            # If there is no assertion, it is possible the user is attempting
            # to authenticate from outside the network, so we check for a login
            # form in their response.
            logger.debug('No SAML assertion found in response. Attempting to log in...')
            form_response = self.authenticate_to_adfs_portal(response)
            return self.get_saml_response(response=form_response)

        else:
            msg = 'Response did not contain a valid SAML assertion, a valid login form, or request MFA.'
            click.secho(msg, fg='red')
            sys.exit(1)

    def process_okta_mfa(self, response):
        state_token = self.get_state_token_from_response(response)
        okta_available_factors = self.fetch_available_mfa_factors(state_token)
        if 'token:software:totp' in okta_available_factors.keys():
            logger.debug('Okta TOTP Verification Method available, attempting to verify...')
            totp_factor = okta_available_factors.get('token:software:totp')
            if self.okta_totp_verification(state_token, totp_factor):
                return True
        if 'push' in okta_available_factors.keys():
            logger.debug('Okta Push Verification Method available, attempting to verify...')
            push_factor = okta_available_factors.get('push')
            if self.poll_for_okta_push_verification(state_token, push_factor):
                return True
        return False

    def get_verification_status_from_response(self, response):
        status_search = re.search(re.compile(r"var status = '(.*?)';"), response.text)
        if status_search:
            if len(status_search.groups()) == 1:
                return status_search.groups()[0]
        click.secho('No Verification Status found in response. Exiting...', fg='red')
        sys.exit(1)

    def get_state_token_from_response(self, response):
        state_token_search = re.search(re.compile(r"var stateToken = '(.*?)';"), response.text)
        if state_token_search:
            if len(state_token_search.groups()) == 1:
                state_token = state_token_search.groups()[0]
                logger.debug('Found state_token: {}'.format(state_token))
                return state_token
        click.secho('No State Token found in response. Exiting...', fg='red')
        sys.exit(1)

    def submit_adapter_glue_form(self, response):
        response.soup = BeautifulSoup(response.content, 'lxml')
        adapter_glue_form = response.soup.find(id='adapterGlue')
        referer = response.url
        self.session.headers.update({'Referer': referer})
        selectors = ",".join("{}[name]".format(i) for i in ("input", "button", "textarea", "select"))
        data = [(tag.get('name'), tag.get('value')) for tag in adapter_glue_form.select(selectors)]
        logger.debug('Posting data to url: {}\n{}'.format(referer, data))
        return self.session.post(referer, data=data)

    def fetch_available_mfa_factors(self, state_token):
        okta_auth_url = 'https://{}.okta.com/api/v1/authn'.format(self.okta_org)
        okta_transaction_state = self.session.post(
            okta_auth_url,
            json={'stateToken': state_token}
        )
        okta_factors = okta_transaction_state.json().get('_embedded', {}).get('factors', {})
        if len(okta_factors) > 0:
            # Format the factors as {factorType: {details..}, ..}
            # so it will be easier to pick pull out by type later
            return {f['factorType']: f for f in okta_factors}
        else:
            click.secho('No Okta MFA Verification Factors available. Exiting...')
            sys.exit(1)

    def okta_totp_verification(self, state_token, factor_details):
        if not self.okta_shared_secret:
            logger.debug(
                'TOTP Verification available but Okta Shared Secret '
                'is not set. For instructions to set the Shared Secret, '
                'refer to the README: '
                'https://github.com/cshamrick/stsauth/blob/master/README.md'
            )
            return False

        totp = pyotp.TOTP(self.okta_shared_secret)
        verify_url = factor_details.get('_links', {}).get('verify', {}).get('href')
        data = {'stateToken': state_token, 'passCode': totp.now()}
        if verify_url:
            verify_response = self.session.post(verify_url, json=data)
            if verify_response.ok:
                status = verify_response.json().get('status')
                if status == 'SUCCESS':
                    return True
        click.secho(
            'TOTP Verification failed. '
            'Continuing to other methods if available', fg='red'
        )
        return False

    def poll_for_okta_push_verification(self, state_token, factor_details, max_retries=10, poll_delay=10):
        status = 'MFA_CHALLENGE'
        tries = 0
        verify_data = {'stateToken': state_token}
        verify_url = factor_details.get('_links', {}).get('verify', {}).get('href')
        if verify_url == None:
            click.secho('No Okta verification URL present in response. Exiting...', fg='red')
            sys.exit(1)
        while (status == 'MFA_CHALLENGE' and tries < max_retries):

            verify_response = requests.post(verify_url, json=verify_data)
            if verify_response.ok:
                verify_response_json = verify_response.json()
                logger.debug('Okta Verification Response:\n{}'.format(verify_response_json))
                status = verify_response_json.get('status', 'MFA_CHALLENGE')

                if verify_response_json.get('factorResult') == 'REJECTED':
                    click.secho('Okta push notification was rejected! Exiting...', fg='red')
                    sys.exit(1)
                if status == 'SUCCESS':
                    break
                tries += 1
                click.secho(
                    '({}/{}) Waiting for Okta push notification to be accepted...'.format(tries, max_retries),
                    fg='green'
                )
                time.sleep(poll_delay)

        if status != 'SUCCESS':
            return False

        return True

    def generate_payload_from_login_page(self, response):
        login_page = BeautifulSoup(response.text, "html.parser")
        payload = {}

        for input_tag in login_page.find_all(re.compile('(INPUT|input)')):
            name = input_tag.get('name', '')
            value = input_tag.get('value', '')
            logger.debug('Adding value for {!r} to Login Form payload.'.format(name))
            if "user" in name.lower():
                payload[name] = self.domain_user
            elif "email" in name.lower():
                payload[name] = self.domain_user
            elif "pass" in name.lower():
                payload[name] = self.password
            else:
                payload[name] = value

        return payload

    def build_idp_auth_url(self, response):
        idp_auth_form_submit_url = response.url
        login_page = BeautifulSoup(response.text, "html.parser")

        for form in login_page.find_all(re.compile('(FORM|form)')):
            action = form.get('action')
            if action:
                parsed_action = urlparse(action)
                parsed_idp_url = urlparse(self.idpentryurl)
                # Fallback to the IDP Entry URL from the config file if the
                # form action does not contain a fully defined URL.
                # i.e. action='/path/to/something' vs action='http://test.com/path/to/something'
                scheme = parsed_action.scheme if parsed_action.scheme else parsed_idp_url.scheme
                netloc = parsed_action.netloc if parsed_action.netloc else parsed_idp_url.netloc
                url_parts = (scheme, netloc, parsed_action.path, None, parsed_action.query, None)
                idp_auth_form_submit_url = urlunparse(url_parts)

        return idp_auth_form_submit_url

    def authenticate_to_adfs_portal(self, response):
        payload = self.generate_payload_from_login_page(response)
        idp_auth_form_submit_url = self.build_idp_auth_url(response)

        logger.debug('Posting login data to URL: {}'.format(idp_auth_form_submit_url))
        login_response = self.session.post(
            idp_auth_form_submit_url,
            data=payload,
            verify=True
        )
        login_response_page = BeautifulSoup(login_response.text, "html.parser")
        login_error_message = login_response_page.find(id='errorText')
        if login_error_message and len(login_error_message.string) > 0:
            msg = ('Login page returned the following message. '
                   'Please resolve this issue before continuing:')
            click.secho(msg, fg='red')
            click.secho(login_error_message.string, fg='red')
            sys.exit(1)
        return login_response

    def fetch_aws_sts_token(self, role_arn, principal_arn, assertion, duration_seconds=3600):
        """Use the assertion to get an AWS STS token using `assume_role_with_saml`
        """
        try:
            sts = boto3.client('sts')
        except Exception:
            # TODO: Proper exception and message
            raise

        token = sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=assertion,
            DurationSeconds=duration_seconds
        )
        return token

    def write_to_configuration_file(self, token, profile=None):
        """Store credentials in a specific profile.

        Takes the credentials and details from the token provided and writes them out to a
        configuration

        Args:
            token: Object containing the credentials to write out.
            profile: optional profile paramater. Uses the class profile if undefined
        """
        if profile is None:
            profile = self.profile

        if not self.config.has_section(profile):
            self.config.add_section(profile)

        if not self.config.has_section('default'):
            self.config.add_section('default')

        self.config.set('default', 'idpentryurl', self.idpentryurl)

        credentials = token.get('Credentials', {})
        expiration = to_epoch(credentials.get('Expiration', ''))
        self.config.set(profile, 'output', self.output)
        self.config.set(profile, 'region', self.region)
        self.config.set(profile, 'aws_access_key_id', credentials.get('AccessKeyId', ''))
        self.config.set(profile, 'aws_secret_access_key', credentials.get('SecretAccessKey', ''))
        self.config.set(profile, 'aws_session_token', credentials.get('SessionToken', ''))
        self.config.set(profile, 'aws_credentials_expiry', expiration)

        # Write the AWS STS token into the AWS credential file
        with open(self.credentialsfile, 'w') as f:
            self.config.write(f)


def format_roles_for_display(attrs):
    """Formats role ARNs for display to the user and a dictionary for lookup.

    We need two objects so that we can easily display a pretty list to the user
    which requests their input. Once they provide input, we need to determine
    which ARN was mapped to their input.

    Args:
        attrs: List of ARNs/roles.

    Returns:
        List of dictionaries used to display to the user
        Dictionary mapping input values to ARNs
    """
    account_roles = defaultdict(list)
    account_lookup = {}
    for attr in attrs:
        _attr = attr.split(',')
        role = _attr[0] if ':role/' in _attr[0] else _attr[1]
        acct_id = get_account_id_from_role(role)
        acct_name = role.split('/')[1]
        item = {'label': acct_name, 'attr': attr, 'id': acct_id}
        account_roles[acct_id].append(item)
    i = 0
    for _, roles in account_roles.items():
        for role in roles:
            role['key'] = i
            account_lookup[i] = role['attr']
            i += 1
    return account_roles, account_lookup


def parse_roles_from_assertion(xml_body):
    """Given the xml_body assertion, return a list of roles.

    Args:
        xml_body: XML Body containing roles returned from AWS.

    Returns:
        List of roles available to the user.
    """
    roles = []
    root = ElementTree.fromstring(base64.b64decode(xml_body))
    role = 'https://aws.amazon.com/SAML/Attributes/Role'
    attr_base = '{urn:oasis:names:tc:SAML:2.0:assertion}'
    attr = '{}Attribute'.format(attr_base)
    attr_value = '{}Value'.format(attr)
    for saml2attr in root.iter(attr):
        if saml2attr.get('Name') == role:
            for saml2attrvalue in saml2attr.iter(attr_value):
                roles.append(saml2attrvalue.text)
    roles = format_role_order(roles)
    return roles


def format_role_order(roles):
    """Given roles, returns them in the format: role_arn,principal_arn.

    The format of the attribute value should be role_arn,principal_arn
    but lots of blogs list it as principal_arn,role_arn so let's reverse
    them if needed.

    Args:
        roles: List of roles.

    Returns:
        List of roles in the format: role_arn,principal_arn
    """
    for role in roles:
        chunks = role.split(',')
        if 'saml-provider' in chunks[0]:
            newrole = chunks[1] + ',' + chunks[0]
            index = roles.index(role)
            roles.insert(index, newrole)
            roles.remove(role)
    return roles


def get_account_id_from_role(role):
    """Parse the account ID from the role.

    Args:
        role: Role string with account ID.

    Returns:
        Account ID.

    Raises:
        Exception: An error occured with getting the Account ID.
    """
    acct_id_re = re.compile(r'::(\d+):')
    acct_ids = re.search(acct_id_re, role)
    if acct_ids.groups():
        for ids in acct_ids.groups():
            if len(ids) == 12:
                return ids
    else:
        raise Exception('Missing or malformed account ID!')


def to_epoch(dt):
    """Given a datetime object, return seconds since epoch.

    Args:
        dt: Datetime object

    Returns:
        seconds since epoch for dt
    """
    dt = dt.replace(tzinfo=None)
    return (dt - datetime(1970, 1, 1)).total_seconds()


def from_epoch(seconds):
    """Given seconds since epoch, return a datetime object

    Args:
        seconds: Seconds since epoch

    Returns:
        datetime representation of seconds since epoch
    """
    return datetime.fromtimestamp(int(float(seconds)))
