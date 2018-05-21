import os
import re
import sys
import base64
import configparser
from datetime import datetime
from dateutil.tz import tzutc
from xml.etree import ElementTree

import boto3
import click
import requests
from requests_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


##########################################################################
# Variables

# REGION: The default AWS REGION that this script will connect to for all API calls
# region = 'us-east-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
# output = 'json'

# awscredentialsfile: The file where this script will store credentials under the saml profile
# awscredentialsfile = '~/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
# sslverification = True

# idpentryurl: The initial url that starts the authentication process.
# idpentryurl = ('https://<fdqn>/adfs/ls/'
#                'idpinitiatedsignon.aspx?LoginToRP=urn:amazon:webservices')

##########################################################################

class STSAuth:
    def __init__(self, username, password, credentialsfile,
                 idpentryurl=None, domain=None, region=None, output=None):
        # TODO: Clean up the following conditional, it's just non-pythonic:
        if domain:
            self.domain = domain + '\\{}'
            self.username = self.domain.format(username)
        else:
            self.domain = None
            self.username = username
        self.password = password
        self.credentialsfile = os.path.expanduser(credentialsfile)
        self.idpentryurl = idpentryurl
        self.region = region
        self.output = output
        self.session = requests.Session()

        self.session.auth = HttpNtlmAuth(self.username, self.password)
        self.config = configparser.RawConfigParser()
        self.config.read(self.credentialsfile)

    @property
    def config_file_is_valid(self):
        valid = True
        url = self.config.get('default', 'idpentryurl', fallback=self.idpentryurl)
        domain = self.config.get('default', 'domain', fallback=self.domain)
        region = self.config.get('default', 'region', fallback=self.region)
        output = self.config.get('default', 'output', fallback=self.output)

        if not (url and region and output):
            _map = {'idpentryurl': url, 'domain': domain, 'region': region, 'output': output}
            items = [k for k, v in _map.items() if not v]
            msg = ('Config value missing for the items {}.\n'
                   'Please add these to {} or provide them '
                   'through CLI flags (see `stsauth --help`) and try again.'
                   .format(items, self.credentialsfile))
            valid = False
        else:
            valid = True

        if not valid:
            click.secho(msg, fg='red')
        return valid

    @property
    def credentials_expired(self):
        if self.config.has_section('saml'):
            expiry = self.config.get('saml', 'aws_credentials_expiry', fallback=None)
            if expiry:
                return from_epoch(expiry) <= datetime.now()
        else:
            return True

    def parse_config_file(self):
        """Read configuration file and only set values if they
        were not passed in from the CLI.
        """
        if self.config.has_section('default'):
            default = self.config['default']
            if not self.region:
                self.region = default.get('region')
            if not self.output:
                self.output = default.get('output')
            if not self.idpentryurl:
                self.idpentryurl = default.get('idpentryurl')
            if not self.domain:
                self.domain = default.get('domain') + '\\{}'
                self.username = self.domain.format(self.username)

    def get_saml_response(self, response=None):
        if not response:
            response = self.session.get(self.idpentryurl)
        pattern = re.compile(r'name=\"SAMLResponse\" value=\"(.*)\"\s*/><noscript>')
        assertion = re.search(pattern, response.text)
        # TODO: Better error handling is required for production use.
        if assertion is None:
            # If there is no assertion, it is possible the user is attempting
            # to authenticate from outside the network, so we check for a login
            # form in their response.
            form_pattern = re.compile('(FORM|form)')
            form_exists = re.search(form_pattern, response.text)
            if form_exists:
                form_response = self.get_saml_response_from_login_form(response)
                return self.get_saml_response(form_response)
            else:
                msg = 'Response did not contain a valid SAML assertion nor a valid login form.'
                click.secho(msg, fg='red')
                sys.exit(1)
        else:
            return assertion.groups()[0]

    def get_saml_response_from_login_form(self, response):
        idp_auth_form_submit_url = response.url
        form = BeautifulSoup(response.text, "html.parser")
        payload = {}

        for input_tag in form.find_all(re.compile('(INPUT|input)')):
            name = input_tag.get('name', '')
            value = input_tag.get('value', '')
            if "user" in name.lower():
                payload[name] = self.username
            elif "email" in name.lower():
                payload[name] = self.username
            elif "pass" in name.lower():
                payload[name] = self.password
            else:
                payload[name] = value

        for input_tag in form.find_all(re.compile('(FORM|form)')):
            action = input_tag.get('action')
            if action:
                parsed_url = urlparse(self.idpentryurl)
                idp_auth_form_submit_url = ('{0.scheme}://{0.netloc}{1}'
                                            .format(parsed_url, action))

        # TODO: need to check for valid response
        response = self.session.post(
            idp_auth_form_submit_url,
            data=payload,
            verify=True
        )
        return response

    def fetch_aws_sts_token(self, role_arn, principal_arn, assertion, duration_seconds=3600):
        """Use the assertion to get an AWS STS token using `assume_role_with_saml`
        """
        try:
            sts = boto3.client('sts')
        except Exception:
            # TODO: Proper exception and message
            raise
            sys.exit(1)
        token = sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=assertion,
            DurationSeconds=duration_seconds
        )
        return token

    def write_saml_conf(self, token):
        """Put the credentials into a saml specific profile instead of clobbering
        the default credentials.
        TODO: Need to support passing in the profile instead of defaulting to `saml`
        """
        if not self.config.has_section('saml'):
            self.config.add_section('saml')

        if not self.config.has_section('default'):
            self.config.add_section('default')

        self.config.set('default', 'idpentryurl', self.idpentryurl)

        credentials = token.get('Credentials', {})
        expiration = to_epoch(credentials.get('Expiration', ''))
        self.config.set('saml', 'output', self.output)
        self.config.set('saml', 'region', self.region)
        self.config.set('saml', 'aws_access_key_id', credentials.get('AccessKeyId', ''))
        self.config.set('saml', 'aws_secret_access_key', credentials.get('SecretAccessKey', ''))
        self.config.set('saml', 'aws_session_token', credentials.get('SessionToken', ''))
        self.config.set('saml', 'aws_credentials_expiry', expiration)

        # Write the AWS STS token into the AWS credential file
        with open(self.credentialsfile, 'w') as f:
            self.config.write(f)

    def format_role_order(self, roles):
        # The format of the attribute value should be role_arn,principal_arn
        # but lots of blogs list it as principal_arn,role_arn so let's reverse
        # them if needed
        for role in roles:
            chunks = role.split(',')
            if 'saml-provider' in chunks[0]:
                newrole = chunks[1] + ',' + chunks[0]
                index = roles.index(role)
                roles.insert(index, newrole)
                roles.remove(role)
        return roles

    def parse_roles_from_assertion(self, xml_body):
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
        roles = self.format_role_order(roles)
        return roles


def to_epoch(dt):
    return (dt - datetime(1970, 1, 1, tzinfo=tzutc())).total_seconds()


def from_epoch(seconds):
    return datetime.fromtimestamp(int(float(seconds)))
