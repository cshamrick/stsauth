import os
import re
import base64
import logging
from datetime import datetime
from collections import defaultdict
from xml.etree import ElementTree

logger = logging.getLogger(__name__)


def get_state_token_from_response(response):
    state_token_search = re.search(re.compile(r"var stateToken = '(.*?)';"), response.text)
    if state_token_search:
        if len(state_token_search.groups()) == 1:
            return state_token_search.groups()[0]


def format_roles_for_display(attrs):
    """Formats role ARNs for display to the user and a dictionary for lookup.

    We need two objects so that we can easily display a pretty list to the user
    which requests their input. Once they provide input, we need to determine
    which ARN was mapped to their input.

    Args:
        attrs: List of ARNs/roles.

    Returns:
        List of dictionaries used to display to the user
    """
    accts = []
    for attr in attrs:
        _attr = attr.split(',')
        role = _attr[0] if ':role/' in _attr[0] else _attr[1]
        acct_id = get_account_id_from_role(role)
        acct_name = role.split('/')[1]
        item = {'label': acct_name, 'attr': attr, 'id': acct_id}
        accts.append(item)
    sorted_acct_roles = [k for k in sorted(accts, key=lambda k: k['id'])]
    account_roles = defaultdict(list)
    for i, v in enumerate(sorted_acct_roles):
        v['num'] = i
        account_roles[v['id']].append(v)
    return account_roles


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


def unset_proxy():
    """Remove proxy settings from the current process
    """
    env_vars = [
        "http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "FTP_PROXY"
    ]
    for var in env_vars:
        if var in os.environ:
            logger.debug('Unsetting {!r} environment variable!'.format(var))
            del os.environ[var]