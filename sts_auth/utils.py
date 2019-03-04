import os
import re
import base64
import logging
from datetime import datetime
from collections import defaultdict
from xml.etree import ElementTree

logger = logging.getLogger(__name__)


def get_state_token_from_response(response_text):
    state_token_search = re.search(re.compile(r"var stateToken = '(.*?)';"), response_text)
    group_len = 0 if state_token_search is None else len(state_token_search.groups())
    if group_len == 1:
        return state_token_search.group(1)
    return None


def parse_aws_account_names_from_response(response):
    acct_map = {}
    for _acct in response.soup.find_all('div', {'class': 'saml-account-name'}):
        acct = _acct.contents[0]
        acct_id = acct.split(' ')[2].strip('()')
        acct_name = acct.split(' ')[1]
        acct_map[acct_id] = acct_name
    return acct_map


def format_roles_for_display(attrs, account_map):
    """Formats role ARNs for display to the user.

    Args:
        attrs: List of ARNs/roles.
        account_map: Dictionary of account id and account name pairs.

    Returns:
        Dictionary used to display roles/accounts to the user
    """
    accts = []
    for attr in attrs:
        role = attr.split(',')[0]
        acct_id = get_account_id_from_role(role)
        acct_name = account_map.get(acct_id, '')
        role_name = role.split('/')[1]
        item = {'label': role_name, 'attr': attr, 'id': acct_id, 'name': acct_name}
        accts.append(item)
    sorted_acct_roles = [k for k in sorted(accts, key=lambda k: k['id'])]
    account_roles = defaultdict(list)
    for i, v in enumerate(sorted_acct_roles):
        v['num'] = i
        account_roles[v['id']].append(v)
    return account_roles


def parse_roles_from_assertion(assertion):
    """Given the base64 encoded assertion, return a list of roles.

    Args:
        assertion: base64 encoded XML Body containing roles returned from AWS.

    Returns:
        List of roles available to the user.
    """
    roles = []
    xml = base64.b64decode(assertion)
    root = ElementTree.fromstring(xml)
    role = 'https://aws.amazon.com/SAML/Attributes/Role'
    attr_base = '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
    attr_value = '{}Value'.format(attr_base)

    for attr in root.iter(attr_base):
        if attr.get('Name') == role:
            for attrvalue in attr.iter(attr_value):
                roles.append(attrvalue.text)
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
            _role = chunks[1] + ',' + chunks[0]
            index = roles.index(role)
            roles.insert(index, _role)
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
    acct_id_re = re.compile(r'::(\d{12}):')
    acct_id = set(re.findall(acct_id_re, role))
    if len(acct_id) == 1:
        return acct_id.pop()
    else:
        raise Exception('Missing or malformed account ID in {}!'.format(role))


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
    return datetime.utcfromtimestamp(float(seconds))


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