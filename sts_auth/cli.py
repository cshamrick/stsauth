#!/usr/bin/env python

import os
import re
import sys

import click
import click_log
import configparser

from sts_auth import utils
from sts_auth import stsauth
from sts_auth.stsauth import STSAuth

click_log.basic_config(utils.logger)


@click.group()
@click_log.simple_verbosity_option(utils.logger)
@click.version_option()
def cli():
    pass


@cli.command()
@click.option('--username', '-u', help='IdP endpoint username.', prompt=True)
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=False, help='Program will prompt for input if not provided.')
@click.option('--idpentryurl', '-i', default=None,
              help='The initial url that starts the authentication process.')
@click.option('--domain', '-d', help='The active directory domain.')
@click.option('--credentialsfile', '-c', help='Path to AWS credentials file.',
              default='~/.aws/credentials')
@click.option('--profile', '-l', help='Name of config profile.', default=None)
@click.option('--region', '-r', default=None, help='The AWS region to use. ex: us-east-1')
@click.option('--okta-org', '-k', default=None, help='The Okta organization to use. ex: my-organization')
@click.option('--okta-shared-secret', '-s', default=None,
              help=(
                  'Okta Shared Secret for TOTP Authentication. '
                  '\nWARNING! Please use push notifications if at all possible. '
                  'Unless you are aware of what you are doing, this method could '
                  'potentially expose your Shared Secret. '
                  'Proceed with caution and use a tool like `pass` to securely store your secrets.'
              )
              )
@click.option('--output', '-o', default=None, type=click.Choice(['json', 'text', 'table']))
@click.option('--force', '-f', is_flag=True, help='Auto-accept confirmation prompts.')
def authenticate(username, password, idpentryurl, domain,
                 credentialsfile, profile, okta_org,
                 okta_shared_secret, region, output, force):

    sts_auth = STSAuth(
        username=username,
        password=password,
        credentialsfile=credentialsfile,
        idpentryurl=idpentryurl,
        profile=profile,
        okta_org=okta_org,
        okta_shared_secret=okta_shared_secret,
        domain=domain,
        region=region,
        output=output
    )

    if not sts_auth.config_file_is_valid:
        sys.exit(1)

    if not sts_auth.credentials_expired and not force:
        prompt_for_unexpired_credentials(sts_auth.profile)

    sts_auth.parse_config_file()

    saml_response = sts_auth.get_saml_response()
    adfs_response = sts_auth.fetch_aws_account_names(saml_response)
    if adfs_response is not None:
        account_map = utils.parse_aws_account_names_from_response(adfs_response)
    else:
        account_map = utils.parse_aws_account_names_from_config(sts_auth.config)
    # Parse the returned assertion and extract the authorized roles
    awsroles = utils.parse_roles_from_assertion(saml_response.assertion)
    account_roles = utils.format_roles_for_display(awsroles, account_map)
    account_roles_len = len(account_roles)
    account_roles_vals_len = len(list(account_roles.values())[0])

    if profile:
        # If a profile is passed in, use that
        role = parse_arn_from_input_profile(account_roles, profile)
    elif ((account_roles_len > 1) or (account_roles_len == 1 and account_roles_vals_len > 1)):
        # If there is more than one account or there is one account with multiple roles, prompt
        role = prompt_for_role(account_map, account_roles)
    elif account_roles_len == 1 and account_roles_vals_len == 1:
        # If there is one account and only one role, use it
        role = account_roles.values()[0][0]
    else:
        click.secho('No roles are available. Please verify in the ADFS Portal.', fg='red')

    role_arn, principal_arn = role.get('attr').split(',')
    acct_name = role.get('name', '')
    acct_id = role.get('id', '')
    # Generate a safe-name for the profile based on acct no. and role
    role_for_section = parse_role_for_profile(role_arn)

    # Update to use the selected profile and re-check expiry
    sts_auth.profile = role_for_section
    if not profile and not sts_auth.credentials_expired and not force:
        prompt_for_unexpired_credentials(sts_auth.profile)

    click.secho("\nRequesting credentials for role: " + role_arn, fg='green')

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    token = sts_auth.fetch_aws_sts_token(role_arn, principal_arn, saml_response.assertion)

    # Put the credentials into a role specific section
    sts_auth.write_to_configuration_file(token, acct_name, acct_id, role_for_section)

    # Give the user some basic info as to what has just happened
    msg = (
        '\n------------------------------------------------------------\n'
        'Your new access key pair has been generated with the following details:\n'
        '------------------------------------------------------------\n'
        'File Path: {config_file}\n'
        'Profile: {role}\n'
        'Expiration Date: {expiry}\n'
        '------------------------------------------------------------\n'
        'To use this credential, call the AWS CLI with the --profile option:\n'
        'e.g. aws --profile {role} ec2 describe-instances\n'
        'Or provided as an environment variable:\n'
        'export AWS_PROFILE={role}\n'
        '--------------------------------------------------------------\n'
        .format(config_file=sts_auth.credentialsfile,
                expiry=token.get('Credentials', {}).get('Expiration', ''),
                role=role_for_section)
    )
    click.secho(msg, fg='green')


@cli.command()
@click.option('--credentialsfile', '-c', help='Path to AWS credentials file.',
              default='~/.aws/credentials')
@click.argument('profile', nargs=1, required=False)
@click.option('--query', '-q', help='Value to query from the profile.')
def profiles(credentialsfile, profile, query):
    """Lists the profile details from the credentialsfile or a specified profile.

    Args:
        credentialsfile: the file containing the profile details.
        profile: (Optional) a specific profile to print details for.
    """
    credentialsfile = os.path.expanduser(credentialsfile)
    config = configparser.RawConfigParser()
    config.read(credentialsfile)

    if profile is None:
        if query is not None:
            click.secho("When using the 'query' parameter, 'profile' is required.", fg='red')
            sys.exit(1)
        else:
            headers = ['Account', 'Profile', 'Expire Date', 'Status']
            profiles = fetch_profiles_from_config(config)
            print_table_format(headers, profiles)
    else:
        if config.has_section(profile):
            if query is not None:
                fetch_profile_attribute(config, profile, query)
            else:
                print_profile(config, profile)
        else:
            msg = "Section '{}' does not exist in {}!"
            click.secho(msg.format(profile, credentialsfile), fg='red')
            sys.exit(1)


def fetch_profiles_from_config(config):
    profiles = config.sections()
    expiry = []
    statuses = []
    accounts = []

    for profile in profiles:
        account = config.get(profile, 'account', fallback='None')
        accounts.append(account)

        profile_expiry = config.get(profile, 'aws_credentials_expiry', fallback=None)
        profile_expiry_string = str(utils.from_epoch(profile_expiry)) if profile_expiry else 'No Expiry Set'
        expiry.append(profile_expiry_string)

        is_active = utils.is_profile_active(config, profile)
        statuses.append('Active' if is_active else 'Expired')

    return [accounts, profiles, expiry, statuses]


def print_table_format(headers, values):
    """Formats and prints tabular formatted data.

    headers = ['col1', 'col2']
    values  = [
        ['row1col1', 'row2col1'],
        ['row1col2', 'row2col2']
    ]

    Output:
    col1     col2
    -------- --------
    row1col1 row2col1
    row1col2 row2col2

    Args:
        headers: A list of the headers for each column.
        values: A list of lists, each list containing a column of data.
    """
    if len(headers) != len(values):
        raise Exception("Not enough headers for columns.")
    row_format = ""
    max_lens = []
    for i, v in enumerate(values):
        row_format += "{{{0}:<{{{1}}}}} ".format(i * 2, (i * 2) + 1)
        v.insert(0, headers[i])
        max_len = len(max(v, key=len))
        max_lens.append(max_len)
        v.insert(1, ('-' * max_len))

    row_len = len(values) + len(max_lens)
    for row_items in zip(*values):
        row = [None] * row_len
        row[::2] = row_items
        row[1::2] = max_lens
        print(row_format.format(*row))


def print_profile(config, profile):
    click.secho('[{}]'.format(profile), fg='green')
    for k, v in config.items(profile):
        click.secho('{}='.format(k), fg='blue', nl=False)
        if k == 'aws_credentials_expiry':
            v = '{} ({})'.format(v, str(utils.from_epoch(v)))
        click.secho(v, fg='green')

    click.secho('status=', fg='blue', nl=False)
    if utils.is_profile_active(config, profile):
        click.secho('active', fg='green')
    else:
        click.secho('expired', fg='red')


def fetch_profile_attribute(config, profile, query):
    profile_attributes = dict(config.items(profile))
    is_active = utils.is_profile_active(config, profile)
    profile_attributes['status'] = 'active' if is_active else 'expired'
    attribute_value = profile_attributes.get(query)

    if attribute_value is None:
        click.secho("Invalid value {!r} for 'query' parameter. Valid choices:".format(query), fg='red')
        click.secho(", ".join(profile_attributes.keys()), fg='red')
        sys.exit(1)
    else:
        click.secho(attribute_value)


def prompt_for_role(account_map, account_roles):
    """Prompts the user to select a role based off what roles are available to them.

    Provides a prompt listing out accounts available to the user and does some basic
    checks to validate their input. If the input is invalid, re-prompts the user.

    Args:
        account_map: dictionary of account ids and account names
        account_roles: dictionary of account and role details

    Returns:
        Set containing the selected Role ARN and Principal ARN
    """
    click.secho('Please choose the role you would like to assume:', fg='green')
    for acct_id, roles in account_roles.items():
        acct_name = account_map.get(acct_id, '')
        click.secho('Account: {} ({})'.format(acct_name, acct_id), fg='blue')
        for role in roles:
            click.secho('[{num}]: {label}'.format(**role))
        click.secho('')
    click.secho('Selection: ', nl=False, fg='green')
    selected_role_index = input()
    selected_role_index = int(selected_role_index)
    flat_roles = [i for sl in account_roles.values() for i in sl]

    # Basic sanity check of input
    if not role_selection_is_valid(selected_role_index, flat_roles):
        return prompt_for_role(account_map, account_roles)

    role = next((v for v in flat_roles if v['num'] == selected_role_index), None)

    return role


def role_selection_is_valid(selection, account_roles):
    """Checks that the user input is a valid selection

    Args:
        selection: Value the user entered.
        account_roles: List of valid roles to check against.

    Returns:
        Boolean reflecting the validity of given choice.
    """
    err_msg = 'You selected an invalid role index, please try again'
    try:
        selection
    except ValueError:
        click.secho(err_msg, fg='red')
        return False

    if selection not in range(len(account_roles)):
        click.secho(err_msg, fg='red')
        return False

    return True


def parse_role_for_profile(role):
    """Returns a 'safe' profile name for a given role.

    Args:
        role: The role to generate a profile name for.

    Returns:
        Formatted profile name.
    """
    account_id = '000000000000'
    role_name = 'Unknown-Role-Name'

    account_re = re.compile(r'::(\d+):')
    _account_id = re.search(account_re, role)
    _role_name = role.split('/')
    if _account_id.groups():
        account_id = _account_id.groups()[0]
    if len(_role_name) == 2:
        role_name = _role_name[1]

    return '{}-{}'.format(account_id, role_name)


def prompt_for_unexpired_credentials(profile):
    """Prompts the user if the given profile's credentials have not expired yet.

    Args:
        profile: The profile for which a user is requesting credentials.
    """
    click.secho('\nCredentials for the following profile are still valid:', fg='red')
    click.secho(profile, fg='red')
    click.echo()
    msg = click.style('Would you like to continue?', fg='red')
    click.confirm(msg, abort=True)


def parse_arn_from_input_profile(account_roles, profile):
    """Given a list of account/role details, return the ARNs for the given profile

    Args:
        account_roles: List of dictionaries containing account/role details
        profile: A user-provided profile to retreive the ARN from the account_roles.

    Returns:
        A set with the Role ARN and the Principal ARN. If the profile does not exist, exits the cli.
    """
    click.echo()
    profile_split = profile.split('-')
    acct_number = profile_split[0]
    role_name = '-'.join(profile_split[1:])
    role = next((item for item in account_roles[acct_number] if item['label'] == role_name), None)
    if role is None:
        click.secho(
            'Profile not found!\n'
            'Please check `stsauth profiles` for a list of available profiles\n'
            'or use `stsauth authenticate` to view profiles available to your user.\n'
            'The profile may no longer be available to your user.',
            fg='red'
        )
        sys.exit()
    return role
