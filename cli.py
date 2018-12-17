#!/usr/bin/env python

import os
import re
import sys
import configparser

import click
import click_log

import stsauth
from stsauth import STSAuth
from stsauth import logger

click_log.basic_config(logger)


@click.group()
@click_log.simple_verbosity_option(logger)
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
    # UNSET any proxy vars that exist in the session
    unset_proxy()

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

    assertion = sts_auth.get_saml_response()
    # Parse the returned assertion and extract the authorized roles
    awsroles = stsauth.parse_roles_from_assertion(assertion)
    account_roles, account_lookup = stsauth.format_roles_for_display(awsroles)

    if profile:
        role_arn, principal_arn = parse_arn_from_input_profile(account_roles, profile)
    elif len(account_lookup) > 1:
        role_arn, principal_arn = prompt_for_role(account_roles, account_lookup)
    else:
        role_arn, principal_arn = account_lookup.get(0).split(',')

    # Generate a safe-name for the profile based on acct no. and role
    role_for_section = parse_role_for_profile(role_arn)

    # Update to use the selected profile and re-check expiry
    sts_auth.profile = role_for_section
    if not profile and not sts_auth.credentials_expired and not force:
        prompt_for_unexpired_credentials(sts_auth.profile)

    click.secho("\nRequesting credentials for role: " + role_arn, fg='green')

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    token = sts_auth.fetch_aws_sts_token(role_arn, principal_arn, assertion)

    # Put the credentials into a role specific section
    sts_auth.write_to_configuration_file(token, role_for_section)

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
        '(e.g. aws --profile {role} ec2 describe-instances).\n'
        '--------------------------------------------------------------\n'
        .format(config_file=sts_auth.credentialsfile,
                expiry=token.get('Credentials', {}).get('Expiration', ''),
                role=role_for_section)
    )
    click.secho(msg, fg='green')


@cli.command()
@click.option('--credentialsfile', '-c', help='Path to AWS credentials file.',
              default='~/.aws/credentials')
def profiles(credentialsfile):
    """Lists the profile details from the credentialsfile.

    Prints a list to the cli containing a tabular list of Profile and Expiry:
    Profile             Expire Date
    ------------------- -----------------
    test                2018-01-01 00:00:00
    ......

    Args:
        credentialsfile: the file containing the profile details.
    """
    credentialsfile = os.path.expanduser(credentialsfile)
    config = configparser.RawConfigParser()
    config.read(credentialsfile)
    profiles = config.sections()
    headers = ['Profile', 'Expire Date']
    expiry = []

    for profile in profiles:
        profile_expiry = config.get(profile, 'aws_credentials_expiry', fallback=None)
        profile_expiry = stsauth.from_epoch(profile_expiry) if profile_expiry else 'No Expiry Set'
        expiry.append(str(profile_expiry))

    profile_max_len = len(max(profiles, key=len))
    expiry_max_len = len(max(expiry, key=len))
    row_format = "{item_0:<{item_0_len}} {item_1:<{item_1_len}}"
    print(row_format.format(
        item_0=headers[0],
        item_1=headers[1],
        item_0_len=profile_max_len,
        item_1_len=expiry_max_len)
    )
    print('-' * profile_max_len + ' ' + '-' * expiry_max_len)
    for profile in zip(profiles, expiry):
        print(row_format.format(
            item_0=profile[0],
            item_1=profile[1],
            item_0_len=profile_max_len,
            item_1_len=expiry_max_len)
        )


def prompt_for_role(account_roles, account_lookup):
    """Prompts the user to select a role based off what roles are available to them.

    Provides a prompt listing out accounts available to the user and does some basic
    checks to validate their input. If the input is invalid, re-prompts the user.

    Args:
        account_roles: list of account and role details
        account_lookup: dictionary mapping selction values to ARNs.

    Returns:
        Set containing the Role ARN  and Principal ARN
    """
    click.secho('Please choose the role you would like to assume:', fg='green')
    for acct_id, roles in account_roles.items():
        click.secho('Account {}:'.format(acct_id), fg='blue')
        for role in roles:
            click.secho('[{key}]: {label}'.format(**role))
        click.secho('')
    click.secho('Selection: ', nl=False, fg='green')
    selected_role_index = input()

    # Basic sanity check of input
    if not role_selection_is_valid(selected_role_index, account_lookup):
        return prompt_for_role(account_roles, account_lookup)

    role_arn, principal_arn = account_lookup.get(int(selected_role_index)).split(',')

    return role_arn, principal_arn


def role_selection_is_valid(selection, account_lookup):
    """Checks that the user input is a valid selection

    Args:
        selection: Value the user entered.
        account_lookup: List of valid choices to check against.

    Returns:
        Boolean reflecting the validity of given choice.
    """
    err_msg = 'You selected an invalid role index, please try again'
    try:
        int(selection)
    except ValueError:
        click.secho(err_msg, fg='red')
        return False

    if int(selection) not in range(len(account_lookup)):
        click.secho(err_msg, fg='red')
        return False

    return True


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
    arn = next((item for item in account_roles[acct_number] if item['label'] == role_name), None)
    if arn:
        role_arn, principal_arn = arn['attr'].split(',')
    else:
        click.secho(
            'Profile not found!\n'
            'Please check `stsauth profiles` for a list of available profiles\n'
            'or use `stsauth authenticate` to view profiles available to your user.\n'
            'The profile may no longer be available to your user.',
            fg='red'
        )
        sys.exit()

    return role_arn, principal_arn
