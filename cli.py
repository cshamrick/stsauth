#!/usr/bin/env python

import os
import re
import sys

import click
import click_log

from stsauth import STSAuth
from stsauth import logger

click_log.basic_config(logger)


@click.command()
@click.option('--username', '-u', help='IdP endpoint username.', prompt=True)
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=False, help='Program will prompt for input if not provided.')
@click.option('--idpentryurl', '-i', default=None,
              help='The initial url that starts the authentication process.')
@click.option('--domain', '-d', help='The active directory domain.')
@click.option('--credentialsfile', '-c', help='Path to AWS credentials file.',
              default='~/.aws/credentials')
@click.option('--profile', '-l', help='Name of config profile.', default='saml')
@click.option('--region', '-r', default=None, help='The AWS region to use. ex: us-east-1')
@click.option('--output', '-o', default=None, type=click.Choice(['json', 'text', 'table']))
@click.option('--force', '-f', is_flag=True, help='Auto-accept confirmation prompts.')
@click.version_option('--version', '-V')
@click_log.simple_verbosity_option(logger)
def cli(username, password, idpentryurl, domain,
        credentialsfile, profile, region, output, force):
    # UNSET any proxy vars that exist in the session
    unset_proxy()

    sts_auth = STSAuth(username, password, credentialsfile,
                       idpentryurl, profile, domain, region, output)

    if not sts_auth.config_file_is_valid:
        sys.exit(1)

    if not sts_auth.credentials_expired and not force:
        msg = 'Credentials for profile {!r} valid, would you like to continue?'
        if not click.confirm(msg.format(sts_auth.profile)):
            sys.exit(0)

    sts_auth.parse_config_file()
    assertion = sts_auth.get_saml_response()
    # Parse the returned assertion and extract the authorized roles
    awsroles = sts_auth.parse_roles_from_assertion(assertion)
    account_roles, account_lookup = sts_auth.format_roles_for_display(awsroles)

    # If more than one role returned, ask the user which one they want,
    # otherwise just proceed
    click.echo("")
    if len(account_lookup) > 1:
        role_arn, principal_arn = prompt_for_role(account_roles, account_lookup)
    else:
        role_arn, principal_arn = account_lookup.get(0).split(',')

    click.secho("\nRequesting credentials for role: " + role_arn, fg='green')

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    token = sts_auth.fetch_aws_sts_token(role_arn, principal_arn, assertion)


    # Put the credentials into a role specific section
    role_for_section = parse_role_for_profile(role_arn)
    sts_auth.write_saml_conf(token, role_for_section)

    # Give the user some basic info as to what has just happened
    msg = (
        '\n------------------------------------------------------------\n'
        'Your new access key pair has been stored in the AWS configuration '
        'file {config_file} under the saml profile.\n'
        'Note that it will expire at {expiry}.\n'
        'After this time, you may safely rerun this script to refresh your access key pair.\n'
        'To use this credential, call the AWS CLI with the --profile option '
        '(e.g. aws --profile {role} ec2 describe-instances).\n'
        '--------------------------------------------------------------\n'
        .format(config_file=sts_auth.credentialsfile,
                expiry=token.get('Credentials', {}).get('Expiration', ''),
                role=role_for_section)
    )
    click.secho(msg, fg='green')


def prompt_for_role(account_roles, account_lookup):
    for acct_id, roles in account_roles.items():
        print('\nAccount {}:'.format(acct_id))
        for role in roles:
            print('[{key}]: {label}'.format(**role))
    click.echo('Selection: ', nl=False)
    selected_role_index = input()

    # Basic sanity check of input
    if not role_selection_is_valid(selected_role_index, account_lookup):
        return prompt_for_role(account_roles, account_lookup)

    return account_lookup.get(int(selected_role_index)).split(',')

def role_selection_is_valid(selection, account_lookup):
    try:
        int(selection)
    except ValueError:
        click.secho('You selected an invalid role index, please try again', fg='red')
        return False

    if int(selection) not in range(len(account_lookup)):
        click.secho('You selected an invalid role index, please try again', fg='red')
        return False

    return True

def unset_proxy():
    env_vars = [
        "http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "FTP_PROXY"
    ]
    for var in env_vars:
        if var in os.environ:
            logger.debug('Unsetting {!r} environment variable!'.format(var))
            del os.environ[var]

def parse_role_for_profile(role):
    account_re = re.compile(r'::(\d+):')
    account_id = '000000000000'
    role_name = 'Unknown-Role-Name'

    _account_id = re.search(account_re, role)
    _role_name = role.split('/')
    if _account_id.groups():
        account_id = _account_id.groups()[0]
    if len(_role_name) == 2:
        role_name = _role_name[1]

    return '{}-{}'.format(account_id, role_name)
